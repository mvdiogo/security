import json
import subprocess
import smtplib
import logging
import os
import ipaddress
from datetime import datetime
from email.mime.text import MIMEText

logging.basicConfig(
    filename='/var/log/incident_response.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

class AutomatedIncidentResponse:
    def __init__(self, config_file):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        self.response_actions = {
            'block_ip': self.block_ip_address,
            'isolate_host': self.isolate_host,
            'collect_evidence': self.collect_evidence,
            'notify_team': self.notify_security_team,
            'create_ticket': self.create_incident_ticket,
            'escalate_to_ciso': self.escalate_to_ciso
        }

    def process_alert(self, alert):
        severity = alert.get('severity', 'LOW')
        alert_type = alert.get('classification', 'unknown')

        actions = self.determine_response_actions(severity, alert_type)
        response_results = []

        for action in actions:
            func = self.response_actions.get(action)
            if func:
                try:
                    result = func(alert)
                    logging.info(f"Ação {action} executada com sucesso.")
                    response_results.append({'action': action, 'status': 'success', 'result': result})
                except Exception as e:
                    logging.error(f"Erro ao executar ação {action}: {e}")
                    response_results.append({'action': action, 'status': 'failed', 'error': str(e)})
            else:
                logging.warning(f"Ação desconhecida: {action}")
        
        self.log_response(alert, response_results)
        return response_results

    def determine_response_actions(self, severity, alert_type):
        actions = ['notify_team']

        if severity in ['HIGH', 'CRITICAL']:
            actions.extend(['block_ip', 'collect_evidence', 'create_ticket'])

        if alert_type in ['trojan-activity', 'shellcode-detect']:
            actions.append('isolate_host')

        if severity == 'CRITICAL':
            actions.append('escalate_to_ciso')

        return actions

    def block_ip_address(self, alert):
        source_ip = alert.get('source_ip')
        if not self._valid_ip(source_ip):
            raise ValueError("Invalid or missing source IP")

        cmd = f"iptables -I INPUT -s {source_ip} -j DROP"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            unblock_cmd = f"echo 'iptables -D INPUT -s {source_ip} -j DROP' | at now + 1 hour"
            subprocess.run(unblock_cmd, shell=True)
            return f"IP {source_ip} blocked and scheduled to unblock in 1 hour"
        else:
            raise RuntimeError(f"Failed to block IP {source_ip}: {result.stderr.strip()}")

    def isolate_host(self, alert):
        dest_ip = alert.get('destination_ip')
        if not self._valid_ip(dest_ip):
            raise ValueError("Invalid or missing destination IP")

        isolation_cmds = [
            "vconfig add eth0 999",
            "ip addr add 192.168.999.1/24 dev eth0.999",
            f"iptables -t nat -A PREROUTING -s {dest_ip} -j DNAT --to-destination 192.168.999.2"
        ]
        output = []
        for cmd in isolation_cmds:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            status = 'success' if result.returncode == 0 else f'failed ({result.stderr.strip()})'
            output.append(f"{cmd}: {status}")
        return "; ".join(output)

    def collect_evidence(self, alert):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        evidence_dir = f"/var/log/incident_evidence/{timestamp}"
        os.makedirs(evidence_dir, exist_ok=True)

        commands = {
            "eve.json": "cp /var/log/suricata/eve.json",
            "netstat.txt": "netstat -an",
            "processes.txt": "ps aux",
            "connections.txt": "ss -tulpn"
        }

        for filename, command in commands.items():
            path = os.path.join(evidence_dir, filename)
            with open(path, 'w') as f:
                subprocess.run(command, shell=True, stdout=f, stderr=subprocess.DEVNULL)

        with open(f"{evidence_dir}/alert_details.json", 'w') as f:
            json.dump(alert, f, indent=2)

        return f"Evidence saved to {evidence_dir}"

    def notify_security_team(self, alert):
        subject = f"Security Alert: {alert.get('classification')} - {alert.get('severity')}"
        body = f"""
        Security Alert Details:
        Timestamp: {alert.get('timestamp')}
        Severity: {alert.get('severity')}
        Classification: {alert.get('classification')}
        Source IP: {alert.get('source_ip')}
        Destination IP: {alert.get('destination_ip')}
        Message: {alert.get('message')}
        Signature ID: {alert.get('signature_id')}
        """

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = self.config['email']['from']
        msg['To'] = ', '.join(self.config['email']['security_team'])

        try:
            server = smtplib.SMTP(self.config['email']['smtp_server'])
            server.send_message(msg)
            server.quit()
            return "Security team notified"
        except Exception as e:
            raise RuntimeError(f"Email notification failed: {str(e)}")

    def create_incident_ticket(self, alert):
        # Placeholder para integração com sistema de chamados (ex: Jira, GLPI)
        return "Incident ticket created (placeholder)"

    def escalate_to_ciso(self, alert):
        # Ação simulada de escalonamento
        logging.critical(f"ALERTA CRÍTICO: {alert.get('classification')} de {alert.get('source_ip')}")
        return "Alert escalated to CISO"

    def log_response(self, alert, results):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'alert': alert,
            'responses': results
        }
        with open('/var/log/incident_response_history.json', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

    def _valid_ip(self, ip_str):
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
