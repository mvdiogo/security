from flask import Flask, request, jsonify
import json
from typing import Dict, Any

app = Flask(__name__)

class SecurityGate:
    """
    Implementação de Security Gate automatizado
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.violations = []
    
    def check_sast_results(self, bandit_report: Dict) -> bool:
        """
        Verificar resultados de análise estática
        """
        try:
            results = bandit_report
            high_severity = len([r for r in results.get('results', []) 
                                 if r.get('issue_severity') == 'HIGH'])
            
            if high_severity > self.config.get('max_high_severity', 0):
                self.violations.append(f"Encontradas {high_severity} vulnerabilidades de alta severidade")
                return False
            return True
        except Exception as e:
            self.violations.append(f"Erro ao processar relatório SAST: {e}")
            return False
    
    def check_dependency_vulnerabilities(self, safety_report: list) -> bool:
        """
        Verificar vulnerabilidades em dependências
        """
        try:
            results = safety_report
            critical_vulns = len([v for v in results 
                                  if v.get('vulnerability_id', '').startswith('CVE')])
            
            if critical_vulns > self.config.get('max_dependency_vulns', 0):
                self.violations.append(f"Encontradas {critical_vulns} vulnerabilidades críticas em dependências")
                return False
            return True
        except Exception as e:
            self.violations.append(f"Erro ao processar relatório de dependências: {e}")
            return False
    
    def check_container_security(self, trivy_report: Dict) -> bool:
        """
        Verificar segurança do container
        """
        try:
            results = trivy_report
            critical_count = 0
            for result in results.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    if vuln.get('Severity') == 'CRITICAL':
                        critical_count += 1
            
            if critical_count > self.config.get('max_container_critical', 0):
                self.violations.append(f"Container possui {critical_count} vulnerabilidades críticas")
                return False
            return True
        except Exception as e:
            self.violations.append(f"Erro ao processar relatório de container: {e}")
            return False
    
    def evaluate(self, reports: Dict[str, Any]) -> bool:
        """
        Avaliar todos os critérios de segurança
        """
        checks = [
            self.check_sast_results(reports.get('bandit')),
            self.check_dependency_vulnerabilities(reports.get('safety')),
            self.check_container_security(reports.get('trivy'))
        ]
        
        return all(checks)

# Configuração padrão do Security Gate
gate_config = {
    'max_high_severity': 0,
    'max_dependency_vulns': 0,
    'max_container_critical': 0
}

@app.route('/security-gate', methods=['POST'])
def security_gate():
    gate = SecurityGate(gate_config)
    
    try:
        # Recebe os relatórios como JSON no corpo da requisição
        data = request.get_json()
        reports = {
            'bandit': data.get('bandit'),
            'safety': data.get('safety'),
            'trivy': data.get('trivy')
        }
        
        # Verifica se todos os relatórios foram fornecidos
        if not all(reports.values()):
            return jsonify({"error": "Todos os relatórios (bandit, safety, trivy) são necessários"}), 400
        
        passed = gate.evaluate(reports)
        
        if passed:
            return jsonify({"message": "Security Gate PASSOU - Deploy autorizado"}), 200
        else:
            return jsonify({"message": "Security Gate FALHOU", "violations": gate.violations}), 403
    except Exception as e:
        return jsonify({"error": f"Erro ao processar a requisição: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
