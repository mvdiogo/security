#!/usr/bin/env python3
import sqlite3
import threading
import time
from datetime import datetime
from contextlib import contextmanager
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, hexdump
    SCAPY_AVAILABLE = True
except ImportError:
    print("⚠️  Scapy não encontrado. Instale com: pip install scapy")
    SCAPY_AVAILABLE = False
    exit(1)

class PacketAnalyzer:
    def __init__(self, db_path='network_traffic.db'):
        self.db_path = db_path
        self.db_lock = threading.Lock()
        self.setup_database()
        
    def setup_database(self):
        """Cria a tabela para armazenar os pacotes"""
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    packet_size INTEGER,
                    is_malicious BOOLEAN,
                    reason TEXT,
                    payload_hex TEXT,
                    payload_ascii TEXT
                )
            ''')
            conn.commit()
    
    @contextmanager
    def get_db_connection(self):
        """Context manager para conexões thread-safe com timeout"""
        conn = None
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path, timeout=10.0)
                conn.execute('PRAGMA journal_mode=WAL')  # Permite leituras simultâneas
                yield conn
        finally:
            if conn:
                conn.close()
    
    def is_malicious_traffic(self, src_ip, dst_ip, src_port, dst_port, packet_size, payload=None):
        """
        Lógica melhorada para detectar tráfego malicioso
        Retorna (is_malicious, reason)
        """
        reasons = []
        
        # Portas comumente usadas por malware
        malicious_ports = [1337, 31337, 4444, 5555, 6666, 9999, 12345, 54321, 
                          1234, 2222, 3333, 7777, 8888, 9000, 10000]
        
        # IPs suspeitos (redes privadas anômalas)
        suspicious_patterns = ['10.0.0.666', '192.168.1.666', '127.0.0.2']
        
        # Análise de payload se disponível
        if payload:
            payload_str = payload.lower()
            
            # Palavras-chave suspeitas no payload
            malicious_keywords = [
                b'backdoor', b'rootkit', b'keylog', b'trojan', b'malware',
                b'exploit', b'shell', b'cmd.exe', b'powershell', b'wget',
                b'curl http', b'download', b'execute', b'inject', b'bypass'
            ]
            
            for keyword in malicious_keywords:
                if keyword in payload:
                    reasons.append(f"Payload suspeito: {keyword.decode()}")
        
        # Pacotes muito grandes (possível exfiltração)
        if packet_size > 60000:
            reasons.append(f"Pacote muito grande: {packet_size} bytes")
        
        # Portas maliciosas conhecidas
        if src_port in malicious_ports:
            reasons.append(f"Porta maliciosa de origem: {src_port}")
        if dst_port in malicious_ports:
            reasons.append(f"Porta maliciosa de destino: {dst_port}")
        
        # IPs suspeitos
        for suspicious in suspicious_patterns:
            if suspicious in src_ip or suspicious in dst_ip:
                reasons.append(f"IP suspeito: {src_ip} -> {dst_ip}")
                break
        
        # Serviços suspeitos em portas não padronizadas (apenas destino)
        # Portas altas de origem são normais (conexões efêmeras)
        suspicious_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 
            993: "IMAPS", 995: "POP3S", 587: "SMTP-Sub", 465: "SMTPS",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 3389: "RDP"
        }
        
        # Apenas verifica portas de destino baixas em serviços não comuns
        if dst_port < 1024 and dst_port not in suspicious_services:
            reasons.append(f"Serviço não comum em porta privilegiada: {dst_port}")
        
        # Verifica apenas serviços conhecidamente perigosos em qualquer porta
        dangerous_services = [1337, 31337, 4444, 5555, 6666, 9999, 12345, 54321]
        if dst_port in dangerous_services:
            reasons.append(f"Porta de destino maliciosa conhecida: {dst_port}")
        
        return len(reasons) > 0, "; ".join(reasons) if reasons else "Tráfego normal"
    
    def analyze_malicious_packet(self, packet):
        """Análise detalhada de pacotes maliciosos"""
        print("\n" + "="*60)
        print("🔍 ANÁLISE DETALHADA DO PACOTE MALICIOSO")
        print("="*60)
        
        # Informações gerais
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            print(f"📍 IP Origem: {ip_layer.src}")
            print(f"📍 IP Destino: {ip_layer.dst}")
            print(f"📋 Protocolo: {ip_layer.proto}")
            print(f"📏 Tamanho: {len(packet)} bytes")
            
        # Informações de porta
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"🔌 TCP {tcp_layer.sport} -> {tcp_layer.dport}")
            print(f"🏁 Flags: {tcp_layer.flags}")
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"🔌 UDP {udp_layer.sport} -> {udp_layer.dport}")
        
        # Análise do payload
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"\n📦 PAYLOAD ({len(payload)} bytes):")
            print("-" * 40)
            
            # Hexdump do payload
            print("🔢 Hexdump:")
            try:
                hexdump(payload)
            except:
                print("Erro ao exibir hexdump")
            
            # ASCII legível
            print("\n📝 ASCII legível:")
            ascii_payload = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload[:200])
            print(ascii_payload)
            
            return payload.hex(), ascii_payload
        
        print("="*60 + "\n")
        return None, None
    
    def save_packet(self, src_ip, dst_ip, protocol, src_port, dst_port, 
                   packet_size, is_malicious, reason, payload_hex=None, payload_ascii=None):
        """Salva o pacote no banco de dados de forma thread-safe"""
        try:
            with self.get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO packets 
                    (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, 
                     packet_size, is_malicious, reason, payload_hex, payload_ascii)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    src_ip, dst_ip, protocol, src_port, dst_port, 
                    packet_size, is_malicious, reason, payload_hex, payload_ascii
                ))
                conn.commit()
        except sqlite3.Error as e:
            print(f"⚠️  Erro ao salvar no banco: {e}")
    
    def process_packet(self, packet):
        """Processa cada pacote capturado"""
        if not packet.haslayer(IP):
            return
            
        # Extrai informações básicas
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        packet_size = len(packet)
        
        # Extrai portas
        src_port = dst_port = 0
        protocol_name = "OTHER"
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            protocol_name = "TCP"
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            protocol_name = "UDP"
        
        # Extrai payload para análise
        payload = None
        if packet.haslayer(Raw):
            payload = packet[Raw].load
        
        # Verifica se é tráfego malicioso
        is_malicious, reason = self.is_malicious_traffic(
            src_ip, dst_ip, src_port, dst_port, packet_size, payload
        )
        
        # Se for malicioso, faz análise detalhada
        payload_hex = payload_ascii = None
        if is_malicious:
            payload_hex, payload_ascii = self.analyze_malicious_packet(packet)
            print(f"🚨 MALICIOSO: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{protocol_name}]")
            print(f"📝 Motivo: {reason}")
        else:
            print(f"✅ Normal: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{protocol_name}]")
        
        # Salva no banco
        self.save_packet(
            src_ip, dst_ip, protocol_name, src_port, dst_port, 
            packet_size, is_malicious, reason, payload_hex, payload_ascii
        )
    
    def start_monitoring(self, interface=None):
        """Inicia o monitoramento usando Scapy"""
        if not SCAPY_AVAILABLE:
            print("❌ Scapy não está disponível")
            return
            
        print("🔍 Iniciando monitoramento com Scapy...")
        if interface:
            print(f"🌐 Interface: {interface}")
        else:
            print("🌐 Interface: Todas as interfaces")
        print("📊 Dados salvos em:", self.db_path)
        print("🛑 Pressione Ctrl+C para parar\n")
        
        try:
            # Inicia captura com Scapy
            sniff(
                iface=interface,
                prn=self.process_packet,
                filter="ip",  # Apenas pacotes IP
                store=0       # Não armazena pacotes na memória
            )
        except KeyboardInterrupt:
            print("\n🛑 Monitoramento interrompido pelo usuário")
        except Exception as e:
            print(f"❌ Erro durante monitoramento: {e}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Analisador de Pacotes de Rede')
    parser.add_argument('-i', '--interface', help='Interface de rede específica')
    parser.add_argument('-d', '--database', default='network_traffic.db', 
                       help='Caminho do banco de dados SQLite')
    
    args = parser.parse_args()
    
    analyzer = PacketAnalyzer(args.database)
    analyzer.start_monitoring(args.interface)

if __name__ == "__main__":
    main()