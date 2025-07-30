#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detector Simplificado de DNS Tunneling
=====================================

Detecta atividades suspeitas de tunelamento DNS através de:
- Análise de entropia (dados codificados)
- Comprimento anômalo de subdomínios
- Padrões de codificação (hex, base64)
- Frequência de consultas

Dependência: pip install tldextract
"""
import re
import math
import time
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional

try:
    import tldextract
except ImportError:
    print("❌ Erro: Execute 'pip install tldextract' para instalar a dependência")
    exit(1)


class SimpleDNSTunnelDetector:
    """Detector simplificado de tunelamento DNS"""
    
    def __init__(self):
        # Thresholds otimizados
        self.MAX_ENTROPY = 4.0          # Entropia máxima aceitável
        self.MAX_LENGTH = 30            # Comprimento máximo do subdomínio
        self.MAX_QUERIES = 50           # Máximo de queries por IP em 5min
        self.TIME_WINDOW = 300          # Janela de tempo (5 minutos)
        
        # Padrões suspeitos (regex compilados para performance)
        self.patterns = {
            'hex_long': re.compile(r'^[a-f0-9]{16,}$'),        # Hex longo
            'base64_like': re.compile(r'^[A-Za-z0-9+/=]{16,}$'), # Base64
            'random_chars': re.compile(r'^[a-z0-9]{20,}$')     # Chars aleatórios
        }
        
        # Armazenamento de queries por IP
        self.queries_by_ip = defaultdict(list)
    
    def calculate_entropy(self, text: str) -> float:
        """Calcula entropia de Shannon (simplicidade máxima)"""
        if not text:
            return 0.0
        
        # Conta frequência de cada caractere
        counter = Counter(text.lower())
        length = len(text)
        
        # Calcula entropia
        entropy = 0
        for count in counter.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def extract_subdomain(self, domain: str) -> str:
        """Extrai apenas a parte do subdomínio"""
        try:
            extracted = tldextract.extract(domain)
            return extracted.subdomain.lower()
        except:
            return ""
    
    def is_suspicious_domain(self, domain: str) -> Tuple[bool, List[str]]:
        """Verifica se um domínio é suspeito (análise individual)"""
        subdomain = self.extract_subdomain(domain)
        
        if not subdomain or len(subdomain) < 10:
            return False, []
        
        reasons = []
        
        # 1. Verificar comprimento
        if len(subdomain) > self.MAX_LENGTH:
            reasons.append(f"subdomínio muito longo ({len(subdomain)} chars)")
        
        # 2. Verificar entropia
        entropy = self.calculate_entropy(subdomain)
        if entropy > self.MAX_ENTROPY:
            reasons.append(f"alta entropia ({entropy:.2f})")
        
        # 3. Verificar padrões suspeitos
        for pattern_name, pattern in self.patterns.items():
            if pattern.match(subdomain):
                reasons.append(f"padrão {pattern_name}")
        
        return len(reasons) >= 2, reasons  # Suspeito se 2+ indicadores
    
    def analyze_query(self, ip: str, domain: str, timestamp: Optional[float] = None) -> Dict:
        """Analisa uma query DNS"""
        if timestamp is None:
            timestamp = time.time()
        
        # Análise individual do domínio
        is_suspicious, reasons = self.is_suspicious_domain(domain)
        
        # Armazena query para análise de frequência
        query_data = {
            'domain': domain,
            'timestamp': timestamp,
            'suspicious': is_suspicious,
            'reasons': reasons
        }
        
        self.queries_by_ip[ip].append(query_data)
        
        return {
            'ip': ip,
            'domain': domain,
            'suspicious': is_suspicious,
            'reasons': reasons,
            'entropy': self.calculate_entropy(self.extract_subdomain(domain))
        }
    
    def check_traffic_patterns(self) -> List[Dict]:
        """Verifica padrões de tráfego suspeitos"""
        alerts = []
        current_time = time.time()
        
        for ip, queries in self.queries_by_ip.items():
            # Filtra queries recentes
            recent = [q for q in queries 
                     if current_time - q['timestamp'] <= self.TIME_WINDOW]
            
            if len(recent) <= self.MAX_QUERIES:
                continue
            
            # Calcula estatísticas
            suspicious_count = sum(1 for q in recent if q['suspicious'])
            suspicious_ratio = suspicious_count / len(recent)
            
            # Alerta se muitas queries suspeitas
            if suspicious_ratio > 0.3:  # 30% ou mais suspeitas
                alerts.append({
                    'type': 'HIGH_FREQUENCY_TUNNELING',
                    'ip': ip,
                    'total_queries': len(recent),
                    'suspicious_queries': suspicious_count,
                    'suspicious_ratio': f"{suspicious_ratio:.1%}",
                    'confidence': 'HIGH' if suspicious_ratio > 0.5 else 'MEDIUM'
                })
        
        return alerts
    
    def get_summary(self) -> Dict:
        """Retorna resumo das detecções"""
        total_queries = sum(len(queries) for queries in self.queries_by_ip.values())
        total_ips = len(self.queries_by_ip)
        
        suspicious_queries = 0
        for queries in self.queries_by_ip.values():
            suspicious_queries += sum(1 for q in queries if q['suspicious'])
        
        return {
            'total_queries': total_queries,
            'total_ips': total_ips,
            'suspicious_queries': suspicious_queries,
            'suspicious_percentage': f"{suspicious_queries/total_queries*100:.1f}%" if total_queries > 0 else "0%"
        }


def demo():
    """Demonstração do detector"""
    print("🛡️  DNS Tunneling Detector - Demo\n")
    
    detector = SimpleDNSTunnelDetector()
    
    # Dados de teste da sua rede 192.168.20.0
    test_data = [
        # Tráfego normal
        ('192.168.20.100', 'www.google.com'),
        ('192.168.20.100', 'api.github.com'),
        ('192.168.20.101', 'cdn.cloudflare.com'),
        
        # Queries suspeitas
        ('192.168.20.50', 'dGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0.evil.com'),
        ('192.168.20.50', 'deadbeef1234567890abcdef.tunnel.net'),
        ('192.168.20.50', 'aabbccddeeff112233445566778899.malware.org'),
    ]
    
    # Simula tráfego de tunneling (muitas queries suspeitas)
    tunnel_ip = '192.168.20.99'
    for i in range(60):
        payload = f"{'a' * 20}{i:04d}{'b' * 15}"
        test_data.append((tunnel_ip, f'{payload}.tunnel-site.com'))
    
    print("📊 Analisando queries...\n")
    
    # Processa queries
    suspicious_found = []
    for ip, domain in test_data:
        result = detector.analyze_query(ip, domain)
        if result['suspicious']:
            suspicious_found.append(result)
    
    # Mostra queries suspeitas
    if suspicious_found:
        print("🚨 QUERIES SUSPEITAS DETECTADAS:")
        for result in suspicious_found[:5]:  # Mostra apenas as primeiras 5
            print(f"   IP: {result['ip']}")
            print(f"   Domínio: {result['domain'][:50]}...")
            print(f"   Motivos: {', '.join(result['reasons'])}")
            print(f"   Entropia: {result['entropy']:.2f}\n")
        
        if len(suspicious_found) > 5:
            print(f"   ... e mais {len(suspicious_found) - 5} queries suspeitas\n")
    
    # Verifica padrões de tráfego
    print("📈 Verificando padrões de tráfego...\n")
    traffic_alerts = detector.check_traffic_patterns()
    
    if traffic_alerts:
        print("🚨 ALERTAS DE TRÁFEGO:")
        for alert in traffic_alerts:
            print(f"   Tipo: {alert['type']}")
            print(f"   IP: {alert['ip']}")
            print(f"   Queries totais: {alert['total_queries']}")
            print(f"   Queries suspeitas: {alert['suspicious_queries']}")
            print(f"   Taxa suspeita: {alert['suspicious_ratio']}")
            print(f"   Confiança: {alert['confidence']}\n")
    else:
        print("✅ Nenhum padrão de tráfego suspeito detectado.\n")
    
    # Resumo
    summary = detector.get_summary()
    print("📋 RESUMO:")
    print(f"   Total de queries: {summary['total_queries']}")
    print(f"   IPs únicos: {summary['total_ips']}")
    print(f"   Queries suspeitas: {summary['suspicious_queries']} ({summary['suspicious_percentage']})")


if __name__ == "__main__":
    demo()
