import requests
import time
import json
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any
import logging

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DASTScanner:
    """Scanner DAST automatizado para identificar vulnerabilidades em aplicações web."""

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def crawl_application(self, max_depth: int = 3) -> List[str]:
        """Realiza o crawl da aplicação para descobrir endpoints."""
        urls_to_scan = [self.target_url]
        logger.info(f"Iniciando crawl em {self.target_url} com profundidade máxima {max_depth}")

        for depth in range(max_depth):
            new_urls = []
            for url in urls_to_scan:
                if url not in self.crawled_urls:
                    try:
                        response = self.session.get(url, timeout=10)
                        self.crawled_urls.add(url)
                        if 'text/html' in response.headers.get('content-type', ''):
                            links = self._extract_links(response.text, url)
                            new_urls.extend(links)
                    except requests.RequestException as e:
                        logger.error(f"Erro ao crawlear {url}: {e}")
            urls_to_scan = list(set(new_urls) - self.crawled_urls)

        logger.info(f"Crawl concluído. Encontradas {len(self.crawled_urls)} URLs.")
        return list(self.crawled_urls)

    def _extract_links(self, html_content: str, base_url: str) -> List[str]:
        """Extrai links de conteúdo HTML."""
        import re
        link_pattern = r'href=[\'"]([^\'"]+)[\'"]'
        links = re.findall(link_pattern, html_content)
        absolute_links = []
        for link in links:
            if link.startswith('http'):
                absolute_links.append(link)
            elif link.startswith('/'):
                absolute_links.append(urljoin(base_url, link))
        target_domain = urlparse(self.target_url).netloc
        same_domain_links = [link for link in absolute_links if urlparse(link).netloc == target_domain]
        return same_domain_links

    def test_sql_injection(self, urls: List[str]):
        """Testa vulnerabilidades de SQL Injection."""
        sql_payloads = [
            "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*", "admin'--", "admin' #",
            "' UNION SELECT NULL--", "' AND 1=1--", "' AND 1=2--"
        ]
        logger.info("Testando SQL Injection...")
        for url in urls:
            if '?' in url:
                base_url, params = url.split('?', 1)
                param_pairs = params.split('&')
                for payload in sql_payloads:
                    for i, param_pair in enumerate(param_pairs):
                        if '=' in param_pair:
                            param_name, _ = param_pair.split('=', 1)
                            test_params = param_pairs.copy()
                            test_params[i] = f"{param_name}={payload}"
                            test_url = f"{base_url}?{'&'.join(test_params)}"
                            try:
                                response = self.session.get(test_url, timeout=10)
                                if self._detect_sql_injection(response):
                                    self.vulnerabilities.append({
                                        'type': 'SQL Injection',
                                        'url': test_url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'severity': 'HIGH',
                                        'description': f'Possível SQL Injection detectada no parâmetro {param_name}.',
                                        'mitigation': 'Utilize consultas parametrizadas ou prepared statements.'
                                    })
                            except requests.RequestException as e:
                                logger.error(f"Erro ao testar SQL Injection em {test_url}: {e}")

    def _detect_sql_injection(self, response: requests.Response) -> bool:
        """Detecta indicadores de SQL Injection na resposta."""
        sql_error_patterns = [
            'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB Provider for ODBC Drivers',
            'PostgreSQL query failed', 'Warning: mysql_', 'valid MySQL result'
        ]
        response_text = response.text.lower()
        return any(pattern.lower() in response_text for pattern in sql_error_patterns)

    def test_xss(self, urls: List[str]):
        """Testa vulnerabilidades XSS."""
        xss_payloads = [
            "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>", "javascript:alert('XSS')"
        ]
        logger.info("Testando XSS...")
        for url in urls:
            if '?' in url:
                base_url, params = url.split('?', 1)
                param_pairs = params.split('&')
                for payload in xss_payloads:
                    for i, param_pair in enumerate(param_pairs):
                        if '=' in param_pair:
                            param_name, _ = param_pair.split('=', 1)
                            test_params = param_pairs.copy()
                            test_params[i] = f"{param_name}={payload}"
                            test_url = f"{base_url}?{'&'.join(test_params)}"
                            try:
                                response = self.session.get(test_url, timeout=10)
                                if payload in response.text:
                                    self.vulnerabilities.append({
                                        'type': 'Cross-Site Scripting (XSS)',
                                        'url': test_url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'severity': 'MEDIUM',
                                        'description': f'XSS refletido detectado no parâmetro {param_name}.',
                                        'mitigation': 'Sanitize entradas do usuário e use codificação de saída.'
                                    })
                            except requests.RequestException as e:
                                logger.error(f"Erro ao testar XSS em {test_url}: {e}")

    def test_security_headers(self, urls: List[str]):
        """Testa a presença de headers de segurança."""
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1; mode=block'
        }
        logger.info("Testando headers de segurança...")
        for url in urls:
            try:
                response = self.session.get(url, timeout=10)
                for header, expected_value in security_headers.items():
                    if header not in response.headers:
                        self.vulnerabilities.append({
                            'type': 'Missing Security Header',
                            'url': url,
                            'parameter': header,
                            'payload': None,
                            'severity': 'LOW',
                            'description': f'Header de segurança ausente: {header}.',
                            'mitigation': f'Adicione o header {header} às respostas do servidor.'
                        })
                    elif expected_value and isinstance(expected_value, list) and response.headers[header] not in expected_value:
                        self.vulnerabilities.append({
                            'type': 'Incorrect Security Header',
                            'url': url,
                            'parameter': header,
                            'payload': response.headers[header],
                            'severity': 'LOW',
                            'description': f'Valor incorreto para {header}: {response.headers[header]}.',
                            'mitigation': f'Defina {header} como um dos valores: {expected_value}.'
                        })
            except requests.RequestException as e:
                logger.error(f"Erro ao testar headers em {url}: {e}")

    def run_full_scan(self) -> Dict[str, Any]:
        """Executa um scan DAST completo."""
        logger.info(f"🎯 Iniciando scan DAST em {self.target_url}")
        urls = self.crawl_application()
        self.test_sql_injection(urls)
        self.test_xss(urls)
        self.test_security_headers(urls)
        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        """Gera um relatório detalhado das vulnerabilidades encontradas."""
        report = {
            'target': self.target_url,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'urls_scanned': len(self.crawled_urls),
            'vulnerabilities_found': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
            }
        }
        logger.info(f"Scan concluído. Vulnerabilidades encontradas: {report['vulnerabilities_found']}")
        return report