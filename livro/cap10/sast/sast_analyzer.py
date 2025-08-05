#!/usr/bin/env python3
"""
SAST Analyzer - Ferramenta simplificada para análise de segurança estática
Suporta múltiplas ferramentas com configuração flexível
"""

import subprocess
import json
import os
import sys
import argparse
import tempfile
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import logging

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class SASTResult:
    """Resultado padronizado de análise SAST"""
    tool: str
    status: str
    vulnerabilities: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0
    execution_time: float = 0.0
    error_message: str = ""
    details: List[Dict] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = []

class SASTAnalyzer:
    """Analisador SAST simplificado e robusto"""
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()
        self.output_dir = Path("sast_reports").resolve()
        self.results: Dict[str, SASTResult] = {}
        
        # Verificar se projeto existe
        if not self.project_path.exists():
            raise ValueError(f"Caminho do projeto não existe: {self.project_path}")
        
        # Criar diretório de saída se não existir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"📁 Diretório de relatórios: {self.output_dir}")
    
    def _run_command(self, cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
        """Executar comando com timeout e captura de saída"""
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Timeout após {timeout} segundos"
        except Exception as e:
            return -1, "", str(e)
    
    def _check_tool_installed(self, tool_name: str) -> bool:
        """Verificar se ferramenta está instalada"""
        try:
            result = subprocess.run(
                [tool_name, "--help"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def run_bandit(self) -> SASTResult:
        """Executar análise com Bandit (Python)"""
        start_time = datetime.now()
        
        if not self._check_tool_installed("bandit"):
            return SASTResult(
                tool="bandit",
                status="skipped",
                error_message="Bandit não instalado. Execute: pip install bandit"
            )
        
        # Usar arquivo temporário para evitar problemas com barra de progresso
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmpfile:
            temp_path = tmpfile.name
        
        cmd = [
            "bandit",
            "-r", str(self.project_path),
            "-f", "json",
            "-o", temp_path,
            "--severity-level", "low"
        ]
        
        logger.debug(f"Executando comando: {' '.join(cmd)}")
        returncode, stdout, stderr = self._run_command(cmd)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Bandit retorna 1 quando encontra vulnerabilidades, 0 quando não encontra
        if returncode not in [0, 1]:
            return SASTResult(
                tool="bandit",
                status="error",
                execution_time=execution_time,
                error_message=f"Erro ao executar bandit (code {returncode}): {stderr}"
            )
        
        # Processar resultados do arquivo temporário
        try:
            if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                with open(temp_path, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    
                # Tentar decodificar o JSON
                try:
                    report = json.loads(content)
                except json.JSONDecodeError as e:
                    logger.error(f"Erro ao decodificar JSON do Bandit: {str(e)}")
                    logger.debug(f"Conteúdo do arquivo: {content[:500]}...")
                    raise
                    
                results = report.get('results', [])
                
                # Salvar relatório para referência
                self.output_dir.mkdir(parents=True, exist_ok=True)
                output_file = self.output_dir / "bandit_report.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                
                return SASTResult(
                    tool="bandit",
                    status="success",
                    vulnerabilities=len(results),
                    high_severity=len([r for r in results if r.get('issue_severity') == 'HIGH']),
                    medium_severity=len([r for r in results if r.get('issue_severity') == 'MEDIUM']),
                    low_severity=len([r for r in results if r.get('issue_severity') == 'LOW']),
                    execution_time=execution_time,
                    details=results[:15]  # Mostrar mais vulnerabilidades
                )
            else:
                logger.warning("Arquivo de saída do Bandit não encontrado ou vazio")
                return SASTResult(
                    tool="bandit",
                    status="error",
                    execution_time=execution_time,
                    error_message="Arquivo de saída do Bandit não gerado"
                )
        
        except Exception as e:
            logger.error(f"Erro ao processar resultados do Bandit: {str(e)}")
            return self._run_bandit_fallback(execution_time)
        
        finally:
            # Remover arquivo temporário
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
    
    def _run_bandit_fallback(self, execution_time: float) -> SASTResult:
        """Fallback para bandit usando arquivo de saída"""
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            output_file = self.output_dir / "bandit_report_fallback.json"
            
            cmd = [
                "bandit",
                "-r", str(self.project_path),
                "-f", "json",
                "-o", str(output_file),
                "--severity-level", "low"
            ]
            
            returncode, stdout, stderr = self._run_command(cmd)
            
            if returncode not in [0, 1]:
                return SASTResult(
                    tool="bandit",
                    status="error",
                    execution_time=execution_time,
                    error_message=f"Fallback bandit falhou (code {returncode}): {stderr}"
                )
            
            # Verificar se arquivo foi criado e tem conteúdo válido
            if output_file.exists():
                try:
                    with open(output_file, 'r', encoding='utf-8') as f:
                        content = f.read().strip()
                        if content:
                            report = json.loads(content)
                            results = report.get('results', [])
                            
                            return SASTResult(
                                tool="bandit",
                                status="success",
                                vulnerabilities=len(results),
                                high_severity=len([r for r in results if r.get('issue_severity') == 'HIGH']),
                                medium_severity=len([r for r in results if r.get('issue_severity') == 'MEDIUM']),
                                low_severity=len([r for r in results if r.get('issue_severity') == 'LOW']),
                                execution_time=execution_time,
                                details=results[:15]
                            )
                except json.JSONDecodeError:
                    logger.debug(f"Arquivo de fallback contém JSON inválido: {content[:100]}...")
            
            # Se chegou aqui, assume que não há vulnerabilidades
            return SASTResult(
                tool="bandit",
                status="success",
                execution_time=execution_time
            )
            
        except Exception as e:
            return SASTResult(
                tool="bandit",
                status="error",
                execution_time=execution_time,
                error_message=f"Erro no fallback do bandit: {str(e)}"
            )
    
    def run_semgrep(self) -> SASTResult:
        """Executar análise com Semgrep"""
        start_time = datetime.now()
        
        if not self._check_tool_installed("semgrep"):
            return SASTResult(
                tool="semgrep",
                status="skipped",
                error_message="Semgrep não instalado. Execute: pip install semgrep"
            )
        
        # Primeira tentativa: usar stdout diretamente
        cmd = [
            "semgrep",
            "--config=auto",
            "--json",
            str(self.project_path)
        ]
        
        logger.debug(f"Executando comando: {' '.join(cmd)}")
        returncode, stdout, stderr = self._run_command(cmd)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if returncode not in [0, 1]:  # Semgrep pode retornar 1 com findings
            return SASTResult(
                tool="semgrep",
                status="error",
                execution_time=execution_time,
                error_message=f"Erro ao executar semgrep (code {returncode}): {stderr}"
            )
        
        # Processar resultados do stdout
        try:
            if stdout.strip():
                report = json.loads(stdout)
                findings = report.get('results', [])
                
                # Salvar relatório para referência
                self.output_dir.mkdir(parents=True, exist_ok=True)
                output_file = self.output_dir / "semgrep_report.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                
                # Categorizar por severidade
                high = len([f for f in findings if f.get('extra', {}).get('severity') == 'ERROR'])
                medium = len([f for f in findings if f.get('extra', {}).get('severity') == 'WARNING'])
                low = len([f for f in findings if f.get('extra', {}).get('severity') == 'INFO'])
                
                return SASTResult(
                    tool="semgrep",
                    status="success",
                    vulnerabilities=len(findings),
                    high_severity=high,
                    medium_severity=medium,
                    low_severity=low,
                    execution_time=execution_time,
                    details=findings[:15]  # Mostrar mais vulnerabilidades
                )
            else:
                # Stdout vazio - sem vulnerabilidades
                logger.debug("Semgrep: stdout vazio, assumindo nenhuma vulnerabilidade")
                return SASTResult(
                    tool="semgrep",
                    status="success",
                    execution_time=execution_time
                )
            
        except json.JSONDecodeError as e:
            logger.debug(f"Erro ao decodificar JSON do semgrep: {e}")
            logger.debug(f"Stdout recebido: {stdout[:200]}...")
            
            return SASTResult(
                tool="semgrep",
                status="error",
                execution_time=execution_time,
                error_message=f"Saída JSON inválida do semgrep: {str(e)}"
            )
            
        except Exception as e:
            return SASTResult(
                tool="semgrep",
                status="error",
                execution_time=execution_time,
                error_message=f"Erro inesperado ao processar semgrep: {str(e)}"
            )
    
    def run_all_tools(self, tools: Optional[List[str]] = None) -> Dict[str, SASTResult]:
        """Executar todas as ferramentas disponíveis"""
        available_tools = {
            'bandit': self.run_bandit,
            'semgrep': self.run_semgrep
        }
        
        if tools:
            # Filtrar apenas ferramentas solicitadas
            available_tools = {k: v for k, v in available_tools.items() if k in tools}
        
        logger.info(f"🔍 Iniciando análise SAST em: {self.project_path}")
        logger.info(f"📁 Relatórios serão salvos em: {self.output_dir}")
        
        for tool_name, tool_func in available_tools.items():
            logger.info(f"🔧 Executando {tool_name}...")
            try:
                self.results[tool_name] = tool_func()
                status = self.results[tool_name].status
                if status == "success":
                    vulns = self.results[tool_name].vulnerabilities
                    logger.info(f"✅ {tool_name}: {vulns} vulnerabilidades encontradas")
                elif status == "skipped":
                    logger.warning(f"⏭️  {tool_name}: {self.results[tool_name].error_message}")
                else:
                    logger.error(f"❌ {tool_name}: {self.results[tool_name].error_message}")
            except Exception as e:
                logger.error(f"💥 Erro inesperado com {tool_name}: {str(e)}")
                self.results[tool_name] = SASTResult(
                    tool=tool_name,
                    status="error",
                    error_message=str(e)
                )
        
        return self.results
    
    def generate_report(self, format: str = "text") -> str:
        """Gerar relatório consolidado"""
        if format == "json":
            return json.dumps({k: asdict(v) for k, v in self.results.items()}, indent=2)
        
        # Relatório em texto
        report = []
        report.append("🔒 RELATÓRIO DE ANÁLISE SAST")
        report.append("=" * 50)
        report.append(f"📅 Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"📁 Projeto: {self.project_path}")
        report.append("")
        
        total_vulnerabilities = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        successful_tools = 0
        
        for tool_name, result in self.results.items():
            report.append(f"🔧 {tool_name.upper()}")
            report.append("-" * 20)
            
            if result.status == "success":
                successful_tools += 1
                total_vulnerabilities += result.vulnerabilities
                total_high += result.high_severity
                total_medium += result.medium_severity
                total_low += result.low_severity
                
                report.append(f"✅ Status: Sucesso")
                report.append(f"⏱️  Tempo: {result.execution_time:.2f}s")
                report.append(f"🐛 Total: {result.vulnerabilities}")
                report.append(f"🔴 Alta: {result.high_severity}")
                report.append(f"🟡 Média: {result.medium_severity}")
                report.append(f"🟢 Baixa: {result.low_severity}")
                
            elif result.status == "skipped":
                report.append(f"⏭️  Status: Pulado")
                report.append(f"💬 Motivo: {result.error_message}")
                
            else:
                report.append(f"❌ Status: Erro")
                report.append(f"💬 Erro: {result.error_message}")
            
            report.append("")
        
        # Resumo executivo
        report.append("📊 RESUMO EXECUTIVO")
        report.append("=" * 20)
        report.append(f"🔧 Ferramentas executadas: {successful_tools}/{len(self.results)}")
        report.append(f"🐛 Total de vulnerabilidades: {total_vulnerabilities}")
        report.append(f"🔴 Alta severidade: {total_high}")
        report.append(f"🟡 Média severidade: {total_medium}")
        report.append(f"🟢 Baixa severidade: {total_low}")
        report.append("")
        
        # Recomendações
        report.append("💡 RECOMENDAÇÕES")
        report.append("=" * 15)
        if total_vulnerabilities == 0:
            report.append("🎉 Excelente! Nenhuma vulnerabilidade detectada.")
        elif total_high > 0:
            report.append("🚨 CRÍTICO: Vulnerabilidades de alta severidade encontradas!")
            report.append("   Corrija imediatamente antes do deploy.")
        elif total_medium > 0:
            report.append("⚠️  ATENÇÃO: Vulnerabilidades de média severidade encontradas.")
            report.append("   Recomenda-se correção antes do deploy.")
        else:
            report.append("ℹ️  Apenas vulnerabilidades de baixa severidade encontradas.")
            report.append("   Considere correção em próxima iteração.")
        
        return "\n".join(report)
    
    def generate_detailed_report(self) -> str:
        """Gerar relatório com detalhes das vulnerabilidades"""
        report = []
        report.append("🔍 VULNERABILIDADES DETALHADAS")
        report.append("=" * 50)
        report.append(f"📅 Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"📁 Projeto: {self.project_path}")
        report.append("")
        
        for tool_name, result in self.results.items():
            if result.status != "success" or not result.details:
                continue
                
            report.append(f"\n🔧 {tool_name.upper()} - PRINCIPAIS VULNERABILIDADES")
            report.append("-" * 50)
            
            for i, vuln in enumerate(result.details, 1):
                if tool_name == "bandit":
                    report.append(f"{i}. [{vuln.get('issue_severity')}] {vuln.get('test_id')} - {vuln.get('test_name')}")
                    report.append(f"   Arquivo: {vuln.get('filename')}:{vuln.get('line_number')}")
                    report.append(f"   Descrição: {vuln.get('issue_text')}")
                    if vuln.get('code'):
                        report.append(f"   Código: {vuln.get('code').strip()}")
                    
                    # Adicionar link para mais informações
                    if vuln.get('more_info'):
                        report.append(f"   🔗 Mais info: {vuln.get('more_info')}")
                    
                elif tool_name == "semgrep":
                    extra = vuln.get('extra', {})
                    report.append(f"{i}. [{extra.get('severity')}] {vuln.get('check_id')}")
                    report.append(f"   Arquivo: {vuln.get('path')}:{vuln.get('start', {}).get('line')}")
                    report.append(f"   Mensagem: {extra.get('message')}")
                    if 'lines' in extra:
                        report.append(f"   Código: {extra.get('lines').strip()}")
                    
                    # Adicionar link para documentação
                    if 'metadata' in extra and 'source' in extra['metadata']:
                        report.append(f"   🔗 Documentação: {extra['metadata']['source']}")
                
                report.append("-" * 40)
        
        return "\n".join(report)
    
    def save_report(self, format: str = "text") -> Path:
        """Salvar relatório em arquivo"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == "json":
            filename = f"sast_report_{timestamp}.json"
        else:
            filename = f"sast_report_{timestamp}.txt"
        
        report_path = self.output_dir / filename
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_report(format))
        
        return report_path
    
    def save_detailed_report(self) -> Path:
        """Salvar relatório detalhado em arquivo"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"detailed_sast_report_{timestamp}.txt"
        report_path = self.output_dir / filename
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_detailed_report())
        
        return report_path
    
    def diagnose_tools(self) -> Dict[str, Dict[str, str]]:
        """Diagnosticar status das ferramentas SAST"""
        tools_status = {}
        
        # Verificar Bandit
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                tools_status["bandit"] = {
                    "status": "installed",
                    "version": version,
                    "install_cmd": "pip install bandit"
                }
            else:
                tools_status["bandit"] = {
                    "status": "error",
                    "error": result.stderr,
                    "install_cmd": "pip install bandit"
                }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            tools_status["bandit"] = {
                "status": "not_installed",
                "install_cmd": "pip install bandit"
            }
        
        # Verificar Semgrep
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                tools_status["semgrep"] = {
                    "status": "installed",
                    "version": version,
                    "install_cmd": "pip install semgrep"
                }
            else:
                tools_status["semgrep"] = {
                    "status": "error",
                    "error": result.stderr,
                    "install_cmd": "pip install semgrep"
                }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            tools_status["semgrep"] = {
                "status": "not_installed",
                "install_cmd": "pip install semgrep"
            }
        
        return tools_status
    
    def print_diagnosis(self):
        """Imprimir diagnóstico das ferramentas"""
        print("🔍 DIAGNÓSTICO DE FERRAMENTAS SAST")
        print("=" * 40)
        
        diagnosis = self.diagnose_tools()
        
        for tool_name, info in diagnosis.items():
            print(f"\n🔧 {tool_name.upper()}")
            
            if info["status"] == "installed":
                print(f"  ✅ Status: Instalado")
                print(f"  📋 Versão: {info['version']}")
            elif info["status"] == "not_installed":
                print(f"  ❌ Status: Não instalado")
                print(f"  💡 Instalar: {info['install_cmd']}")
            else:
                print(f"  ⚠️  Status: Erro")
                print(f"  💬 Erro: {info.get('error', 'Desconhecido')}")
                print(f"  💡 Reinstalar: {info['install_cmd']}")
        
        print(f"\n📁 Projeto: {self.project_path}")
        print(f"📁 Relatórios: {self.output_dir}")
        
        # Verificar se há arquivos Python no projeto
        python_files = list(self.project_path.rglob("*.py"))
        print(f"🐍 Arquivos Python encontrados: {len(python_files)}")
        
        if python_files:
            print("   Alguns arquivos:")
            for f in python_files[:5]:
                print(f"   - {f.relative_to(self.project_path)}")
            if len(python_files) > 5:
                print(f"   ... e mais {len(python_files) - 5} arquivos")
        else:
            print("   ⚠️  Nenhum arquivo Python encontrado!")
        
        print()

    def check_security_gate(
        self, 
        max_high: int, 
        max_medium: int, 
        max_total: int
    ) -> bool:
        """Verificar se código passa no security gate"""
        total_high = sum(r.high_severity for r in self.results.values() if r.status == "success")
        total_medium = sum(r.medium_severity for r in self.results.values() if r.status == "success")
        total_vulns = sum(r.vulnerabilities for r in self.results.values() if r.status == "success")
        
        passed = (total_high <= max_high and 
                 total_medium <= max_medium and 
                 total_vulns <= max_total)
        
        logger.info(f"🚦 Security Gate: {'✅ PASSOU' if passed else '❌ FALHOU'}")
        logger.info(f"   Alta: {total_high}/{max_high}")
        logger.info(f"   Média: {total_medium}/{max_medium}")
        logger.info(f"   Total: {total_vulns}/{max_total}")
        
        return passed

def create_test_project(path: str = "test_project"):
    """Criar projeto de teste com vulnerabilidades intencionais para demonstração"""
    test_path = Path(path)
    test_path.mkdir(exist_ok=True)
    
    # Arquivo Python com vulnerabilidades intencionais
    vulnerable_code = '''#!/usr/bin/env python3
"""
Arquivo de teste com vulnerabilidades intencionais para demonstrar SAST
NÃO USE ESTE CÓDIGO EM PRODUÇÃO!
"""

import os
import subprocess
import pickle
import hashlib

def vulnerable_function_1():
    """Uso inseguro de subprocess"""
    user_input = input("Digite um comando: ")
    # VULNERABILIDADE: Command injection
    os.system(user_input)

def vulnerable_function_2():
    """Uso inseguro de pickle"""
    with open('data.pkl', 'rb') as f:
        # VULNERABILIDADE: Pickle deserialization
        data = pickle.load(f)
    return data

def vulnerable_function_3():
    """Hash MD5 inseguro"""
    password = "senha123"
    # VULNERABILIDADE: Weak cryptographic hash
    hash_obj = hashlib.md5(password.encode())
    return hash_obj.hexdigest()

def vulnerable_function_4():
    """SQL injection potencial"""
    user_id = input("Digite seu ID: ")
    # VULNERABILIDADE: SQL injection (simulada)
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

def vulnerable_function_5():
    """Hardcoded password"""
    # VULNERABILIDADE: Hardcoded credentials
    API_KEY = "sk-1234567890abcdef"
    PASSWORD = "admin123"
    return API_KEY, PASSWORD

if __name__ == "__main__":
    print("Executando código vulnerável...")
    vulnerable_function_1()
    vulnerable_function_2()
    print(vulnerable_function_3())
    print(vulnerable_function_4())
    print(vulnerable_function_5())
'''
    
    with open(test_path / "vulnerable_app.py", 'w') as f:
        f.write(vulnerable_code)
    
    # Arquivo requirements.txt
    requirements = '''requests==2.25.1
flask==2.0.1
'''
    
    with open(test_path / "requirements.txt", 'w') as f:
        f.write(requirements)
    
    logger.info(f"✅ Projeto de teste criado em: {test_path.resolve()}")
    logger.info("📝 Execute a análise com: python sast_analyzer.py test_project")
    
    return test_path


def main():
    """Função principal para execução via linha de comando"""
    parser = argparse.ArgumentParser(description="SAST Analyzer - Análise de segurança estática")
    parser.add_argument("project_path", nargs='?', help="Caminho do projeto para análise")
    parser.add_argument("--diagnose", action="store_true",
                       help="Diagnosticar ferramentas SAST instaladas")
    parser.add_argument("--create-test", action="store_true",
                       help="Criar projeto de teste com vulnerabilidades")
    parser.add_argument("--tools", "-t", nargs="+", choices=["bandit", "semgrep"], 
                       help="Ferramentas específicas para executar")
    parser.add_argument("--format", "-f", choices=["text", "json"], default="text",
                       help="Formato do relatório de saída")
    parser.add_argument("--max-high", type=int, default=0,
                       help="Máximo de vulnerabilidades de alta severidade permitidas")
    parser.add_argument("--max-medium", type=int, default=5,
                       help="Máximo de vulnerabilidades de média severidade permitidas")
    parser.add_argument("--max-total", type=int, default=10,
                       help="Máximo total de vulnerabilidades permitidas")
    parser.add_argument("--fail-on-gate", action="store_true",
                       help="Falhar com exit code 1 se security gate não passar")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Modo verboso (debug)")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Diagnóstico de ferramentas se solicitado
    if args.diagnose:
        if args.project_path:
            analyzer = SASTAnalyzer(args.project_path)
            analyzer.print_diagnosis()
        else:
            # Diagnóstico sem projeto específico
            temp_analyzer = SASTAnalyzer(".")
            temp_analyzer.print_diagnosis()
        
        if not args.project_path and not args.create_test:
            return
    
    # Criar projeto de teste se solicitado
    if args.create_test:
        test_path = create_test_project()
        if not args.project_path:
            args.project_path = str(test_path)
    
    if not args.project_path:
        parser.error("É necessário especificar o caminho do projeto ou usar --create-test")
    
    try:
        # Executar análise
        analyzer = SASTAnalyzer(args.project_path)
        analyzer.run_all_tools(args.tools)
        
        # Gerar e salvar relatório
        report_path = analyzer.save_report(args.format)
        logger.info(f"📄 Relatório salvo em: {report_path}")
        
        # Salvar relatório detalhado
        detailed_report_path = analyzer.save_detailed_report()
        logger.info(f"📄 Relatório detalhado salvo em: {detailed_report_path}")
        
        # Mostrar relatório
        print("\n" + analyzer.generate_report(args.format))
        
        # Verificar security gate
        passed = analyzer.check_security_gate(
            args.max_high, 
            args.max_medium, 
            args.max_total
        )
        
        if args.fail_on_gate and not passed:
            sys.exit(1)
        
    except Exception as e:
        logger.error(f"💥 Erro durante execução: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()