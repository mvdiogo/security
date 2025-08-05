#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script completo para:
1. Extrair ativos do scan Nmap (-oG)
2. Extrair CVEs do Nmap com vulners
3. Buscar informações dos CVEs
4. Calcular prioridades de correção
5. Gerar relatório final em JSON
6. Gerar dashboard HTML com visualização
"""

import re
import sys
import json
import time
import requests
import webbrowser
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional

# ========== Etapa 1: Análise dos ativos ==========
def extrair_produtos(port_info):
    produtos = []
    for porta in port_info.split(','):
        campos = porta.split('/')
        if len(campos) >= 5:
            nome_produto = campos[4].strip()
            if nome_produto:
                produtos.append(nome_produto)
    return produtos

def processar_linha(linha):
    if not linha.startswith("Host:"):
        return None

    try:
        partes = linha.split()
        ip = partes[1]
        hostname = "unknown"
        if len(partes) >= 3 and "(" in partes[2]:
            hostname = partes[2].split('(')[-1].strip(')') or "unknown"

        match = re.search(r'Ports: ([^;]+)', linha)
        produtos = []
        if match:
            produtos = extrair_produtos(match.group(1))
        if not produtos:
            produtos = ["unknown"]

        criticality = "medium"
        exposure = "internal"
        data_classification = "public"
        business_impact = "moderate"

        return f"{ip}\t{hostname}\t{','.join(produtos)}\t{criticality}\t{exposure}\t{data_classification}\t{business_impact}"
    except Exception as e:
        print(f"Erro ao processar linha: {linha.strip()}")
        print(e)
        return None


def gerar_ativos(scan_path: Path, ativos_path: Path):
    linhas_processadas = []
    for linha in scan_path.read_text(encoding="utf-8").splitlines():
        resultado = processar_linha(linha)
        if resultado:
            linhas_processadas.append(resultado)
    ativos_path.write_text("\n".join(linhas_processadas), encoding="utf-8")
    print(f"[✔] {ativos_path.name} gerado com {len(linhas_processadas)} ativos.")
    return ativos_path


# ========== Etapa 2: Extração de CVEs ==========
def extrair_cves(texto):
    cve_regex = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    return sorted(set(cve_regex.findall(texto)))

def salvar_cves(cves, destino: Path):
    destino.write_text("\n".join(c.upper() for c in cves))
    print(f"[✔] {len(cves)} CVEs salvos em: {destino}")


# ========== Etapa 3: Estruturas e Engine ==========
class PatchPriority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class ExploitStatus(Enum):
    ACTIVE = "active_exploitation"
    POC_AVAILABLE = "poc_available"
    THEORETICAL = "theoretical"
    NONE = "no_known_exploits"

@dataclass
class VulnerabilityInfo:
    cve_id: str
    cvss_score: float
    cvss_vector: str
    description: str
    affected_products: List[str]
    exploit_status: ExploitStatus
    published_date: datetime
    patch_available: bool
    patch_complexity: str

@dataclass
class AssetContext:
    asset_id: str
    hostname: str
    products: str
    criticality: str
    exposure: str
    data_classification: str
    business_impact: str

class PatchPrioritizationEngine:
    def __init__(self):
        self.known_exploits_feed = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.weights = {
            "cvss_score": 0.3,
            "exploit_availability": 0.25,
            "asset_criticality": 0.2,
            "exposure_level": 0.15,
            "data_sensitivity": 0.1
        }

    def fetch_vulnerability_data(self, cve_id: str) -> Optional[VulnerabilityInfo]:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code != 200:
                print(f"[!] Erro ao buscar {cve_id}: status {r.status_code}")
                return None
            
            data = r.json()
            if not data.get("vulnerabilities") or len(data["vulnerabilities"]) == 0:
                print(f"[!] CVE {cve_id} não encontrado no NVD.")
                return None
            
            cve_data = data["vulnerabilities"][0]["cve"]
            
            descriptions = cve_data.get("descriptions", [])
            description_en = "No description available"
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description_en = desc.get("value", description_en)
                    break
            
            metrics = cve_data.get("metrics", {})
            baseScore = 0.0
            vector = "N/A"
            for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_type in metrics and metrics[metric_type]:
                    metric = metrics[metric_type][0]
                    if "cvssData" in metric:
                        baseScore = metric["cvssData"].get("baseScore", 0.0)
                        vector = metric["cvssData"].get("vectorString", "N/A")
                        break
            
            published_str = cve_data.get("published")
            if published_str:
                published_date = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
            else:
                published_date = datetime.now()
            
            exploit_status = self.check_exploit_status(cve_id)
            
            return VulnerabilityInfo(
                cve_id=cve_id,
                cvss_score=baseScore,
                cvss_vector=vector,
                description=description_en,
                affected_products=[],
                exploit_status=exploit_status,
                published_date=published_date,
                patch_available=True,
                patch_complexity="low"
            )
        except Exception as e:
            print(f"[!] Erro com {cve_id}: {e}")
            return None

    def check_exploit_status(self, cve_id: str) -> ExploitStatus:
        try:
            r = requests.get(self.known_exploits_feed, timeout=30)
            data = r.json()
            for v in data.get("vulnerabilities", []):
                if v["cveID"] == cve_id:
                    return ExploitStatus.ACTIVE
            return ExploitStatus.THEORETICAL
        except:
            return ExploitStatus.NONE

    def calculate_patch_priority(self, vuln: VulnerabilityInfo, asset: AssetContext):
        cvss_normalized = vuln.cvss_score / 10
        exploit_scores = {
            ExploitStatus.ACTIVE: 1.0,
            ExploitStatus.POC_AVAILABLE: 0.8,
            ExploitStatus.THEORETICAL: 0.4,
            ExploitStatus.NONE: 0.1
        }
        exposure_scores = {"internet_facing": 1.0, "internal": 0.6, "isolated": 0.2}
        criticality_scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
        data_scores = {"restricted": 1.0, "confidential": 0.8, "internal": 0.5, "public": 0.2}

        final_score = (
            cvss_normalized * self.weights["cvss_score"] +
            exploit_scores[vuln.exploit_status] * self.weights["exploit_availability"] +
            criticality_scores[asset.criticality] * self.weights["asset_criticality"] +
            exposure_scores[asset.exposure] * self.weights["exposure_level"] +
            data_scores[asset.data_classification] * self.weights["data_sensitivity"]
        )

        if final_score >= 0.8:
            return PatchPriority.CRITICAL, final_score, 24
        elif final_score >= 0.6:
            return PatchPriority.HIGH, final_score, 72
        elif final_score >= 0.4:
            return PatchPriority.MEDIUM, final_score, 168
        else:
            return PatchPriority.LOW, final_score, 720

    def generate_patch_plan(self, results: List[tuple]):
        plan = {
            "generated_at": datetime.now().isoformat(),
            "total_patches": len(results),
            "priority_breakdown": {},
            "deployment_schedule": {},
            "all_patches": []
        }
        buckets = {p: [] for p in PatchPriority}
        
        for vuln, asset, prio, score, sla in results:
            deadline = (datetime.now() + timedelta(hours=sla)).isoformat()
            patch_data = {
                "cve_id": vuln.cve_id,
                "asset": asset.asset_id,
                "hostname": asset.hostname,
                "products": asset.products,
                "priority": prio.value,
                "score": round(score, 2),
                "sla_hours": sla,
                "deadline": deadline,
                "cvss_score": vuln.cvss_score,
                "exploit_status": vuln.exploit_status.value,
                "exposure": asset.exposure,
                "criticality": asset.criticality
            }
            plan["all_patches"].append(patch_data)
            buckets[prio].append(patch_data)

        plan["priority_breakdown"] = {p.value: len(v) for p, v in buckets.items()}
        plan["deployment_schedule"] = {
            "emergency": buckets[PatchPriority.CRITICAL],
            "weekly": buckets[PatchPriority.HIGH] + buckets[PatchPriority.MEDIUM],
            "monthly": buckets[PatchPriority.LOW],
        }
        return plan


# ========== Geração de Dashboard HTML ==========
def generate_html_dashboard(plano: dict):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"patch_dashboard_{timestamp}.html"
    
    # Calcular estatísticas para o dashboard
    total_patches = plano["total_patches"]
    critical = plano["priority_breakdown"]["critical"]
    high = plano["priority_breakdown"]["high"]
    medium = plano["priority_breakdown"]["medium"]
    low = plano["priority_breakdown"]["low"]
    
    # Calcular prazos críticos
    now = datetime.now()
    critical_patches = [p for p in plano["all_patches"] if p["priority"] == "critical"]
    critical_patches.sort(key=lambda x: datetime.fromisoformat(x["deadline"]))
    
    # Preparar dados para gráficos
    priority_data = {
        "labels": ["Critical", "High", "Medium", "Low"],
        "counts": [critical, high, medium, low],
        "colors": ["#dc3545", "#ffc107", "#17a2b8", "#28a745"]
    }
    
    # Funções auxiliares para gerar linhas da tabela
    def generate_critical_row(patch):
        return f"""
        <tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/{patch['cve_id']}" target="_blank">{patch['cve_id']}</a></td>
            <td>{patch['asset']} ({patch['hostname']})</td>
            <td>{patch['products']}</td>
            <td>{patch['score']}</td>
            <td>{patch['cvss_score']}</td>
            <td>{patch['exploit_status'].replace('_', ' ').title()}</td>
            <td>{patch['deadline'].replace('T', ' ').split('.')[0]}</td>
            <td class="remaining-time" data-deadline="{patch['deadline']}"></td>
        </tr>
        """
    
    def generate_patch_row(patch):
        priority_class = {
            "critical": "critical-badge",
            "high": "high-badge",
            "medium": "medium-badge",
            "low": "low-badge"
        }[patch["priority"]]
        
        return f"""
        <tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/{patch['cve_id']}" target="_blank">{patch['cve_id']}</a></td>
            <td><span class="badge priority-badge {priority_class}">{patch['priority'].upper()}</span></td>
            <td>{patch['asset']}</td>
            <td>{patch['products']}</td>
            <td>{patch['score']}</td>
            <td>{patch['sla_hours']}</td>
            <td>{patch['deadline'].split('T')[0]}</td>
        </tr>
        """
    
    # Gerar as linhas das tabelas ANTES de construir o HTML
    critical_rows = "".join([generate_critical_row(p) for p in critical_patches])
    all_patches_rows = "".join([generate_patch_row(p) for p in plano["all_patches"]])
    
    # Gerar HTML com dashboard interativo
    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Patch Prioritization Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            .card {{ margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,.1); }}
            .critical-card {{ border-left: 5px solid #dc3545; }}
            .high-card {{ border-left: 5px solid #ffc107; }}
            .medium-card {{ border-left: 5px solid #17a2b8; }}
            .low-card {{ border-left: 5px solid #28a745; }}
            .priority-badge {{ font-size: 0.8em; }}
            .critical-badge {{ background-color: #dc3545; }}
            .high-badge {{ background-color: #ffc107; color: #000; }}
            .medium-badge {{ background-color: #17a2b8; }}
            .low-badge {{ background-color: #28a745; }}
            .sla-warning {{ background-color: #fff3cd; border-left: 5px solid #ffc107; }}
            .sla-critical {{ background-color: #f8d7da; border-left: 5px solid #dc3545; }}
        </style>
    </head>
    <body>
        <div class="container-fluid">
            <div class="row mt-4">
                <div class="col-12">
                    <h1 class="text-center">Patch Prioritization Dashboard</h1>
                    <p class="text-center text-muted">Gerado em: {plano["generated_at"]}</p>
                </div>
            </div>
            
            <!-- Cards de Resumo -->
            <div class="row mt-4">
                <div class="col-md-3">
                    <div class="card critical-card">
                        <div class="card-body">
                            <h5 class="card-title">Critical</h5>
                            <h2 class="display-4">{critical}</h2>
                            <p class="card-text">Patches com SLA de 24h</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card high-card">
                        <div class="card-body">
                            <h5 class="card-title">High</h5>
                            <h2 class="display-4">{high}</h2>
                            <p class="card-text">SLA de 72h</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card medium-card">
                        <div class="card-body">
                            <h5 class="card-title">Medium</h5>
                            <h2 class="display-4">{medium}</h2>
                            <p class="card-text">SLA de 1 semana</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card low-card">
                        <div class="card-body">
                            <h5 class="card-title">Low</h5>
                            <h2 class="display-4">{low}</h2>
                            <p class="card-text">SLA de 1 mês</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Gráficos -->
            <div class="row mt-4">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5>Distribuição de Prioridades</h5>
                        </div>
                        <div class="card-body">
                            <canvas id="priorityChart" height="250"></canvas>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5>Distribuição de Prazos</h5>
                        </div>
                        <div class="card-body">
                            <canvas id="deadlineChart" height="250"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Lista de Patches Críticos -->
            <div class="row mt-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5>Patches Críticos (SLA de 24 horas)</h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>CVE ID</th>
                                            <th>Ativo</th>
                                            <th>Produto</th>
                                            <th>Score</th>
                                            <th>CVSS</th>
                                            <th>Exploit</th>
                                            <th>Prazo Limite</th>
                                            <th>Tempo Restante</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {critical_rows}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Lista Completa de Patches -->
            <div class="row mt-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5>Todos os Patches ({total_patches})</h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped">
                                    <thead>
                                        <tr>
                                            <th>CVE ID</th>
                                            <th>Prioridade</th>
                                            <th>Ativo</th>
                                            <th>Produto</th>
                                            <th>Score</th>
                                            <th>SLA (h)</th>
                                            <th>Prazo</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {all_patches_rows}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            // Gráfico de distribuição de prioridades
            const priorityCtx = document.getElementById('priorityChart').getContext('2d');
            new Chart(priorityCtx, {{
                type: 'doughnut',
                data: {{
                    labels: {json.dumps(priority_data["labels"])},
                    datasets: [{{
                        data: {json.dumps(priority_data["counts"])},
                        backgroundColor: {json.dumps(priority_data["colors"])}
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{ position: 'right' }},
                        title: {{ display: true, text: 'Distribuição de Patches por Prioridade' }}
                    }}
                }}
            }});
            
            // Gráfico de prazos
            const deadlineCtx = document.getElementById('deadlineChart').getContext('2d');
            const slaHours = {json.dumps([p["sla_hours"] for p in plano["all_patches"]])};
            new Chart(deadlineCtx, {{
                type: 'bar',
                data: {{
                    labels: slaHours.map((_, i) => 'Patch ' + (i+1)),
                    datasets: [{{
                        label: 'Horas até o prazo (SLA)',
                        data: slaHours,
                        backgroundColor: slaHours.map(h => 
                            h <= 24 ? '#dc3545' : 
                            h <= 72 ? '#ffc107' : 
                            h <= 168 ? '#17a2b8' : '#28a745'
                        )
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        title: {{ display: true, text: 'Distribuição de Prazos (SLA em horas)' }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            title: {{ display: true, text: 'Horas' }}
                        }}
                    }}
                }}
            }});
            
            // Atualizar contadores de tempo restante
            function updateRemainingTimes() {{
                document.querySelectorAll('.remaining-time').forEach(el => {{
                    const deadline = new Date(el.dataset.deadline);
                    const now = new Date();
                    const diffMs = deadline - now;
                    
                    if (diffMs <= 0) {{
                        el.innerHTML = '<span class="badge bg-danger">EXPIRADO</span>';
                        return;
                    }}
                    
                    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
                    const diffDays = Math.floor(diffHours / 24);
                    const remainingHours = diffHours % 24;
                    
                    if (diffDays > 0) {{
                        el.innerHTML = `<span class="badge bg-warning text-dark">${{diffDays}}d ${{remainingHours}}h</span>`;
                    }} else if (diffHours > 0) {{
                        el.innerHTML = `<span class="badge bg-warning text-dark">${{diffHours}}h</span>`;
                    }} else {{
                        const diffMinutes = Math.floor(diffMs / (1000 * 60));
                        el.innerHTML = `<span class="badge bg-danger">${{diffMinutes}}min</span>`;
                    }}
                }});
            }}
            
            // Atualizar a cada minuto
            updateRemainingTimes();
            setInterval(updateRemainingTimes, 60000);
        </script>
    </body>
    </html>
    """
    
    # Salvar o arquivo HTML
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[✔] Dashboard HTML gerado em: {filename}")
    return filename
    
    # Funções auxiliares para gerar linhas da tabela
    def generate_critical_row(patch):
        return f"""
        <tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/{patch['cve_id']}" target="_blank">{patch['cve_id']}</a></td>
            <td>{patch['asset']} ({patch['hostname']})</td>
            <td>{patch['products']}</td>
            <td>{patch['score']}</td>
            <td>{patch['cvss_score']}</td>
            <td>{patch['exploit_status'].replace('_', ' ').title()}</td>
            <td>{patch['deadline'].replace('T', ' ').split('.')[0]}</td>
            <td class="remaining-time" data-deadline="{patch['deadline']}"></td>
        </tr>
        """
    
    def generate_patch_row(patch):
        priority_class = {
            "critical": "critical-badge",
            "high": "high-badge",
            "medium": "medium-badge",
            "low": "low-badge"
        }[patch["priority"]]
        
        return f"""
        <tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/{patch['cve_id']}" target="_blank">{patch['cve_id']}</a></td>
            <td><span class="badge priority-badge {priority_class}">{patch['priority'].upper()}</span></td>
            <td>{patch['asset']}</td>
            <td>{patch['products']}</td>
            <td>{patch['score']}</td>
            <td>{patch['sla_hours']}</td>
            <td>{patch['deadline'].split('T')[0]}</td>
        </tr>
        """
    
    # Salvar o arquivo HTML
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[✔] Dashboard HTML gerado em: {filename}")
    return filename


# ========== Execução principal ==========
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python gerar_relatorio_patchs.py <scan.txt> <scan_cves.txt>")
        sys.exit(1)

    scan_txt = Path(sys.argv[1])
    scan_cves = Path(sys.argv[2])
    ativos_txt = Path("ativos.txt")
    cves_txt = Path("vulnerabilidades.txt")

    # Etapa 1
    gerar_ativos(scan_txt, ativos_txt)

    # Etapa 2
    cves = extrair_cves(scan_cves.read_text())
    if not cves:
        print("[!] Nenhum CVE encontrado.")
        sys.exit(0)
    salvar_cves(cves, cves_txt)

    # Etapa 3
    engine = PatchPrioritizationEngine()
    ativos = [AssetContext(*l.split("\t")) for l in ativos_txt.read_text().splitlines()]
    resultados = []

    total_cves = len(cves)
    for i, cve in enumerate(cves):
        print(f"[⏳] Processando CVE {i+1}/{total_cves}: {cve}")
        info = engine.fetch_vulnerability_data(cve)
        if not info:
            continue
        for ativo in ativos:
            prio, score, sla = engine.calculate_patch_priority(info, ativo)
            resultados.append((info, ativo, prio, score, sla))
        
        if i < total_cves - 1:
            time.sleep(6)

    plano = engine.generate_patch_plan(resultados)
    print(f"[🧪 DEBUG] CVEs processados: {len(cves)}")
    print(f"[🧪 DEBUG] Ativos detectados: {len(ativos)}")
    print(f"[🧪 DEBUG] Patches gerados: {len(resultados)}")
    
    # Salvar relatório JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_filename = f"patch_report_{timestamp}.json"
    with open(json_filename, 'w', encoding='utf-8') as f:
        json.dump(plano, f, indent=4, ensure_ascii=False)
    print(f"[✔] Relatório JSON salvo em: {json_filename}")
    
    # Gerar e abrir dashboard
    dashboard_file = generate_html_dashboard(plano)
    webbrowser.open(dashboard_file)