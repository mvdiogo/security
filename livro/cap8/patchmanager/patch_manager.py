#!/usr/bin/env python3
# Sistema de classificação e priorização de patches

import json
import requests
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum

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
    criticality: str  # critical, high, medium, low
    exposure: str     # internet_facing, internal, isolated
    data_classification: str  # public, internal, confidential, restricted
    business_impact: str      # high, medium, low

class PatchPrioritizationEngine:
    def __init__(self):
        self.vulnerability_feeds = [
            "https://services.nvd.nist.gov/rest/json/cves/1.0",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        ]
        
        # Pesos para cálculo de prioridade
        self.priority_weights = {
            "cvss_score": 0.3,
            "exploit_availability": 0.25,
            "asset_criticality": 0.2,
            "exposure_level": 0.15,
            "data_sensitivity": 0.1
        }
    
    def fetch_vulnerability_data(self, cve_id: str) -> Optional[VulnerabilityInfo]:
        """Buscar dados de vulnerabilidade de fontes externas"""
        try:
            # Consultar NVD
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0/{cve_id}"
            response = requests.get(nvd_url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                cve_item = data["result"]["CVE_Items"][0]
                
                # Extrair informações relevantes
                cvss_data = cve_item["impact"]["baseMetricV3"]["cvssV3"]
                
                vuln_info = VulnerabilityInfo(
                    cve_id=cve_id,
                    cvss_score=cvss_data["baseScore"],
                    cvss_vector=cvss_data["vectorString"],
                    description=cve_item["cve"]["description"]["description_data"][0]["value"],
                    affected_products=self.extract_affected_products(cve_item),
                    exploit_status=self.check_exploit_status(cve_id),
                    published_date=datetime.fromisoformat(cve_item["publishedDate"].replace("Z", "+00:00")),
                    patch_available=self.check_patch_availability(cve_id),
                    patch_complexity=self.assess_patch_complexity(cve_item)
                )
                
                return vuln_info
                
        except Exception as e:
            print(f"Erro ao buscar dados de vulnerabilidade para {cve_id}: {e}")
            return None
    
    def check_exploit_status(self, cve_id: str) -> ExploitStatus:
        """Verificar status de exploração da vulnerabilidade"""
        try:
            # Verificar CISA KEV (Known Exploited Vulnerabilities)
            kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            response = requests.get(kev_url, timeout=30)
            
            if response.status_code == 200:
                kev_data = response.json()
                for vuln in kev_data["vulnerabilities"]:
                    if vuln["cveID"] == cve_id:
                        return ExploitStatus.ACTIVE
            
            # Verificar outras fontes de exploit (ExploitDB, Metasploit, etc.)
            # Implementação simplificada  em produção, integrar com múltiplas fontes
            exploit_sources = [
                f"https://www.exploitdb.com/search?cve={cve_id}",
                f"https://www.rapid7.com/db/?q={cve_id}"
            ]
            
            for source in exploit_sources:
                try:
                    response = requests.get(source, timeout=10)
                    if "exploit" in response.text.lower():
                        return ExploitStatus.POC_AVAILABLE
                except:
                    continue
            
            return ExploitStatus.THEORETICAL
            
        except Exception as e:
            print(f"Erro ao verificar status de exploit para {cve_id}: {e}")
            return ExploitStatus.NONE
    
    def calculate_patch_priority(self, vuln_info: VulnerabilityInfo, asset_context: AssetContext) -> tuple:
        """Calcular prioridade do patch baseado em múltiplos fatores"""
        
        # Normalizar CVSS score (010 para 01)
        cvss_normalized = vuln_info.cvss_score / 10.0
        
        # Pontuação de exploit
        exploit_scores = {
            ExploitStatus.ACTIVE: 1.0,
            ExploitStatus.POC_AVAILABLE: 0.8,
            ExploitStatus.THEORETICAL: 0.4,
            ExploitStatus.NONE: 0.1
        }
        exploit_score = exploit_scores.get(vuln_info.exploit_status, 0.1)
        
        # Pontuação de criticidade do ativo
        criticality_scores = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2
        }
        asset_score = criticality_scores.get(asset_context.criticality, 0.2)
        
        # Pontuação de exposição
        exposure_scores = {
            "internet_facing": 1.0,
            "internal": 0.6,
            "isolated": 0.2
        }
        exposure_score = exposure_scores.get(asset_context.exposure, 0.6)
        
        # Pontuação de sensibilidade dos dados
        data_scores = {
            "restricted": 1.0,
            "confidential": 0.8,
            "internal": 0.5,
            "public": 0.2
        }
        data_score = data_scores.get(asset_context.data_classification, 0.5)
        
        # Calcular pontuação final ponderada
        final_score = (
            cvss_normalized * self.priority_weights["cvss_score"] +
            exploit_score * self.priority_weights["exploit_availability"] +
            asset_score * self.priority_weights["asset_criticality"] +
            exposure_score * self.priority_weights["exposure_level"] +
            data_score * self.priority_weights["data_sensitivity"]
        )
        
        # Determinar prioridade baseada na pontuação
        if final_score >= 0.8:
            priority = PatchPriority.CRITICAL
            sla_hours = 24
        elif final_score >= 0.6:
            priority = PatchPriority.HIGH
            sla_hours = 72
        elif final_score >= 0.4:
            priority = PatchPriority.MEDIUM
            sla_hours = 168  # 1 semana
        else:
            priority = PatchPriority.LOW
            sla_hours = 720  # 30 dias
        
        return priority, final_score, sla_hours
    
    def generate_patch_deployment_plan(self, vulnerabilities: List[tuple]) -> Dict:
        """Gerar plano de implantação de patches"""
        
        # Agrupar por prioridade
        priority_groups = {
            PatchPriority.CRITICAL: [],
            PatchPriority.HIGH: [],
            PatchPriority.MEDIUM: [],
            PatchPriority.LOW: []
        }
        
        for vuln_info, asset_context, priority, score, sla in vulnerabilities:
            priority_groups[priority].append({
                "cve_id": vuln_info.cve_id,
                "asset_id": asset_context.asset_id,
                "score": score,
                "sla_hours": sla,
                "deadline": datetime.now() + timedelta(hours=sla)
            })
        
        # Criar cronograma de implantação
        deployment_plan = {
            "generated_at": datetime.now().isoformat(),
            "total_patches": len(vulnerabilities),
            "priority_breakdown": {
                priority.value: len(patches) 
                for priority, patches in priority_groups.items()
            },
            "deployment_schedule": {
                "emergency_window": {
                    "patches": priority_groups[PatchPriority.CRITICAL],
                    "window_start": datetime.now().isoformat(),
                    "window_duration": "24 hours",
                    "approval_required": True,
                    "rollback_plan": "mandatory"
                },
                "weekly_maintenance": {
                    "patches": priority_groups[PatchPriority.HIGH] + priority_groups[PatchPriority.MEDIUM],
                    "window_start": self.get_next_maintenance_window().isoformat(),
                    "window_duration": "4 hours",
                    "approval_required": True,
                    "rollback_plan": "recommended"
                },
                "monthly_maintenance": {
                    "patches": priority_groups[PatchPriority.LOW],
                    "window_start": self.get_next_monthly_window().isoformat(),
                    "window_duration": "8 hours",
                    "approval_required": False,
                    "rollback_plan": "optional"
                }
            },
            "risk_assessment": self.assess_deployment_risk(priority_groups),
            "resource_requirements": self.calculate_resource_requirements(priority_groups)
        }
        
        return deployment_plan
    
    def get_next_maintenance_window(self) -> datetime:
        """Obter próxima janela de manutenção semanal"""
        now = datetime.now()
        # Assumir janela de manutenção aos domingos às 2:00 AM
        days_until_sunday = (6 * now.weekday()) % 7
        if days_until_sunday == 0 and now.hour >= 2:
            days_until_sunday = 7
        
        next_window = now + timedelta(days=days_until_sunday)
        return next_window.replace(hour=2, minute=0, second=0, microsecond=0)
    
    def get_next_monthly_window(self) -> datetime:
        """Obter próxima janela de manutenção mensal"""
        now = datetime.now()
        # Assumir janela mensal no primeiro sábado do mês
        first_day = now.replace(day=1)
        first_saturday = first_day + timedelta(days=(5 * first_day.weekday()) % 7)
        
        if now > first_saturday:
            # Próximo mês
            if now.month == 12:
                next_month = now.replace(year=now.year + 1, month=1, day=1)
            else:
                next_month = now.replace(month=now.month + 1, day=1)
            
            first_saturday = next_month + timedelta(days=(5 * next_month.weekday()) % 7)
        
        return first_saturday.replace(hour=1, minute=0, second=0, microsecond=0)

# Exemplo de uso
if __name__ == "__main__":
    engine = PatchPrioritizationEngine()
    
    # Simular vulnerabilidade crítica
    critical_vuln = VulnerabilityInfo(
        cve_id="CVE20241234",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="Remote code execution in web server",
        affected_products=["Apache HTTP Server 2.4.x"],
        exploit_status=ExploitStatus.ACTIVE,
        published_date=datetime.now() - timedelta(days=1),
        patch_available=True,
        patch_complexity="low"
    )
    
    # Contexto do ativo crítico
    critical_asset = AssetContext(
        asset_id="webserverprod01",
        criticality="critical",
        exposure="internet_facing",
        data_classification="confidential",
        business_impact="high"
    )
    
    # Calcular prioridade
    priority, score, sla = engine.calculate_patch_priority(critical_vuln, critical_asset)
    
    print(f"Prioridade: {priority.value}")
    print(f"Pontuação: {score:.2f}")
    print(f"SLA: {sla} horas")
    print(f"Deadline: {datetime.now() + timedelta(hours=sla)}")
