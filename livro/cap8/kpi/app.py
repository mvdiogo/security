#!/usr/bin/env python3
"""
Sistema simplificado de métricas e KPIs para patch management
Versão melhorada com foco em simplicidade e eficiência
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json
import statistics


class PatchManagementMetrics:
    """Sistema de métricas para gerenciamento de patches"""
    
    def __init__(self, data_source):
        self.data_source = data_source
        self.report_cache = {}
    
    def calculate_mean_time_to_patch(self, severity_filter: Optional[str] = None) -> Dict:
        """Calcular tempo médio para aplicação de patches"""
        try:
            start_date = datetime.now() - timedelta(days=90)
            patch_data = self.data_source.get_patch_history(start_date, severity_filter)
            
            time_to_patch = []
            for patch in patch_data:
                if patch.get('status') == 'deployed':
                    try:
                        published = datetime.fromisoformat(patch['published_date'])
                        deployed = datetime.fromisoformat(patch['deployed_date'])
                        hours_diff = (deployed - published).total_seconds() / 3600
                        time_to_patch.append(hours_diff)
                    except (KeyError, ValueError):
                        continue
            
            if not time_to_patch:
                return self._empty_time_metrics(severity_filter)
            
            return {
                "mean": round(statistics.mean(time_to_patch), 2),
                "median": round(statistics.median(time_to_patch), 2),
                "std_dev": round(statistics.stdev(time_to_patch), 2) if len(time_to_patch) > 1 else 0,
                "sample_size": len(time_to_patch),
                "severity": severity_filter or "all",
                "min": round(min(time_to_patch), 2),
                "max": round(max(time_to_patch), 2)
            }
        except Exception as e:
            print(f"Erro ao calcular MTTP: {e}")
            return self._empty_time_metrics(severity_filter)
    
    def _empty_time_metrics(self, severity: Optional[str]) -> Dict:
        """Retorna métricas vazias para tempo"""
        return {
            "mean": 0, "median": 0, "std_dev": 0, "sample_size": 0,
            "severity": severity or "all", "min": 0, "max": 0
        }
    
    def calculate_compliance_rate(self) -> Dict:
        """Calcular taxa de conformidade de patches"""
        try:
            systems = self.data_source.get_all_systems()
            if not systems:
                return {"error": "Nenhum sistema encontrado"}
            
            compliant_count = 0
            compliance_by_env = {}
            compliance_by_crit = {}
            
            for system in systems:
                # Verificar patches críticos pendentes
                pending_critical = self.data_source.get_pending_patches(
                    system.get('id'), 'Critical'
                )
                is_compliant = len(pending_critical) == 0
                
                if is_compliant:
                    compliant_count += 1
                
                # Agrupar por ambiente
                env = system.get('environment', 'unknown')
                if env not in compliance_by_env:
                    compliance_by_env[env] = {"total": 0, "compliant": 0}
                compliance_by_env[env]["total"] += 1
                if is_compliant:
                    compliance_by_env[env]["compliant"] += 1
                
                # Agrupar por criticidade
                crit = system.get('criticality', 'unknown')
                if crit not in compliance_by_crit:
                    compliance_by_crit[crit] = {"total": 0, "compliant": 0}
                compliance_by_crit[crit]["total"] += 1
                if is_compliant:
                    compliance_by_crit[crit]["compliant"] += 1
            
            # Calcular percentuais
            total_systems = len(systems)
            overall_rate = (compliant_count / total_systems) * 100
            
            for category in [compliance_by_env, compliance_by_crit]:
                for key, data in category.items():
                    data["rate"] = round((data["compliant"] / data["total"]) * 100, 2)
            
            return {
                "overall_rate": round(overall_rate, 2),
                "total_systems": total_systems,
                "compliant_systems": compliant_count,
                "non_compliant_systems": total_systems - compliant_count,
                "by_environment": compliance_by_env,
                "by_criticality": compliance_by_crit
            }
        except Exception as e:
            print(f"Erro ao calcular conformidade: {e}")
            return {"error": str(e)}
    
    def calculate_deployment_success_rate(self, days: int = 30) -> Dict:
        """Calcular taxa de sucesso de deployments"""
        try:
            start_date = datetime.now() - timedelta(days=days)
            deployments = self.data_source.get_deployment_history(start_date)
            
            if not deployments:
                return {"error": "Nenhum deployment encontrado no período"}
            
            success_count = sum(1 for d in deployments if d.get('status') == 'deployed')
            failed_count = sum(1 for d in deployments if d.get('status') == 'failed')
            rollback_count = sum(1 for d in deployments if d.get('status') == 'rolled_back')
            
            total = len(deployments)
            success_rate = (success_count / total) * 100 if total > 0 else 0
            
            # Contar razões de falha
            failure_reasons = {}
            for deployment in deployments:
                if deployment.get('status') == 'failed':
                    reason = deployment.get('failure_reason', 'unknown')
                    failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
            
            return {
                "success_rate": round(success_rate, 2),
                "total_deployments": total,
                "successful": success_count,
                "failed": failed_count,
                "rollbacks": rollback_count,
                "failure_reasons": failure_reasons,
                "period_days": days
            }
        except Exception as e:
            print(f"Erro ao calcular taxa de sucesso: {e}")
            return {"error": str(e)}
    
    def get_vulnerability_summary(self) -> Dict:
        """Resumo de vulnerabilidades por severidade"""
        try:
            systems = self.data_source.get_all_systems()
            vulnerability_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            
            for system in systems:
                for severity in vulnerability_count.keys():
                    pending = self.data_source.get_pending_patches(system.get('id'), severity)
                    vulnerability_count[severity] += len(pending)
            
            total_vulns = sum(vulnerability_count.values())
            
            return {
                "total_vulnerabilities": total_vulns,
                "by_severity": vulnerability_count,
                "critical_percentage": round((vulnerability_count["Critical"] / total_vulns) * 100, 2) if total_vulns > 0 else 0
            }
        except Exception as e:
            print(f"Erro ao obter resumo de vulnerabilidades: {e}")
            return {"error": str(e)}
    
    def generate_executive_summary(self) -> Dict:
        """Gerar resumo executivo"""
        compliance = self.calculate_compliance_rate()
        deployment_success = self.calculate_deployment_success_rate()
        mttp_critical = self.calculate_mean_time_to_patch("Critical")
        vulnerability_summary = self.get_vulnerability_summary()
        
        # Gerar recomendações simples
        recommendations = []
        
        if compliance.get("overall_rate", 0) < 95:
            recommendations.append("Melhorar automação para aumentar conformidade")
        
        if mttp_critical.get("mean", 0) > 24:
            recommendations.append("Acelerar processo de patches críticos")
        
        if deployment_success.get("success_rate", 0) < 90:
            recommendations.append("Aprimorar testes pré-deployment")
        
        if vulnerability_summary.get("by_severity", {}).get("Critical", 0) > 0:
            recommendations.append("Priorizar correção de vulnerabilidades críticas")
        
        return {
            "generated_at": datetime.now().isoformat(),
            "compliance_rate": compliance.get("overall_rate", 0),
            "deployment_success_rate": deployment_success.get("success_rate", 0),
            "critical_mttp_hours": mttp_critical.get("mean", 0),
            "total_systems": compliance.get("total_systems", 0),
            "critical_vulnerabilities": vulnerability_summary.get("by_severity", {}).get("Critical", 0),
            "recommendations": recommendations,
            "health_score": self._calculate_health_score(compliance, deployment_success, mttp_critical)
        }
    
    def _calculate_health_score(self, compliance: Dict, deployment: Dict, mttp: Dict) -> int:
        """Calcular pontuação de saúde (0-100)"""
        try:
            score = 0
            
            # Conformidade (40% do score)
            compliance_rate = compliance.get("overall_rate", 0)
            score += (compliance_rate / 100) * 40
            
            # Taxa de sucesso de deployment (30% do score)
            success_rate = deployment.get("success_rate", 0)
            score += (success_rate / 100) * 30
            
            # Tempo de resposta para patches críticos (30% do score)
            mttp_hours = mttp.get("mean", 0)
            if mttp_hours <= 24:
                score += 30
            elif mttp_hours <= 72:
                score += 20
            elif mttp_hours <= 168:  # 1 semana
                score += 10
            
            return min(100, max(0, int(score)))
        except:
            return 0
    
    def export_report(self, format_type: str = "json") -> str:
        """Exportar relatório em formato especificado"""
        summary = self.generate_executive_summary()
        
        if format_type.lower() == "json":
            return json.dumps(summary, indent=2, ensure_ascii=False)
        
        elif format_type.lower() == "text":
            report = f"""
=== RELATÓRIO DE PATCH MANAGEMENT ===
Gerado em: {summary['generated_at']}

RESUMO EXECUTIVO:
• Taxa de Conformidade: {summary['compliance_rate']:.1f}%
• Taxa de Sucesso de Deployment: {summary['deployment_success_rate']:.1f}%
• Tempo Médio para Patches Críticos: {summary['critical_mttp_hours']:.1f} horas
• Sistemas Gerenciados: {summary['total_systems']}
• Vulnerabilidades Críticas: {summary['critical_vulnerabilities']}
• Score de Saúde: {summary['health_score']}/100

RECOMENDAÇÕES:
"""
            for i, rec in enumerate(summary['recommendations'], 1):
                report += f"{i}. {rec}\n"
            
            return report
        
        else:
            raise ValueError("Formato não suportado. Use 'json' ou 'text'")


# Mock data source para demonstração
class MockDataSource:
    """Fonte de dados simulada para testes"""
    
    def get_patch_history(self, start_date, severity_filter=None):
        patches = [
            {
                "id": "patch001", "severity": "Critical",
                "published_date": "2024-01-01T00:00:00",
                "deployed_date": "2024-01-02T12:00:00",
                "status": "deployed"
            },
            {
                "id": "patch002", "severity": "High",
                "published_date": "2024-01-03T00:00:00",
                "deployed_date": "2024-01-05T08:00:00",
                "status": "deployed"
            },
            {
                "id": "patch003", "severity": "Critical",
                "published_date": "2024-01-10T00:00:00",
                "deployed_date": "2024-01-11T06:00:00",
                "status": "deployed"
            }
        ]
        
        if severity_filter:
            patches = [p for p in patches if p['severity'] == severity_filter]
        
        return patches
    
    def get_all_systems(self):
        return [
            {"id": "sys001", "criticality": "critical", "environment": "production"},
            {"id": "sys002", "criticality": "high", "environment": "production"},
            {"id": "sys003", "criticality": "medium", "environment": "development"},
            {"id": "sys004", "criticality": "critical", "environment": "staging"}
        ]
    
    def get_pending_patches(self, system_id, severity):
        # Simular alguns sistemas com patches pendentes
        if system_id == "sys003" and severity == "Critical":
            return [{"id": "pending001", "severity": "Critical"}]
        return []
    
    def get_deployment_history(self, start_date):
        return [
            {"status": "deployed", "system_type": "windows"},
            {"status": "deployed", "system_type": "linux"},
            {"status": "failed", "system_type": "windows", "failure_reason": "reboot_timeout"},
            {"status": "deployed", "system_type": "linux"},
            {"status": "rolled_back", "system_type": "windows"}
        ]


# Exemplo de uso
if __name__ == "__main__":
    # Inicializar sistema
    data_source = MockDataSource()
    metrics = PatchManagementMetrics(data_source)
    
    # Gerar e exibir relatório
    print(metrics.export_report("text"))
    
    # Exemplo de métricas específicas
    print("\n=== MÉTRICAS DETALHADAS ===")
    compliance = metrics.calculate_compliance_rate()
    print(f"Conformidade por ambiente: {compliance.get('by_environment', {})}")
    
    mttp = metrics.calculate_mean_time_to_patch("Critical")
    print(f"MTTP para patches críticos: {mttp.get('mean', 0):.1f} horas")