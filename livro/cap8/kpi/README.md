# Sistema de Métricas de Patch Management

Um sistema simples e eficiente para monitoramento e análise de KPIs relacionados ao gerenciamento de patches de segurança.

## Índice

- [Sobre o Projeto](#sobre-o-projeto)
- [Funcionalidades](#funcionalidades)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso Básico](#uso-básico)
- [Métricas Disponíveis](#métricas-disponíveis)
- [Exemplos](#exemplos)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Contribuição](#contribuição)
- [Licença](#licença)

## Sobre o Projeto

Este sistema foi desenvolvido para auxiliar equipes de TI e segurança a monitorar a eficiência do processo de patch management através de métricas claras e acionáveis. O foco é simplicidade e praticidade, fornecendo insights essenciais sem complexidade desnecessária.

### Principais Benefícios

- **Visibilidade**: Métricas claras sobre conformidade e performance
- **Simplicidade**: Interface direta e fácil de usar
- **Acionável**: Recomendações automáticas baseadas nos dados
- **Trends**: Score de saúde consolidado (0-100)
- **Flexível**: Suporte a diferentes fontes de dados

## Funcionalidades

### Métricas Principais
- **MTTP (Mean Time to Patch)**: Tempo médio para aplicação de patches
- **Taxa de Conformidade**: Percentual de sistemas em conformidade
- **Taxa de Sucesso de Deployment**: Eficiência das implantações
- **Resumo de Vulnerabilidades**: Distribuição por severidade
- **Score de Saúde**: Pontuação consolidada de 0-100

### Recursos Adicionais
- Análise por ambiente (produção, desenvolvimento, staging)
- Categorização por criticidade do sistema
- Relatórios em JSON e texto
- Recomendações automáticas
- Tratamento robusto de erros

## Requisitos

- Python 3.7+
- Módulos padrão do Python (datetime, typing, json, statistics)

## Instalação

1. **Clone o repositório**
```bash
git clone https://github.com/mvdiogo/security.git
cd security/livro/cap8/kpi
```

2. **Execute o sistema**
```bash
python3 app.py
```

Não há dependências externas - o sistema usa apenas a biblioteca padrão do Python.

## Uso Básico

### Exemplo Simples

```python
from patch_metrics import PatchManagementMetrics, MockDataSource

# Inicializar com fonte de dados
data_source = MockDataSource()  # ou sua própria implementação
metrics = PatchManagementMetrics(data_source)

# Gerar relatório executivo
summary = metrics.generate_executive_summary()
print(f"Score de Saúde: {summary['health_score']}/100")

# Exportar relatório completo
report = metrics.export_report("text")
print(report)
```

### Implementando sua Fonte de Dados

```python
class MinhaFonteDeDados:
    def get_patch_history(self, start_date, severity_filter=None):
        # Retornar lista de patches com status, datas, etc.
        pass
    
    def get_all_systems(self):
        # Retornar lista de sistemas com ambiente, criticidade
        pass
    
    def get_pending_patches(self, system_id, severity):
        # Retornar patches pendentes para um sistema específico
        pass
    
    def get_deployment_history(self, start_date):
        # Retornar histórico de deployments
        pass
```

## Métricas Disponíveis

### 1. Mean Time to Patch (MTTP)
```python
mttp = metrics.calculate_mean_time_to_patch("Critical")
print(f"Tempo médio: {mttp['mean']:.1f} horas")
```

**Retorna:**
- Média, mediana e desvio padrão
- Valores mínimo e máximo
- Tamanho da amostra

### 2. Taxa de Conformidade
```python
compliance = metrics.calculate_compliance_rate()
print(f"Conformidade geral: {compliance['overall_rate']:.1f}%")
```

**Análise por:**
- Ambiente (produção, desenvolvimento, staging)
- Criticidade do sistema (critical, high, medium, low)

### 3. Taxa de Sucesso de Deployment
```python
success = metrics.calculate_deployment_success_rate(days=30)
print(f"Taxa de sucesso: {success['success_rate']:.1f}%")
```

**Inclui:**
- Deployments bem-sucedidos, falhados e rollbacks
- Razões de falha categorizadas

### 4. Score de Saúde
Pontuação de 0-100 baseada em:
- **40%** - Taxa de conformidade
- **30%** - Taxa de sucesso de deployment  
- **30%** - Tempo de resposta para patches críticos

## Exemplos

### Relatório Executivo
```python
summary = metrics.generate_executive_summary()

print(f"""
Score de Saúde: {summary['health_score']}/100
Conformidade: {summary['compliance_rate']:.1f}%
Sistemas: {summary['total_systems']}
Vulns Críticas: {summary['critical_vulnerabilities']}
""")

for rec in summary['recommendations']:
    print(f"• {rec}")
```

### Exportação de Relatórios
```python
# Relatório em texto
text_report = metrics.export_report("text")
with open("relatorio.txt", "w") as f:
    f.write(text_report)

# Relatório em JSON
json_report = metrics.export_report("json")
with open("relatorio.json", "w") as f:
    f.write(json_report)
```

### Análise Detalhada
```python
# Análise por ambiente
compliance = metrics.calculate_compliance_rate()
for env, data in compliance['by_environment'].items():
    print(f"{env}: {data['rate']:.1f}% ({data['compliant']}/{data['total']})")

# Vulnerabilidades por severidade
vulns = metrics.get_vulnerability_summary()
for severity, count in vulns['by_severity'].items():
    print(f"{severity}: {count} vulnerabilidades")
```

## Estrutura do Projeto

```
patch-metrics/
├── app.py          # Sistema principal
└── README.md                 # Este arquivo
```

## Personalização

### Ajustando Thresholds
```python
# Customizar critérios para recomendações
def custom_recommendations(self, report_data):
    recommendations = []
    
    # Seu critério personalizado
    if report_data["compliance_rate"] < 90:
        recommendations.append("Ação customizada necessária")
    
    return recommendations
```

### Métricas Customizadas
```python
def calculate_custom_metric(self):
    """Sua métrica específica"""
    # Implementar lógica personalizada
    return {"custom_value": 42}
```

## Interpretação dos Resultados

### Score de Saúde
- **90-100**: Excelente - processo maduro e eficiente
- **70-89**: Bom - algumas melhorias necessárias  
- **50-69**: Regular - atenção a gaps críticos
- **0-49**: Crítico - revisão urgente do processo

### Benchmarks Sugeridos
- **Taxa de Conformidade**: > 95%
- **MTTP Crítico**: < 24 horas
- **MTTP Alto**: < 72 horas
- **Taxa de Sucesso**: > 90%
- **Rollbacks**: < 5% dos deployments

## Contribuição

Contribuições são bem-vindas! Por favor:

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

### Diretrizes
- Mantenha o código simples e legível
- Adicione testes para novas funcionalidades
- Documente mudanças no README

## Problemas Conhecidos

- Mock data source é apenas para demonstração
- Não há persistência de dados históricos
- Análise de trends requer implementação da fonte de dados
