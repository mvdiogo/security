# Sistema de Resposta Automatizada a Ameaças WAF

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

O Sistema de Resposta Automatizada a Ameaças WAF é uma solução avançada para detecção e mitigação proativa de ataques cibernéticos em tempo real. Projetado para integrar-se com firewalls e sistemas SIEM, este sistema aplica inteligência artificial e análise comportamental para proteger aplicações web contra ameaças modernas.

## Funcionalidades Principais

- **Detecção Avançada de Ameaças**
  - SQL Injection, XSS, LFI, Command Injection
  - Ransomware, Directory Traversal, XXE
  - Análise de payloads com normalização multi-camada
- **Resposta Automatizada**
  - Bloqueio de IPs maliciosos
  - Aplicação de rate limiting
  - Integração com firewalls (AWS, Azure, etc.)
- **Resiliência Operacional**
  - Circuit breaker para APIs externas
  - Retry exponencial com jitter
  - Modo simulação para desenvolvimento
- **Monitoramento e Alertas**
  - Webhooks para notificações
  - Logs estruturados em JSON
  - Métricas de eficácia da resposta
- **Suporte Completo a IPv4/IPv6**
  - Whitelist/Blacklist com CIDR
  - Validação rigorosa de endereços

## Casos de Uso

- Proteção de aplicações web contra OWASP Top 10
- Conformidade com LGPD e regulamentações setoriais
- Redução de falsos positivos em WAFs corporativos
- Automação de resposta a incidentes de segurança

## Pré-requisitos

- Python 3.8+
- Bibliotecas:
  ```bash
  pip install requests ipaddress regex
  ```

## Configuração Rápida

1. Clone o repositório:
   ```bash
   git clone https://github.com/security.git
   cd security/livro/cap9/waf_resposta
   ```

2. Configure o arquivo `config.json`:
   ```json
   {
     "siem_api_url": "https://api.seu-siem.com/events",
     "firewall_api_url": "https://api.seu-firewall.com/block",
     "alert_webhook": "https://hooks.slack.com/services/...",
     "attack_count_critical": 10,
     "attack_count_high": 5,
     "whitelist_cidrs": ["10.0.0.0/8", "192.168.0.0/16"],
     "blacklist_ips": ["203.0.113.42"],
     "analysis_interval": 120
   }
   ```

3. Execute o sistema:
   ```bash
   python app.py
   ```

## Modos de Operação

| Modo | Descrição | Comando |
|------|-----------|---------|
| Produção | Conexão com APIs reais | `python app.py` |
| Simulação | Teste sem APIs externas | Configure URLs vazias no config.json |
| Debug | Logs detalhados | `export LOG_LEVEL=DEBUG` |

## Estrutura do Projeto

```
waf-auto-response-system/
├── app.py                  # Código principal
├── config.json             # Arquivo de configuração
├── requirements.txt        # Dependências
└── README.md               # Este arquivo
```

## Licença

Distribuído sob licença MIT. Veja `LICENSE` para mais informações.
