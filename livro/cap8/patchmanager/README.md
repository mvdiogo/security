# PatchManager - Relatório Inteligente de Vulnerabilidades com Nmap, CVEs e Prioridades

Este projeto automatiza o processo de **detecção de ativos**, **extração de vulnerabilidades** (CVEs) a partir de scans Nmap e geração de um plano de **correção priorizado** com base em criticidade, exposição e escopo dos ativos. É ideal para profissionais de segurança que precisam transformar resultados técnicos em **decisões operacionais eficazes**.

---

## Funcionalidades

- Processa saídas de Nmap (`-oG` e `--script vulners`)
- Extrai ativos com metadados e produtos detectados
- Identifica CVEs únicos no ambiente
- Consulta dados do NVD e CISA KEV
- Calcula a prioridade de correção com base em múltiplos fatores
- Gera um **plano de correção JSON** com SLAs, prazos e classificação de risco

---

## Requisitos

- Python 3.8+
- Nmap com permissão sudo
- Internet ativa (para consultar CVEs)
- Scripts do Nmap (como `vulners.nse`) se quiser detectar CVEs

### Instalação de dependências:

```bash
pip install requests
````

---

## Como Usar

### 1. Faça dois scans Nmap:

**Scan de ativos (produtos/serviços):**

```bash
sudo nmap -sV -oG scan.txt 192.168.20.0/24
```

**Scan com script de vulnerabilidades (vulners):**

```bash
sudo nmap -sV --script vulners -oN scan_cves.txt 192.168.20.0/24
```

> Obs: O script `vulners` precisa estar instalado em seu ambiente. Você pode baixá-lo de [https://github.com/vulnersCom/nmap-vulners](https://github.com/vulnersCom/nmap-vulners).

---

### 2. Execute o script principal:

```bash
python3 patch_manager.py scan.txt scan_cves.txt
```

---

## Arquivos Gerados

| Arquivo                | Descrição                                   |
| ---------------------- | ------------------------------------------- |
| `ativos.txt`           | Lista de ativos com IP, hostname e contexto |
| `vulnerabilidades.txt` | Lista de CVEs extraídos do Nmap             |
| `stdout (JSON)`        | Relatório estruturado com plano de correção |

---

## Exemplo de Saída (parcial)

```json
{
  "generated_at": "2025-07-29T14:00:00",
  "total_patches": 12,
  "priority_breakdown": {
    "critical": 3,
    "high": 5,
    "medium": 3,
    "low": 1
  },
  "deployment_schedule": {
    "emergency": [...],
    "weekly": [...],
    "monthly": [...]
  }
}
```

---

## Objetivo Educacional

Este projeto é voltado para **exercícios e aprendizagem em cibersegurança**. Ele permite aos alunos e analistas simular o ciclo completo de detecção, análise e priorização de vulnerabilidades.

**Importante:** Os dados coletados devem ser utilizados apenas em redes autorizadas. O uso indevido de Nmap ou exploração de CVEs sem permissão é ilegal.

---

## Licença

Este projeto está licenciado sob a [MIT License](LICENSE).
