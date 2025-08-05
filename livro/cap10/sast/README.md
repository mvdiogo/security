# SAST Analyzer

**SAST Analyzer** é uma ferramenta de linha de comando para análise de segurança estática (SAST) em projetos de software. Ele integra ferramentas conhecidas como [Bandit](https://bandit.readthedocs.io/) e [Semgrep](https://semgrep.dev/) para identificar vulnerabilidades no código-fonte, categorizando-as por severidade e gerando relatórios padronizados e informativos.

## Por que usar este projeto?

Em projetos de software modernos, identificar vulnerabilidades o quanto antes é essencial. SAST Analyzer permite realizar essa análise ainda nas fases iniciais de desenvolvimento, evitando riscos críticos em produção. Com suporte para múltiplas ferramentas, relatórios legíveis e integração facilitada com pipelines CI/CD, esta ferramenta é ideal para manter a segurança do código de forma prática, rápida e automatizada.

---

## Funcionalidades

- Suporte a múltiplas ferramentas (Bandit e Semgrep)
- Relatórios em formato **texto** ou **JSON**
- Categorização por severidade (Alta, Média, Baixa)
- Verificação de *Security Gate* com limites personalizáveis
- Geração automática de relatórios em `sast_reports/`
- Detecção de falhas na execução e mensagens amigáveis de erro

---

## Instalação

Certifique-se de ter Python 3.7+ instalado.

Instale as ferramentas suportadas:

```bash
pip install bandit semgrep
````

Clone o repositório e torne o script executável:

```bash
git clone https://github.com/mvdiogo/security.git
cd ./security/livro/cap10/sast
chmod +x sast_analyzer.py
```

---

## Como usar

### Análise padrão:

```bash
python sast_analyzer.py /caminho/do/projeto --verbose
```

### Executar apenas o **Bandit** com limites personalizados:

```bash
python sast_analyzer.py /meuprojeto --tools bandit --max-high 0 --max-medium 3
```

### Gerar relatório em JSON e falhar se o *security gate* não for aprovado:

```bash
python sast_analyzer.py /meuprojeto --format json --fail-on-gate
```

### Configuração completa:

```bash
python sast_analyzer.py /meuprojeto --tools bandit semgrep --max-high 0 --max-medium 5 --max-total 10
```

---

## Relatórios

Os relatórios são salvos automaticamente em `sast_reports/` com nome baseado no timestamp da análise.

* Formato `.txt`: Ideal para leitura humana.
* Formato `.json`: Ideal para integração com outras ferramentas e pipelines.

---

## 🚦 Security Gate

Você pode definir limites de segurança para que a análise falhe caso esses limites sejam ultrapassados:

| Parâmetro        | Descrição                                     | Valor padrão |
| ---------------- | --------------------------------------------- | ------------ |
| `--max-high`     | Máximo permitido de vulnerabilidades críticas | `0`          |
| `--max-medium`   | Máximo permitido de vulnerabilidades médias   | `5`          |
| `--max-total`    | Total máximo permitido de vulnerabilidades    | `10`         |
| `--fail-on-gate` | Força erro (exit 1) se o security gate falhar | `False`      |

---

## Exemplo de saída

```text
🔒 RELATÓRIO DE ANÁLISE SAST
📅 Data: 2025-08-05 10:45:02
📁 Projeto: /home/user/meuprojeto

🔧 BANDIT
✅ Status: Sucesso
⏱️  Tempo: 2.45s
🐛 Total: 5
🔴 Alta: 1
🟡 Média: 2
🟢 Baixa: 2

📊 RESUMO EXECUTIVO
🔧 Ferramentas executadas: 1/1
🐛 Total de vulnerabilidades: 5
🔴 Alta severidade: 1
🟡 Média severidade: 2
🟢 Baixa severidade: 2

💡 RECOMENDAÇÕES
🚨 CRÍTICO: Vulnerabilidades de alta severidade encontradas!
Corrija imediatamente antes do deploy.
```

---

## Licença

Este projeto está licenciado sob os termos da **MIT License**.


