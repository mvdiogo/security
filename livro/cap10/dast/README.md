# DAST Scanner

O **DAST Scanner** é uma ferramenta de teste de segurança automatizada (Dynamic Application Security Testing) projetada para identificar vulnerabilidades em aplicações web, como SQL Injection, Cross-Site Scripting (XSS) e ausência de headers de segurança. A ferramenta inclui uma interface gráfica desenvolvida com Flask, que permite aos usuários iniciar scans e visualizar relatórios de forma intuitiva.

## Funcionalidades

- **Crawling**: Descobre endpoints de uma aplicação web navegando automaticamente pelos links.
- **Testes de Vulnerabilidades**:
  - SQL Injection: Testa parâmetros GET com payloads comuns.
  - XSS (Cross-Site Scripting): Verifica payloads refletidos.
  - Headers de Segurança: Identifica headers ausentes ou mal configurados.
- **Relatórios**:
  - Relatórios detalhados com descrições e recomendações de mitigação.
  - Interface gráfica com design responsivo, destacando vulnerabilidades por severidade (alta, média, baixa).
- **Integração com CI/CD**: Suporte para pipelines, com verificação de critérios de segurança.

## Estrutura do Projeto

```
dast_scanner/
├── app.py              # Aplicação Flask para interface gráfica
├── scanner.py          # Lógica principal do scanner DAST
├── templates/
│   ├── index.html      # Página inicial para inserir URL alvo
│   └── report.html     # Página para exibir relatório de vulnerabilidades
├── static/
│   └── style.css       # Estilização da interface
├── requirements.txt    # Dependências do projeto
└── README.md           # Documentação do projeto
```

## Pré-requisitos

- Python 3.8+
- Dependências listadas em `requirements.txt`

## Instalação

1. Clone o repositório:
   ```bash
    git clone https://github.com/mvdiogo/security.git
    cd ./security/livro/cap10/dast
   ```

2. Crie e ative um ambiente virtual (opcional, mas recomendado):
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```

3. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

## Como Usar

1. Execute a aplicação:
   ```bash
   python app.py
   ```

2. Acesse a interface gráfica:
   - Abra um navegador e vá para `http://127.0.0.1:5000`.
   - Insira a URL alvo (ex.: `http://example.com`) e clique em "Iniciar Scan".
   - O relatório será gerado e exibido na página `/report`.

3. Visualize o relatório:
   - O relatório inclui um sumário com o número de vulnerabilidades por severidade e detalhes de cada vulnerabilidade encontrada, incluindo recomendações de mitigação.

## Exemplo de Relatório

O relatório gerado é salvo em `report.json` e exibido na interface gráfica com:
- Informações do alvo e data do scan.
- Sumário com contagem de vulnerabilidades (alta, média, baixa).
- Detalhes de cada vulnerabilidade, incluindo URL, parâmetro, payload, descrição e mitigação.

## Melhorias Futuras

- Adicionar suporte para autenticação em aplicações web.
- Integrar com OWASP ZAP para scans mais avançados.
- Implementar testes para métodos POST e outras vulnerabilidades (ex.: CSRF, SSRF).
- Adicionar exportação de relatórios em PDF.

## Licença

Este projeto é licenciado sob a [MIT License](LICENSE).