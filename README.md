# Vulnerable Lab - Cybersecurity Training Environment

Um laboratório completo e automatizado para criação e detecção de **vulnerabilidades reais** em ambientes Linux/Docker!
Ideal para estudantes, profissionais de segurança da informação, CTFs e testes de pentest.

---

##  Descrição

O projeto **Vulnerable Lab** instala, configura e detecta **+20 vulnerabilidades conhecidas** em serviços como:
- SSH
- FTP
- Samba
- Apache
- MySQL
- PostgreSQL
- Redis
- Telnet
- NFS
- SNMP
- PHP

Tudo de forma automatizada, com suporte para **execução nativa** no Debian 12 ou em **containers Docker**.

Ao final da detecção, é gerado um **relatório em HTML** com o status de segurança de cada serviço.

---

## Funcionalidades

- Instalação automática de serviços vulneráveis
- Configuração insegura simulando ambientes comprometidos
- Scanner de vulnerabilidades customizado
- Relatório em HTML de vulnerabilidades detectadas
- Ambiente completo em Docker (com docker-compose)
- Foco em aprendizado e treinamento de hardening e auditorias

---

## Pré-requisitos

- Docker + Docker Compose (opcional, mas recomendado)
- Debian 12 ou superior (se preferir instalação direta)
- Acesso sudo/root
- Git instalado

---

## Como usar

### Clone o repositório
```bash
git clone https://github.com/mvdiogo/security.git
cd security
```

---

### Instalação e execução no sistema (Debian 12)

1. Dê permissão de execução:
```bash
chmod +x install_insecure_services.sh detect_vulnerabilities.sh generate_report.sh
```

2. Instale e configure vulnerabilidades:
```bash
sudo ./install_insecure_services.sh
```

3. Detecte vulnerabilidades:
```bash
sudo ./detect_vulnerabilities.sh
```

4. Gere o relatório HTML:
```bash
sudo ./generate_report.sh
```

O relatório `vulnerability_report.html` será criado no diretório atual.

---

###  Usando Docker

1. Build e inicialize o container:
```bash
docker-compose up -d --build
```

2. Acesse o container:
```bash
docker exec -it vulnerable_server bash
```

3. Dentro do container:
```bash
/root/install_insecure_services.sh
/root/detect_vulnerabilities.sh
/root/generate_report.sh
```

4. O relatório será gerado dentro do container em `/root/vulnerability_report.html`. Para copiar para fora do container rode o seguinte comando.
```bash
docker cp vulnerable_server:/root/vulnerability_report.html .
xdg-open vulnerability_report.html
```

---

## Estrutura dos Scripts

| Script | Descrição |
|:---|:---|
| `install_insecure_services.sh` | Instala e configura serviços com vulnerabilidades |
| `detect_vulnerabilities.sh` | Escaneia as configurações e detecta falhas |
| `generate_report.sh` | Gera relatório HTML detalhado |
| `Dockerfile` | Dockerfile para construir imagem vulnerável |
| `docker-compose.yml` | Orquestra o ambiente vulnerável |

---

##  Serviços e Vulnerabilidades Simuladas

- SSH: Root login, brute-force permitido
- FTP: FTP anônimo, FTP sem TLS
- Samba: Guest shares, permissões 777
- Apache: Directory listing, phpinfo exposto
- MySQL/PostgreSQL: Senha vazia, trust authentication
- Redis: Sem senha, bind 0.0.0.0
- Telnet: Serviço exposto
- NFS: Exports inseguros
- SNMP: Comunidade pública "public"
- PHP: Exibição de erros ativa

---

## Aviso de Segurança

Este projeto é **estritamente educacional**!
**Nunca** use esse ambiente em redes de produção ou conectadas à internet real.
Todos os testes devem ser feitos em ambiente controlado.

---

## Licença

Este projeto é licenciado sob a licença MIT.
Sinta-se livre para utilizar, modificar e distribuir para fins educacionais.

---

## Contribuindo

Pull requests são bem-vindas!
Para mudanças maiores, abra uma issue para discutir o que você gostaria de mudar.


