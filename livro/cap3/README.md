# PyShark Network Analyzer Avançado

Analisador de pacotes de rede interativo escrito em Python com PyShark.  
Projetado para capturar tráfego em tempo real, identificar comportamentos suspeitos (como varredura de portas), consultar geolocalização de IPs externos e exibir estatísticas em uma interface simples via terminal.

![PyShark Analyzer](https://img.shields.io/badge/status-em%20desenvolvimento-blue) ![Python](https://img.shields.io/badge/python-3.9%2B-green) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Funcionalidades

- Captura de pacotes com PyShark (interface `tshark`)
- Detecção de varreduras de IPs (ex: Nmap)
- Consulta de geolocalização e ISP de IPs via API
- Filtros por protocolo (ICMP, TCP, UDP, etc.)
- Interface interativa no terminal
- Suporte a múltiplas interfaces de rede

---

## Requisitos

- Python 3.9+
- Wireshark (com `tshark` e `dumpcap`)
- Permissões adequadas para captura
- Linux/macOS (preferencialmente)

Instale as dependências Python:

```bash
pip install pyshark colorama tabulate requests
````

---

## Como usar

1. **Clone o repositório:**

```bash
git clone https://github.com/seu-usuario/pyshark-analyzer.git
cd pyshark-analyzer
```

2. **Execute o script principal:**

```bash
python3 pyshark_analyzer_avancado.py
```

3. **Escolha a interface e comece a analisar!**

---

## Teste rápido

Antes de usar o analisador, verifique se o `tshark` está funcionando corretamente:

```bash
sudo tshark -i any -c 1
```

Se você vir um pacote capturado, está tudo certo! Se aparecer erro de permissão, veja a próxima seção.

---

## Erros comuns e soluções

### `Permission Denied` ao capturar pacotes

#### Opção 1: Conceder capacidades ao `dumpcap`:

```bash
sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap
```

#### Opção 2: Adicionar usuário ao grupo `wireshark`:

```bash
sudo usermod -a -G wireshark $USER
# faça logout/login após isso
```

---

### ❌ `TShark not found` ao rodar o script

Verifique se o `tshark` está instalado:

```bash
which tshark
```

Se não estiver:

```bash
sudo apt install wireshark
```

No Debian, certifique-se de permitir que usuários normais capturem pacotes:

```bash
sudo dpkg-reconfigure wireshark-common
```

---

### ❌ IP externo não resolve localização

O script usa APIs públicas como `ip-api.com`. Se elas falharem:

* Verifique sua conexão com a internet
* Tente novamente mais tarde
* APIs podem ter limites de taxa (rate limit)

---

## 🔒 Segurança

Este projeto requer acesso à rede em modo promíscuo. Execute em ambientes controlados e com conhecimento das implicações de segurança.

---

## 📜 Licença

Distribuído sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

## 🤝 Contribuições

Contribuições são bem-vindas! Relate problemas, envie melhorias ou abra PRs.

