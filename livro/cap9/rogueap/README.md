# Rogue Access Point Detector com Interface Web (Flask)

Este projeto é um sistema de detecção de **Rogue Access Points (APs)** com uma interface web baseada em Flask. Ele utiliza a ferramenta `iwlist` para escanear redes Wi-Fi e armazena os resultados em um banco de dados SQLite. O sistema identifica possíveis APs maliciosos ou não autorizados.

## Funcionalidades

- Detecção de Access Points próximos usando `iwlist`
- Registro dos APs encontrados em banco de dados (`SQLite`)
- Identificação de APs suspeitos (rogue)
- Interface web para visualizar APs e detecções
- Suporte a varreduras manuais

## Requisitos

- Python 3.7+
- Linux com suporte a `iwlist`
- Interface Wi-Fi em modo monitor (ex: `wlan0mon`)

## Instalação

1. Clone o repositório:

```bash
git clone https://github.com/mvdiogo/security.git
cd security/livro/cap9/rogueap
````

2. Crie o ambiente virtual:

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Instale as dependências:

```bash
pip install -r requirements.txt
```

## Executando o sistema

Execute o servidor Flask:

```bash
sudo ./venv/bin/python3 app.py
```

Acesse a aplicação via navegador:

```
http://localhost:5000
```

## Estrutura do Projeto

```
.
├── app.py                 # Servidor Flask
├── rogue_ap_core.py       # Lógica principal de detecção
├── rogue_detection.db     # Banco de dados SQLite
├── requirements.txt       # Dependências
├── templates/             # HTML (Jinja2)
│   ├── index.html
│   └── rogue.html
├── static/
│   └── style.css
└── README.md
```

## Observações

* Certifique-se de ter permissões para usar o modo monitor e o comando `iwlist`.
* Para colocar a interface em modo monitor:

  ```bash
  sudo airmon-ng start wlan0
  ```

## Licença

Este projeto está licenciado sob a [MIT License](LICENSE).
