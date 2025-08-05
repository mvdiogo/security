# Controlador de Acesso Zero Trust em Python

Este repositório contém uma implementação de Prova de Conceito (PoC) de um Controlador de Acesso baseado no modelo de segurança **Zero Trust**, utilizando Python.

O objetivo deste projeto é demonstrar, de forma prática e didática, os princípios fundamentais do Zero Trust, onde nenhuma entidade é confiável por padrão. Cada solicitação de acesso é rigorosamente autenticada e autorizada com base em um conjunto dinâmico de políticas.

> **Aviso:** Este código é para fins educacionais e de demonstração. **Não deve ser utilizado em um ambiente de produção** sem modificações significativas e uma auditoria de segurança completa.

## Princípios de Zero Trust Demonstrados

O script implementa as seguintes ideias centrais do modelo Zero Trust:

1.  **Nunca Confie, Sempre Verifique:** Toda solicitação de acesso a um recurso é tratada como se viesse de uma rede não confiável e deve ser validada.
2.  **Autenticação Forte:** A identidade do usuário é verificada através de credenciais e, opcionalmente, de Autenticação Multifator (MFA).
3.  **Autorização Dinâmica e Contextual:** A decisão de conceder acesso não se baseia apenas na identidade, mas em múltiplos fatores de contexto:
      - **Score de Confiança do Dispositivo:** Avalia a "saúde" e a segurança do dispositivo que solicita o acesso.
      - **Função do Usuário (Role):** Garante o princípio do menor privilégio, concedendo acesso apenas aos recursos necessários para a função do usuário.
      - **Políticas de Acesso:** Regras específicas por recurso, como restrições de horário.
4.  **Monitoramento Contínuo:** As sessões ativas são (simuladamente) monitoradas em busca de comportamento anômalo, com capacidade de resposta automática, como o encerramento da sessão.

## Começando

Siga estas instruções para configurar e executar o projeto em seu ambiente local.

### Pré-requisitos

  - Python 3.9 ou superior
  - `pip` (gerenciador de pacotes do Python)

### Instalação

1.  **Clone o repositório:**

    ```bash
    git clone https://github.com/mvdiogo/security.git
    cd security/cap9/ztna
    ```

2.  **Crie e ative um ambiente virtual (recomendado):**

    ```bash
    # Para Unix/macOS
    python3 -m venv venv
    source venv/bin/activate

    # Para Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Instale as dependências:**
    O projeto requer as bibliotecas `PyJWT` e `cryptography`.

    ```bash
    pip install -r requirements.txt
    ```

## 🔧 Como Usar

O script foi projetado para ser executado diretamente e demonstrar vários cenários de acesso. Basta executar o arquivo Python no seu terminal:

```bash
python ztna.py
```

### Saída Esperada

Você verá a simulação de quatro cenários diferentes, mostrando o sistema em ação:

```text
--- Cenário 1: DBA acessando banco de dados com dispositivo confiável ---
Verificando token MFA para o usuário 'alice'...
Autenticação bem-sucedida. Score de confiança: 100
Sessão 'Gk_L... ' criada para 'alice' no recurso 'database_servers'.
Resultado da autorização: {'authorized': True, 'session_id': 'Gk_L...', 'max_duration_seconds': 3600}

--- Cenário 2: Desenvolvedor acessando banco de dados (não permitido) ---
Verificando token MFA para o usuário 'bob'...
Autenticação bem-sucedida. Score de confiança: 100
Resultado da autorização: {'authorized': False, 'reason': 'Privilégios insuficientes'}

--- Cenário 3: DBA acessando com dispositivo de risco (score baixo) ---
Verificando token MFA para o usuário 'alice'...
Autenticação bem-sucedida. Score de confiança: 30
Resultado da autorização: {'authorized': False, 'reason': 'Score de confiança insuficiente (30/90)'}

--- Cenário 4: Monitoramento de Anomalia na Sessão ---
Monitorando sessão: Gk_L...
ALERTA: Anomalias ['multiple_unauthorized_attempts'] detectadas na sessão 'Gk_L...'!
Sessão 'Gk_L...' encerrada.
Resultado do monitoramento: {'status': 'monitored', 'anomalies': ['multiple_unauthorized_attempts'], 'risk_level': 'medium'}

Verificando status da sessão após anomalia...
Sessão ainda ativa? Não
```

## 📂 Estrutura do Código

O código está encapsulado na classe `ZeroTrustAccessController`. Seus principais métodos são:

  - `__init__(self, secret_key)`: Inicializa o controlador com as políticas de acesso e uma chave secreta para os tokens JWT.
  - `authenticate_user(...)`: Valida as credenciais do usuário e do dispositivo e, se bem-sucedido, gera um token de acesso.
  - `authorize_access(...)`: O coração do sistema. Decodifica o token e o valida contra as políticas de acesso do recurso solicitado.
  - `calculate_device_trust_score(...)`: Simula o cálculo do score de confiança de um dispositivo com base em um histórico pré-definido.
  - `create_access_session(...)`: Cria uma sessão de acesso após uma autorização bem-sucedida.
  - `monitor_session_behavior(...)`: Simula o monitoramento de uma sessão em busca de atividades suspeitas.
  - `handle_session_anomalies(...)`: Define as ações a serem tomadas quando uma anomalia é detectada.


## Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo `LICENSE` para mais detalhes.