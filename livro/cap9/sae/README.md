# SAE Implementation (Simulação Simplificada)

Este projeto simula uma implementação didática do protocolo **SAE (Simultaneous Authentication of Equals)** utilizado no padrão WPA3. O código foca em demonstrar o processo de troca de chaves baseado em senha, com geração de commit, verificação de pares e derivação de chaves.

> Esta é uma versão simplificada e **não deve ser usada em ambientes de produção**. Seu objetivo é educacional.

---

## Funcionalidades

- Geração de **elemento de senha** (hash-to-curve simplificado)
- Troca de **commit scalar e elemento**
- Cálculo de **segredo compartilhado**
- Derivação das chaves **PMK**, **PTK**, **KEK** e **TK**
- **Simulação de ataque de commit inválido**
- Interface de menu interativo
- Exportação das chaves para arquivo `.json`

---

## Instalação

Clone o repositório e instale as dependências:

```bash
git clone https://github.com/seu-usuario/sae-simples.git
cd sae-simples
pip install -r requirements.txt
```

## Como usar

Execute o menu principal:

```bash
python main.py
```

Você verá um menu com opções como:

```bash
==== Menu SAE ====
1. Criar nova sessão SAE
2. Exibir segredo compartilhado
3. Exibir chaves derivadas
4. Salvar chaves em arquivo
5. Simular ataque de commit inválido
6. Sair
```