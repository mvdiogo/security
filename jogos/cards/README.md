# Cyber Security TCG: Triad Defense

Um jogo de cartas educativo sobre segurança cibernética desenvolvido em Flask, onde você deve defender sistemas contra ameaças digitais enquanto completa a Tríade CIA (Confidencialidade, Integridade e Disponibilidade).

## 🎯 Características

- **3 Níveis de Dificuldade**: Fácil, Normal e Difícil
- **Sistema de Cartas Dinâmico**: Ameaças, Defesas e Hackers
- **Interface Responsiva**: Compatível com desktop (1440x900) e mobile
- **Sistema de Recordes**: Acompanhe seu progresso por dificuldade
- **Eventos Aleatórios**: Surtos de rede, patches e vazamentos
- **Design Moderno**: Interface glassmorphism com animações suaves

## 🚀 Instalação

### Pré-requisitos
- Python 3.7 ou superior
- pip (gerenciador de pacotes Python)

### Passo a Passo

1. **Clone ou baixe os arquivos do projeto**

2. **Crie um ambiente virtual (recomendado)**:
   ```bash
   python -m venv venv
   
   # No Windows:
   venv\Scripts\activate
   
   # No Linux/Mac:
   source venv/bin/activate
   ```

3. **Instale as dependências**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Certifique-se de que a estrutura de pastas está correta**:
   ```
   projeto/
   ├── app.py
   ├── cards_database.csv
   ├── requirements.txt
   ├── templates/
   │   ├── index.html
   │   └── game.html
   └── README.md
   ```

5. **Execute a aplicação**:
   ```bash
   python app.py
   ```

6. **Abra seu navegador** e acesse: `http://localhost:5000`

## 🎮 Como Jogar

### Objetivo
- Reduza a vida do oponente a 0 **OU**
- Complete a Tríade CIA (2 pontos em cada pilar: Confidencialidade, Integridade, Disponibilidade)

### Tipos de Cartas

#### 🛡️ Defesas
- **Firewall Next-Gen**: Proteção universal contra ataques
- **Antivírus Avançado**: Especializado contra malware
- **Backup em Tempo Real**: Restaura vida e protege contra ransomware
- **Autenticação MFA**: Defende contra phishing
- **Redundância de Sistema**: Alta disponibilidade
- **Web App Firewall**: Protege contra SQL injection

#### ⚠️ Ameaças
- **Ataque DDoS**: Alto dano de disponibilidade
- **Malware Avançado**: Corrompe a integridade do sistema
- **Phishing**: Compromete credenciais
- **Ransomware**: Criptografa arquivos críticos
- **SQL Injection**: Acesso não autorizado a dados
- **Zero-Day Exploit**: Ignora defesas

#### 🎩 Hackers
- **White Hat**: Melhora todos os pilares da Tríade
- **Black Hat**: Causa dano direto ignorando defesas
- **Grey Hat**: Reduz comandos do oponente

### Mecânicas

- **Comandos**: Recurso para jogar cartas (renovado a cada turno)
- **Durabilidade**: Defesas se desgastam com o uso
- **Counters**: Algumas defesas anulam ameaças específicas
- **Eventos Aleatórios**: Podem ajudar ou atrapalhar (30% de chance por turno)

### Níveis de Dificuldade

| Aspecto | Fácil | Normal | Difícil |
|---------|--------|--------|---------|
| Vida do Jogador | 25 | 20 | 15 |
| Vida do Oponente | 15 | 20 | 25 |
| Comandos Iniciais | 3 | 3 | 2 |
| Cartas Iniciais | 6 | 5 | 4 |
| Turnos Máximos | 12 | 10 | 8 |
| Agressividade da IA | 60% | 80% | 100% |

## 🎨 Controles

- **Mouse**: Clique para selecionar cartas
- **Enter**: Jogar carta selecionada
- **Espaço**: Finalizar turno
- **Esc**: Cancelar seleção

## 📱 Responsividade

O jogo foi projetado para funcionar perfeitamente em:
- **Desktop**: 1440x900 e superiores
- **Tablet**: Layouts adaptáveis para telas médias
- **Mobile**: Interface otimizada para smartphones

## 🔧 Personalização

### Modificar Cartas
Edite o arquivo `cards_database.csv` para:
- Adicionar novas cartas
- Modificar estatísticas existentes
- Criar novos efeitos

### Ajustar Dificuldade
No arquivo `app.py`, modifique o dicionário `DIFFICULTY_SETTINGS` para personalizar:
- Vida inicial
- Recursos por turno
- Comportamento da IA

## 🛠️ Desenvolvimento

### Estrutura do Código

- **app.py**: Servidor Flask principal
- **templates/index.html**: Tela inicial com seleção de jogador
- **templates/game.html**: Interface principal do jogo
- **cards_database.csv**: Base de dados das cartas

### Tecnologias Utilizadas

- **Backend**: Flask (Python)
- **Frontend**: HTML5, CSS3, JavaScript Vanilla
- **Dados**: CSV para portabilidade
- **Design**: Glassmorphism, Gradientes, Animações CSS

## 🎓 Valor Educativo

Este jogo ensina conceitos importantes de segurança cibernética:

- **Tríade CIA**: Pilares fundamentais da segurança da informação
- **Tipos de Ameaças**: DDoS, Malware, Phishing, Ransomware, etc.
- **Mecanismos de Defesa**: Firewalls, Antivírus, MFA, Backups
- **Estratégia de Segurança**: Balanceamento entre recursos e proteção
- **Gestão de Riscos**: Decisões táticas sob pressão

## 📈 Expansões Futuras

- Sistema de decks personalizáveis
- Modo multiplayer online
- Campanhas com narrativa
- Cartas de eventos especiais
- Sistema de conquistas
- Integração com banco de dados

## 🤝 Contribuição

Contribuições são bem-vindas! Áreas de interesse:
- Novas cartas e mecânicas
- Melhorias na IA do oponente
- Otimizações de performance
- Tradução para outros idiomas
- Testes e correções de bugs

## 📞 Suporte

Se encontrar problemas:
1. Verifique se todas as dependências estão instaladas
2. Confirme a estrutura de pastas
3. Teste em diferentes navegadores
4. Verifique o console do navegador para erros JavaScript

---

**Divirta-se defendendo o ciberespaço! 🛡️🎮**
