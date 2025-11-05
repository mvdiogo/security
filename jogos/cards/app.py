import os
import csv
import json
import secrets
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from functools import wraps

from flask import Flask, render_template, request, jsonify, session
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest, NotFound
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Inicialização da aplicação
app = Flask(__name__)

# Configurações de segurança
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_urlsafe(32)),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,
    JSON_SORT_KEYS=False
)

# Configurações de ambiente
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'
CSV_FILE_PATH = Path(os.environ.get('CARDS_CSV_PATH', 'cards_database.csv'))

# Validação de entrada
VALID_DIFFICULTIES = {'facil', 'normal', 'dificil'}
MAX_PLAYER_NAME_LENGTH = 50

# Configurações de dificuldade
DIFFICULTY_SETTINGS = {
    'facil': {
        'player_health': 25,
        'opponent_health': 15,
        'initial_commands': 3,
        'initial_cards': 6,
        'max_turns': 12,
        'opponent_aggression': 0.6
    },
    'normal': {
        'player_health': 20,
        'opponent_health': 20,
        'initial_commands': 3,
        'initial_cards': 5,
        'max_turns': 10,
        'opponent_aggression': 0.8
    },
    'dificil': {
        'player_health': 15,
        'opponent_health': 25,
        'initial_commands': 2,
        'initial_cards': 4,
        'max_turns': 8,
        'opponent_aggression': 1.0
    }
}

# Inicialização de extensões de segurança
csrf = CSRFProtect(app)

# Correção da inicialização do Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Configuração do Talisman com política de segurança de conteúdo
csp = {
    'default-src': ['\'self\''],
    'script-src': ['\'self\'', '\'unsafe-inline\'', 'https://cdnjs.cloudflare.com'],
    'style-src': ['\'self\'', '\'unsafe-inline\'', 'https://stackpath.bootstrapcdn.com'],
    'img-src': ['\'self\'', 'data:', 'https:'],
    'font-src': ['\'self\'', 'https://fonts.gstatic.com']
}

talisman = Talisman(app, content_security_policy=csp)

def validate_input(f):
    """Decorator para validação de entrada"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (ValueError, KeyError, TypeError) as e:
            logger.error(f"Erro de validação: {str(e)}")
            return jsonify({'error': 'Dados de entrada inválidos'}), 400
        except Exception as e:
            logger.error(f"Erro interno: {str(e)}")
            return jsonify({'error': 'Erro interno do servidor'}), 500
    return decorated_function

def sanitize_string(value: str, max_length: int = 100) -> str:
    """Sanitiza strings de entrada"""
    if not isinstance(value, str):
        raise ValueError("Valor deve ser uma string")
    
    # Remove caracteres perigosos
    sanitized = ''.join(char for char in value if char.isprintable())
    
    # Limita o tamanho
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()

def validate_card_data(card_data: Dict[str, Any]) -> bool:
    """Valida dados de carta"""
    required_fields = ['id', 'name', 'type', 'subtype', 'cost', 'effect', 'description']
    
    for field in required_fields:
        if field not in card_data:
            return False
    
    # Validações específicas
    if not isinstance(card_data.get('cost'), int) or card_data['cost'] < 0:
        return False
    
    if card_data['type'] not in ['threat', 'defense', 'hacker']:
        return False
    
    return True

def load_cards_from_csv() -> Dict[str, List[Dict[str, Any]]]:
    """Carrega as cartas do arquivo CSV com tratamento de erros robusto"""
    cards = {'threats': [], 'defenses': [], 'hackers': []}
    
    if not CSV_FILE_PATH.exists():
        logger.warning(f"Arquivo CSV não encontrado: {CSV_FILE_PATH}")
        return get_fallback_cards()
    
    try:
        with open(CSV_FILE_PATH, 'r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            
            for row_num, row in enumerate(csv_reader, 1):
                try:
                    card = parse_card_row(row)
                    if validate_card_data(card):
                        category = get_card_category(card['type'])
                        if category:
                            cards[category].append(card)
                    else:
                        logger.warning(f"Carta inválida na linha {row_num}: {row}")
                        
                except (ValueError, KeyError) as e:
                    logger.error(f"Erro ao processar linha {row_num}: {e}")
                    continue
    
    except (IOError, csv.Error) as e:
        logger.error(f"Erro ao ler arquivo CSV: {e}")
        return get_fallback_cards()
    
    except Exception as e:
        logger.error(f"Erro inesperado ao carregar cartas: {e}")
        return get_fallback_cards()
    
    # Verifica se pelo menos algumas cartas foram carregadas
    total_cards = sum(len(category) for category in cards.values())
    if total_cards == 0:
        logger.warning("Nenhuma carta válida encontrada, usando fallback")
        return get_fallback_cards()
    
    logger.info(f"Carregadas {total_cards} cartas do CSV")
    return cards

def parse_card_row(row: Dict[str, str]) -> Dict[str, Any]:
    """Processa uma linha do CSV em dados de carta"""
    card = {
        'id': sanitize_string(row.get('id', ''), 20),
        'name': sanitize_string(row.get('name', ''), 50),
        'type': sanitize_string(row.get('type', ''), 10),
        'subtype': sanitize_string(row.get('subtype', ''), 20),
        'cost': int(row.get('cost', 0)),
        'effect': sanitize_string(row.get('effect', ''), 200),
        'description': sanitize_string(row.get('description', ''), 300)
    }
    
    # Adiciona atributos opcionais com validação
    optional_int_fields = ['attack', 'defense', 'durability']
    for field in optional_int_fields:
        if row.get(field) and row[field].strip():
            try:
                card[field] = int(row[field])
            except ValueError:
                logger.warning(f"Valor inválido para {field}: {row[field]}")
    
    # Campo counter como string
    if row.get('counter') and row['counter'].strip():
        card['counter'] = sanitize_string(row['counter'], 50)
    
    return card

def get_card_category(card_type: str) -> Optional[str]:
    """Retorna a categoria da carta baseada no tipo"""
    category_mapping = {
        'threat': 'threats',
        'defense': 'defenses',
        'hacker': 'hackers'
    }
    return category_mapping.get(card_type)

def get_fallback_cards() -> Dict[str, List[Dict[str, Any]]]:
    """Retorna cartas básicas como fallback"""
    return {
        'threats': [
            {
                'id': 'ddos',
                'name': 'Ataque DDoS',
                'type': 'threat',
                'subtype': 'availability',
                'cost': 2,
                'attack': 6,
                'effect': 'Sobrecarga de tráfego',
                'description': 'Ataque de negação de serviço'
            }
        ],
        'defenses': [
            {
                'id': 'firewall',
                'name': 'Firewall Next-Gen',
                'type': 'defense',
                'subtype': 'universal',
                'cost': 1,
                'defense': 3,
                'durability': 2,
                'effect': 'Bloqueia ataques genéricos.',
                'counter': 'ddos',
                'description': 'Proteção de rede avançada'
            }
        ],
        'hackers': [
            {
                'id': 'white_hat',
                'name': 'White Hat - Pentest',
                'type': 'hacker',
                'subtype': 'white',
                'cost': 2,
                'effect': 'Ganha 1 ponto em cada pilar da Tríade CIA.',
                'description': 'Hacker ético'
            }
        ]
    }

@app.errorhandler(400)
def bad_request(error):
    logger.warning(f"Bad Request: {request.url}")
    return jsonify({'error': 'Solicitação inválida'}), 400

@app.errorhandler(404)
def not_found(error):
    logger.warning(f"Not Found: {request.url}")
    return jsonify({'error': 'Recurso não encontrado'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal Error: {error}")
    return jsonify({'error': 'Erro interno do servidor'}), 500

@app.after_request
def after_request(response):
    # Adiciona headers de segurança adicionais
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.route('/')
def index():
    """Página inicial"""
    return render_template('index.html')

@app.route('/game')
@validate_input
@limiter.limit("10 per minute")  # Rate limiting
def game():
    """Página do jogo com validação de parâmetros"""
    # Validação e sanitização dos parâmetros
    player_name = request.args.get('name', 'Jogador')
    difficulty = request.args.get('difficulty', 'normal')
    
    try:
        player_name = sanitize_string(player_name, MAX_PLAYER_NAME_LENGTH)
        if not player_name:
            player_name = 'Jogador'
    except ValueError:
        player_name = 'Jogador'
    
    if difficulty not in VALID_DIFFICULTIES:
        logger.warning(f"Dificuldade inválida recebida: {difficulty}")
        difficulty = 'normal'
    
    # Armazena na sessão de forma segura
    session.permanent = True
    session['player_name'] = player_name
    session['difficulty'] = difficulty
    
    logger.info(f"Jogo iniciado - Jogador: {player_name}, Dificuldade: {difficulty}")
    
    return render_template('game.html',
                         player_name=player_name,
                         difficulty=difficulty,
                         difficulty_settings=DIFFICULTY_SETTINGS[difficulty])

@app.route('/api/cards')
@validate_input
@limiter.limit("20 per minute")  # Rate limiting
def get_cards():
    """API para obter cartas"""
    try:
        cards = load_cards_from_csv()
        return jsonify(cards)
    except Exception as e:
        logger.error(f"Erro ao carregar cartas: {e}")
        return jsonify({'error': 'Erro ao carregar cartas'}), 500

@app.route('/api/difficulty/<difficulty>')
@validate_input
@limiter.limit("10 per minute")  # Rate limiting
def get_difficulty_settings(difficulty):
    """API para obter configurações de dificuldade"""
    if difficulty not in VALID_DIFFICULTIES:
        logger.warning(f"Dificuldade inválida solicitada: {difficulty}")
        raise BadRequest("Dificuldade inválida")
    
    return jsonify(DIFFICULTY_SETTINGS[difficulty])

@app.route('/health')
@limiter.exempt  # Isenta de rate limiting
def health_check():
    """Endpoint para verificação de saúde"""
    return jsonify({
        'status': 'healthy',
        'cards_loaded': len(load_cards_from_csv().get('threats', [])) > 0
    })

# Configurações específicas para produção
if IS_PRODUCTION:
    # Desabilita debug e modo de desenvolvimento
    app.config['DEBUG'] = False
    app.config['TESTING'] = False
    
    # Configurações adicionais de segurança para produção
    # Forçar HTTPS em produção
    talisman.force_https = True

if __name__ == '__main__':
    if IS_PRODUCTION:
        # Em produção, use um servidor WSGI como Gunicorn
        print("⚠️  Não execute com app.run() em produção!")
        print("   Use: gunicorn -w 4 -b 0.0.0.0:8000 app:app")
    else:
        app.run(debug=True, host='0.0.0.0', port=8088)