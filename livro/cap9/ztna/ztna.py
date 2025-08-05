# Instale as dependências necessárias:
# pip install pyjwt cryptography

import jwt
import hashlib
import time
from datetime import datetime, timedelta, time as dt_time, timezone # <-- MUDANÇA AQUI
from cryptography.fernet import Fernet
from typing import Dict, Any, Optional, List

# Simulação de um banco de dados de usuários com senhas hasheadas e roles
# Em um ambiente real, isso viria de um banco de dados seguro ou serviço de diretório.
USER_DATABASE = {
    'alice': {
        'hashed_password': hashlib.sha256('password123'.encode()).hexdigest(),
        'roles': ['dba', 'admin'],
    },
    'bob': {
        'hashed_password': hashlib.sha256('bob_pass'.encode()).hexdigest(),
        'roles': ['developer'],
    },
    'service_account': {
        'hashed_password': hashlib.sha256('service_secret'.encode()).hexdigest(),
        'roles': ['app_service'],
    }
}

class ZeroTrustAccessController:
    """
    Controlador de Acesso baseado no modelo Zero Trust.
    Gerencia autenticação, autorização e monitoramento de sessão com base
    na confiança do dispositivo e políticas de acesso dinâmicas.
    """
    def __init__(self, secret_key: str):
        self.secret_key: str = secret_key
        # Em produção, sessões e scores seriam persistidos em um banco de dados (ex: Redis, DynamoDB)
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.device_trust_scores: Dict[str, Dict[str, Any]] = {}
        self.access_policies: Dict[str, Dict[str, Any]] = {
            'database_servers': {
                'required_trust_score': 90,
                'allowed_roles': ['dba', 'app_service'],
                'time_restrictions': {'start': dt_time(8, 0), 'end': dt_time(18, 0)},
                'mfa_required': True,
                'max_session_duration': 3600  # 1 hora
            },
            'application_servers': {
                'required_trust_score': 80,
                'allowed_roles': ['developer', 'app_service', 'admin'],
                'time_restrictions': None,
                'mfa_required': True,
                'max_session_duration': 7200  # 2 horas
            },
            'web_servers': {
                'required_trust_score': 70,
                'allowed_roles': ['web_admin', 'developer', 'admin'],
                'time_restrictions': None,
                'mfa_required': False,
                'max_session_duration': 14400  # 4 horas
            }
        }

    def _verify_credentials(self, username: str, password: str) -> bool:
        """Verifica as credenciais do usuário comparando o hash da senha."""
        user = USER_DATABASE.get(username)
        if not user:
            return False
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return password_hash == user['hashed_password']

    def _verify_mfa_token(self, username: str, mfa_token: str) -> bool:
        """Simula a verificação de um token MFA. Em um sistema real, usaria um serviço como Google Authenticator."""
        # Lógica de verificação do token MFA (ex: TOTP) iria aqui.
        print(f"Verificando token MFA para o usuário '{username}'...")
        return mfa_token == "123456" # Token de exemplo

    def _get_user_roles(self, username: str) -> List[str]:
        """Busca as roles (funções) de um usuário."""
        return USER_DATABASE.get(username, {}).get('roles', [])

    def generate_access_token(self, username: str, device_id: str, device_trust_score: int) -> str:
        """Gera um token de acesso JWT com informações essenciais."""
        payload = {
            'username': username,
            'device_id': device_id,
            'device_trust_score': device_trust_score,
            'roles': self._get_user_roles(username),
            # CORREÇÃO: Usar datetime com fuso horário UTC para evitar erros de expiração
            'iat': datetime.now(timezone.utc),
            'exp': datetime.now(timezone.utc) + timedelta(hours=1)
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')

    def authenticate_user(self, username: str, password: str, device_id: str, mfa_token: Optional[str] = None) -> Dict[str, Any]:
        """Autentica um usuário e seu dispositivo, retornando um token de acesso se bem-sucedido."""
        if not self._verify_credentials(username, password):
            return {'success': False, 'reason': 'Credenciais inválidas'}

        if mfa_token and not self._verify_mfa_token(username, mfa_token):
            return {'success': False, 'reason': 'Token MFA inválido'}

        device_trust_score = self.calculate_device_trust_score(device_id)
        access_token = self.generate_access_token(username, device_id, device_trust_score)

        return {
            'success': True,
            'access_token': access_token,
            'device_trust_score': device_trust_score
        }

    def authorize_access(self, access_token: str, resource: str) -> Dict[str, Any]:
        """Autoriza o acesso a um recurso específico com base no token e nas políticas."""
        try:
            # A biblioteca PyJWT já valida a expiração ('exp') e a assinatura do token
            payload = jwt.decode(access_token, self.secret_key, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return {'authorized': False, 'reason': 'Token expirado'}
        except jwt.InvalidTokenError:
            return {'authorized': False, 'reason': 'Token inválido'}

        username: str = payload['username']
        user_roles: List[str] = payload['roles']
        device_trust_score: int = payload['device_trust_score']
        
        policy = self.access_policies.get(resource)
        if not policy:
            return {'authorized': False, 'reason': f"Recurso '{resource}' não encontrado"}

        if device_trust_score < policy['required_trust_score']:
            return {'authorized': False, 'reason': f"Score de confiança insuficiente ({device_trust_score}/{policy['required_trust_score']})"}

        if not any(role in user_roles for role in policy['allowed_roles']):
            return {'authorized': False, 'reason': 'Privilégios insuficientes'}

        if restrictions := policy['time_restrictions']:
            current_time = datetime.now().time()
            if not (restrictions['start'] <= current_time <= restrictions['end']):
                return {'authorized': False, 'reason': 'Acesso fora do horário permitido'}
        
        session_id = self.create_access_session(username, payload['device_id'], resource, policy['max_session_duration'])
        return {
            'authorized': True,
            'session_id': session_id,
            'max_duration_seconds': policy['max_session_duration']
        }

    def calculate_device_trust_score(self, device_id: str) -> int:
        """Calcula o score de confiança de um dispositivo com base em seu histórico."""
        base_score = 50
        device_history = self.device_trust_scores.get(device_id, {})

        if device_history.get('clean_days', 0) > 30: base_score += 20
        if device_history.get('corporate_managed', False): base_score += 15
        if device_history.get('av_updated', False): base_score += 10
        if device_history.get('patches_current', False): base_score += 10
        if device_history.get('recent_malware', False): base_score -= 30
        if device_history.get('suspicious_activity', False): base_score -= 20
        
        return min(100, max(0, base_score))

    def create_access_session(self, username: str, device_id: str, resource: str, duration: int) -> str:
        """Cria e armazena uma sessão de acesso ativa."""
        session_id = Fernet.generate_key().decode()
        self.active_sessions[session_id] = {
            'username': username,
            'device_id': device_id,
            'resource': resource,
            'start_time': time.time(),
            'expires_at': time.time() + duration,
            'unauthorized_attempts': 0,
            'data_volume_mb': 0
        }
        print(f"Sessão '{session_id[:8]}...' criada para '{username}' no recurso '{resource}'.")
        return session_id
        
    def monitor_session_behavior(self, session_id: str) -> Dict[str, Any]:
        """Monitora o comportamento de uma sessão para detectar anomalias."""
        session = self.active_sessions.get(session_id)
        if not session:
            return {'status': 'session_not_found'}

        if time.time() > session['expires_at']:
            self.terminate_session(session_id)
            return {'status': 'session_expired_and_terminated'}
            
        anomaly_indicators = []
        if session.get('unauthorized_attempts', 0) > 3:
            anomaly_indicators.append('multiple_unauthorized_attempts')
        if session.get('data_volume_mb', 0) > 1000:
            anomaly_indicators.append('high_data_volume')
        
        if anomaly_indicators:
            self.handle_session_anomalies(session_id, anomaly_indicators)
            risk_level = 'high' if len(anomaly_indicators) > 1 else 'medium'
        else:
            risk_level = 'low'
            
        return {'status': 'monitored', 'anomalies': anomaly_indicators, 'risk_level': risk_level}

    def terminate_session(self, session_id: str) -> None:
        """Encerra uma sessão de acesso."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            print(f"Sessão '{session_id[:8]}...' encerrada.")

    def handle_session_anomalies(self, session_id: str, anomalies: List[str]) -> None:
        """Trata anomalias detectadas, aplicando ações corretivas."""
        print(f"ALERTA: Anomalias {anomalies} detectadas na sessão '{session_id[:8]}...'!")
        if 'multiple_unauthorized_attempts' in anomalies:
            self.terminate_session(session_id)

# --- Exemplo de Uso ---
if __name__ == "__main__":
    ZTAC = ZeroTrustAccessController(secret_key="uma-chave-secreta-muito-segura-e-longa")
    
    session_id = None # Inicializa a variável para garantir que ela exista

    ZTAC.device_trust_scores['device-123-confiavel'] = {'clean_days': 45, 'corporate_managed': True, 'av_updated': True, 'patches_current': True, 'recent_malware': False, 'suspicious_activity': False}
    ZTAC.device_trust_scores['device-456-risco'] = {'clean_days': 5, 'corporate_managed': False, 'av_updated': True, 'patches_current': False, 'recent_malware': True, 'suspicious_activity': False}
    
    print("--- Cenário 1: DBA acessando banco de dados com dispositivo confiável ---")
    auth_result = ZTAC.authenticate_user('alice', 'password123', 'device-123-confiavel', mfa_token="123456")
    if auth_result['success']:
        print(f"Autenticação bem-sucedida. Score de confiança: {auth_result['device_trust_score']}")
        access_token = auth_result['access_token']
        # Assumindo que o acesso ocorre em um horário válido (ex: 15h)
        authz_result = ZTAC.authorize_access(access_token, 'database_servers')
        print(f"Resultado da autorização: {authz_result}\n")
        session_id = authz_result.get('session_id')
    else:
        print(f"Falha na autenticação: {auth_result['reason']}\n")

    print("--- Cenário 2: Desenvolvedor acessando banco de dados (não permitido) ---")
    auth_result_dev = ZTAC.authenticate_user('bob', 'bob_pass', 'device-123-confiavel', mfa_token="123456")
    if auth_result_dev['success']:
        print(f"Autenticação bem-sucedida. Score de confiança: {auth_result_dev['device_trust_score']}")
        access_token_dev = auth_result_dev['access_token']
        authz_result_dev = ZTAC.authorize_access(access_token_dev, 'database_servers')
        print(f"Resultado da autorização: {authz_result_dev}\n")
    else:
        print(f"Falha na autenticação: {auth_result_dev['reason']}\n")

    print("--- Cenário 3: DBA acessando com dispositivo de risco (score baixo) ---")
    auth_result_risk = ZTAC.authenticate_user('alice', 'password123', 'device-456-risco', mfa_token="123456")
    if auth_result_risk['success']:
        print(f"Autenticação bem-sucedida. Score de confiança: {auth_result_risk['device_trust_score']}")
        access_token_risk = auth_result_risk['access_token']
        authz_result_risk = ZTAC.authorize_access(access_token_risk, 'database_servers')
        print(f"Resultado da autorização: {authz_result_risk}\n")
    else:
        print(f"Falha na autenticação: {auth_result_risk['reason']}\n")
        
    print("--- Cenário 4: Monitoramento de Anomalia na Sessão ---")
    if session_id:
        print(f"Monitorando sessão: {session_id[:8]}...")
        # Simular atividade anômala na sessão
        ZTAC.active_sessions[session_id]['unauthorized_attempts'] = 5
        
        monitoring_result = ZTAC.monitor_session_behavior(session_id)
        print(f"Resultado do monitoramento: {monitoring_result}\n")
        
        print(f"Verificando status da sessão após anomalia...")
        print(f"Sessão ainda ativa? {'Sim' if session_id in ZTAC.active_sessions else 'Não'}")
    else:
        print("Nenhuma sessão foi criada, o cenário 4 não pode ser executado.")