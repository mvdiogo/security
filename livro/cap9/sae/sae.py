import hashlib
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SAEImplementation:
    def __init__(self, password: str, mac_address: str):
        if not isinstance(password, str) or not isinstance(mac_address, str):
            raise TypeError("Password and MAC address must be strings.")
        self.password = password
        self.mac_address = mac_address.lower()
        self.private_key = None
        self.public_key = None
        self.shared_secret = None

    def __repr__(self):
        return f"<SAE(password='{self.password}', mac='{self.mac_address}')>"

    def generate_password_element(self) -> bytes:
        """Gera o elemento de senha usando hash SHA-256 (hash-to-curve simplificado)."""
        seed = f"{self.password}{self.mac_address}".encode("utf-8")
        return hashlib.sha256(seed).digest()

    def generate_commit_element(self) -> dict:
        """Gera o elemento de commit (scalar + element)."""
        self.private_key = secrets.randbits(256)
        password_element = self.generate_password_element()

        commit_scalar = (self.private_key + int.from_bytes(password_element, "big")) % (2**256)
        commit_element = hashlib.sha256(commit_scalar.to_bytes(32, "big")).digest()

        return {
            "scalar": commit_scalar,
            "element": commit_element
        }

    def process_peer_commit(self, peer_commit: dict) -> bytes:
        """Processa o commit do peer e calcula o segredo compartilhado."""
        if not self.verify_commit(peer_commit):
            raise ValueError("Commit inválido recebido do peer.")

        password_element = self.generate_password_element()
        peer_scalar = peer_commit["scalar"]

        if self.private_key is None:
            raise ValueError("Private key não foi gerada ainda.")

        # Operação matemática simplificada (substitui operação de curva elíptica)
        shared_point = (peer_scalar * self.private_key) % (2**256)

        self.shared_secret = hashlib.sha256(
            shared_point.to_bytes(32, "big") + password_element
        ).digest()

        return self.shared_secret

    def verify_commit(self, commit: dict) -> bool:
        """Verifica se o commit do peer é válido."""
        if not isinstance(commit, dict):
            return False

        scalar = commit.get("scalar")
        element = commit.get("element")

        if not isinstance(scalar, int) or not isinstance(element, bytes):
            return False
        if scalar <= 0 or scalar >= 2**256:
            return False
        if len(element) != 32:
            return False

        return True

    def derive_keys(self) -> dict:
        """Deriva as chaves PMK, PTK, KEK e TK a partir do segredo compartilhado."""
        if self.shared_secret is None:
            raise ValueError("Shared secret ainda não foi estabelecido.")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"WPA3-SAE-PMK",
            info=b"",
        )
        pmk = hkdf.derive(self.shared_secret)

        # Derivação de PTK (poderia ser mais elaborada com nonces e endereço do peer)
        ptk_input = pmk + self.mac_address.encode() + b"peer_mac"
        ptk = hashlib.sha256(ptk_input).digest()

        return {
            "pmk": pmk,
            "ptk": ptk,
            "kek": ptk[:16],  # Key Encryption Key
            "tk": ptk[16:32]  # Temporal Key
        }
