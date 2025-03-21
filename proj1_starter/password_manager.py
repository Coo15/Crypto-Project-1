from typing import Optional, Tuple

from util import dict_to_json_str, json_str_to_dict
from util import str_to_bytes, bytes_to_str, encode_bytes, decode_bytes

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

PBKDF2_ITERATIONS = 100000
SALT_SIZE = 16
HMAC_SIZE = 32
AES_KEY_SIZE = 32

class Keychain:
    def __init__(self, keychain_password: str, salt: bytes, kvs: dict):
        self.data = {"kvs": kvs}
        self.secrets = {}
        
        master_key = PBKDF2(keychain_password, salt, dkLen=HMAC_SIZE, count=PBKDF2_ITERATIONS)
        self.secrets["hmac_key"] = HMAC.new(master_key, b"hmac", SHA256).digest()
        self.secrets["aes_key"] = HMAC.new(master_key, b"aes", SHA256).digest()
        self.secrets["salt"] = salt

    @staticmethod
    def new(keychain_password: str) -> "Keychain":
        salt = get_random_bytes(SALT_SIZE)
        return Keychain(keychain_password, salt, {})

    @staticmethod
    def load(keychain_password: str, repr: str, trusted_data_check: Optional[bytes] = None) -> "Keychain":
        data = json_str_to_dict(repr)
        kvs = data.get("kvs", {})
        salt = decode_bytes(data.get("salt"))

        master_key = PBKDF2(keychain_password, salt, dkLen=HMAC_SIZE, count=PBKDF2_ITERATIONS)

        aes_key = HMAC.new(master_key, b"aes", SHA256).digest()

        if kvs:
            try:
                first_key = next(iter(kvs.keys()))
                nonce, ciphertext, tag = kvs[first_key]

                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=decode_bytes(nonce))
                cipher.decrypt_and_verify(decode_bytes(ciphertext), decode_bytes(tag))
            except (ValueError, KeyError):
                raise ValueError("Invalid keychain password")
        
        keychain = Keychain(keychain_password, salt, kvs)
        
        if trusted_data_check:
            expected_hash = SHA256.new(repr.encode()).digest()
            if expected_hash != trusted_data_check:
                raise ValueError("Checksum failed! Possible rollback attack.")
        
        return keychain

    def dump(self) -> Tuple[str, bytes]:
        serialized_data = dict_to_json_str({"kvs": self.data["kvs"], "salt": encode_bytes(self.secrets["salt"])})
        checksum = SHA256.new(serialized_data.encode()).digest()
        return serialized_data, checksum

    def get(self, domain: str) -> Optional[str]:
        hashed_domain = HMAC.new(self.secrets["hmac_key"], str_to_bytes(domain), SHA256).digest()
        key = encode_bytes(hashed_domain)
        if key in self.data["kvs"]:
            nonce, ciphertext, tag = self.data["kvs"][key]
            cipher = AES.new(self.secrets["aes_key"], AES.MODE_GCM, nonce=decode_bytes(nonce))
            return bytes_to_str(cipher.decrypt_and_verify(decode_bytes(ciphertext), decode_bytes(tag)))
        return None

    def set(self, domain: str, password: str):
        hashed_domain = HMAC.new(self.secrets["hmac_key"], str_to_bytes(domain), SHA256).digest()
        key = encode_bytes(hashed_domain)
        
        cipher = AES.new(self.secrets["aes_key"], AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(str_to_bytes(password))
        
        self.data["kvs"][key] = (
            encode_bytes(cipher.nonce),
            encode_bytes(ciphertext),
            encode_bytes(tag)
        )

    def remove(self, domain: str) -> bool:
        hashed_domain = HMAC.new(self.secrets["hmac_key"], str_to_bytes(domain), SHA256).digest()
        key = encode_bytes(hashed_domain)
        return self.data["kvs"].pop(key, None) is not None
