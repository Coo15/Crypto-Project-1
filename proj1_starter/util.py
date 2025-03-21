import base64
import json


def dict_to_json_str(d: dict) -> str:
    return json.dumps(d)

def json_str_to_dict(json_str: str) -> dict:
    return json.loads(json_str)

def str_to_bytes(s: str) -> bytes:
    return s.encode('utf-8')

def bytes_to_str(b: bytes) -> str:
    return b.decode('utf-8')

def encode_bytes(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def decode_bytes(hex_str: str) -> bytes:
    return base64.b64decode(hex_str)
