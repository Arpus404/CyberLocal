"""Validation of newline-delimited messages received from the ESP32."""
import json

MAX_LINE = 32768

def parse_message(line, expected):
    if not line or len(line) > MAX_LINE or not line.endswith(b'\n'):
        raise ValueError('Réponse série absente ou trop longue')
    try:
        data = json.loads(line.decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError('JSON série invalide') from exc
    if not isinstance(data, dict) or data.get('type') != expected:
        raise ValueError('Type de réponse inattendu')
    if expected == 'hello':
        if data.get('protocol') != 1 or data.get('chip') != 'ESP32':
            raise ValueError('Firmware ou modèle incompatible')
    else:
        if data.get('ok') is not True:
            raise ValueError('Le scan a échoué sur la carte')
        if data.get('kind') not in ('wifi', 'ble') or not isinstance(data.get('items'), list) or len(data['items']) > 50:
            raise ValueError('Résultats invalides')
        for item in data['items']:
            if not isinstance(item, dict):
                raise ValueError('Entrée invalide')
            if not all(isinstance(k, str) and isinstance(v, (str, int, bool)) and len(str(v)) <= 256 for k, v in item.items()):
                raise ValueError('Champs invalides')
    return data
