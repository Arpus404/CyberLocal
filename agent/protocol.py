"""Validation for newline-delimited messages received from the ESP32."""

import json


MAX_LINE = 32768


def parse_message(line: bytes, expected: str) -> dict:
    if not line or len(line) > MAX_LINE or not line.endswith(b"\n"):
        raise ValueError("Réponse série absente ou trop longue")

    try:
        message = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("JSON série invalide") from error

    if not isinstance(message, dict) or message.get("type") != expected:
        raise ValueError("Type de réponse inattendu")

    if expected == "hello":
        if message.get("protocol") != 1 or message.get("chip") != "ESP32":
            raise ValueError("Firmware ou modèle incompatible")
        return message

    if message.get("ok") is not True:
        raise ValueError("Le scan a échoué sur la carte")

    kind = message.get("kind")
    items = message.get("items")
    if kind not in ("wifi", "ble") or not isinstance(items, list) or len(items) > 50:
        raise ValueError("Résultats invalides")

    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Entrée invalide")

        valid_fields = all(
            isinstance(key, str)
            and isinstance(value, (str, int, bool))
            and len(str(value)) <= 256
            for key, value in item.items()
        )
        if not valid_fields:
            raise ValueError("Champs invalides")

    return message
