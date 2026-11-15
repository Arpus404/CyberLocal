"""Windows serial agent for a locally connected ESP32."""

import argparse
import json
import os
import time
import urllib.error
import urllib.request

import serial

from protocol import MAX_LINE, parse_message


URL = "http://127.0.0.1:8000"
RETRY_SECONDS = 5


def post(path: str, payload: dict, token: str) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        URL + path,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=8) as response:
        return json.load(response)


def post_result(payload: dict, token: str) -> dict:
    """Keep a scan result in memory while the local API is temporarily down."""
    while True:
        try:
            return post("/agent/result", payload, token)
        except urllib.error.HTTPError as error:
            if error.code < 500:
                raise
            print(
                "Enregistrement indisponible ; nouvel essai dans 5 secondes.",
                flush=True,
            )
        except (OSError, urllib.error.URLError):
            print(
                "Serveur local indisponible ; résultat conservé en mémoire et nouvel essai dans 5 secondes.",
                flush=True,
            )

        time.sleep(RETRY_SECONDS)


def run(port: str, token: str) -> None:
    while True:
        try:
            with serial.Serial(
                port,
                115200,
                timeout=20,
                write_timeout=5,
            ) as device:
                time.sleep(2)
                device.reset_input_buffer()
                device.write(b'{"cmd":"hello"}\n')
                parse_message(device.readline(MAX_LINE + 1), "hello")
                print(f"ESP32 connecté sur {port}", flush=True)

                while True:
                    job = post("/agent/next", {}, token)
                    if job.get("kind"):
                        kind = job["kind"]
                        job_id = job["id"]

                        try:
                            device.reset_input_buffer()
                            command = json.dumps({"cmd": kind}) + "\n"
                            device.write(command.encode("utf-8"))
                            result = parse_message(
                                device.readline(MAX_LINE + 1),
                                "scan",
                            )
                            if result["kind"] != kind:
                                raise ValueError("Type de scan incorrect")
                        except (ValueError, serial.SerialException):
                            post_result(
                                {
                                    "id": job_id,
                                    "error": "Réponse série invalide ou carte déconnectée.",
                                },
                                token,
                            )
                            raise

                        post_result(
                            {
                                "id": job_id,
                                "items": result["items"],
                            },
                            token,
                        )

                    time.sleep(2)
        except (
            serial.SerialException,
            OSError,
            ValueError,
            urllib.error.URLError,
        ) as error:
            print(
                f"Agent indisponible ({type(error).__name__}) ; "
                f"nouvel essai dans {RETRY_SECONDS} secondes.",
                flush=True,
            )
            time.sleep(RETRY_SECONDS)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port",
        required=True,
        help="Port COM de la carte, par exemple COM3",
    )
    args = parser.parse_args()
    token = os.getenv("CYBERLOCAL_AGENT_TOKEN", "")

    if len(token) < 32:
        parser.error("Configurer CYBERLOCAL_AGENT_TOKEN avec le secret de l’agent")

    try:
        run(args.port, token)
    except KeyboardInterrupt:
        print("\nAgent arrêté.")


if __name__ == "__main__":
    main()
