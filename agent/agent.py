"""Agent Windows : connexion série locale, aucune écoute réseau entrante."""
import argparse
import json
import os
import time
import urllib.error
import urllib.request
import serial
from protocol import MAX_LINE, parse_message

URL = 'http://127.0.0.1:8000'

def post(path, payload, token):
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(URL + path, data=body, headers={'Content-Type':'application/json', 'Authorization':'Bearer ' + token}, method='POST')
    with urllib.request.urlopen(req, timeout=8) as response:
        return json.load(response)

def run(port, token):
    while True:
        try:
            with serial.Serial(port, 115200, timeout=20, write_timeout=5) as device:
                time.sleep(2)
                device.reset_input_buffer()
                device.write(b'{"cmd":"hello"}\n')
                parse_message(device.readline(MAX_LINE + 1), 'hello')
                print('ESP32 connecté sur', port, flush=True)
                while True:
                    job = post('/agent/next', {}, token)
                    if job.get('kind'):
                        kind, job_id = job['kind'], job['id']
                        try:
                            device.reset_input_buffer()
                            device.write((json.dumps({'cmd':kind}) + '\n').encode('utf-8'))
                            result = parse_message(device.readline(MAX_LINE + 1), 'scan')
                            if result['kind'] != kind:
                                raise ValueError('Type de scan incorrect')
                            post('/agent/result', {'id':job_id, 'items':result['items']}, token)
                        except (ValueError, serial.SerialException) as exc:
                            post('/agent/result', {'id':job_id, 'error':'Réponse série invalide ou carte déconnectée.'}, token)
                            raise exc
                    time.sleep(2)
        except (serial.SerialException, OSError, ValueError, urllib.error.URLError) as exc:
            print('Agent indisponible :', type(exc).__name__, '— nouvel essai dans 5 secondes', flush=True)
            time.sleep(5)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', required=True, help='Port COM de la carte, par exemple COM3')
    args = parser.parse_args()
    token = os.getenv('CYBERLOCAL_AGENT_TOKEN', '')
    if len(token) < 32:
        parser.error('Configurer CYBERLOCAL_AGENT_TOKEN avec le secret de l’agent')
    try:
        run(args.port, token)
    except KeyboardInterrupt:
        print('\nAgent arrêté.')
