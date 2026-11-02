"""Small, independently testable helpers for Cyber Local."""
import hashlib
import json
import socket
import struct
import urllib.parse
import urllib.request

MAX_FILE = 20 * 1024 * 1024
NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def clam_scan(data, host='clamav', port=3310):
    """Send bytes by INSTREAM; never execute or save the submitted file."""
    with socket.create_connection((host, port), timeout=8) as conn:
        conn.settimeout(90)
        conn.sendall(b'zINSTREAM\0')
        for offset in range(0, len(data), 65536):
            chunk = data[offset:offset + 65536]
            conn.sendall(struct.pack('!I', len(chunk)) + chunk)
        conn.sendall(struct.pack('!I', 0))
        result = bytearray()
        while len(result) < 8192:
            part = conn.recv(1024)
            if not part:
                break
            result.extend(part)
            if b'\0' in part or b'\n' in part:
                break
    reply = result.decode('utf-8', 'replace').strip('\x00\r\n')
    if reply.endswith(' FOUND'):
        return 'Menace détectée', reply.partition(': ')[2].removesuffix(' FOUND')
    if reply.endswith(' OK'):
        return 'Analyse incomplète', 'Aucune menace détectée par ClamAV ; les limites de couverture ne sont pas vérifiées.'
    return 'Échec de l’analyse', 'Réponse inattendue du moteur.'


def nvd_search(query):
    query = query.strip()
    if not query or len(query) > 150:
        raise ValueError('Saisissez une recherche de 1 à 150 caractères.')
    key = 'cveId' if query.upper().startswith('CVE-') else 'keywordSearch'
    url = NVD_URL + '?' + urllib.parse.urlencode({key: query, 'resultsPerPage': 20})
    req = urllib.request.Request(url, headers={'User-Agent': 'CyberLocal/0.2'})
    with urllib.request.urlopen(req, timeout=12) as response:
        result = json.load(response)
    rows = []
    for item in result.get('vulnerabilities', []):
        cve = item.get('cve', {})
        descs = cve.get('descriptions', [])
        desc = next((d.get('value', '') for d in descs if d.get('lang') == 'en'), '')
        metrics = cve.get('metrics', {})
        cvss = next((m.get('cvssData', {}) for k in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2') for m in metrics.get(k, [])), {})
        refs = [r.get('url', '') for r in cve.get('references', []) if r.get('url', '').startswith(('https://', 'http://'))]
        rows.append({'id': cve.get('id', ''), 'description': desc, 'published': cve.get('published', ''), 'modified': cve.get('lastModified', ''), 'score': cvss.get('baseScore'), 'severity': cvss.get('baseSeverity', ''), 'references': refs[:10]})
    return rows
