from contextlib import asynccontextmanager
from datetime import datetime, timezone
from html import escape
import json
import logging
import os
import secrets
import socket
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from core import MAX_FILE, clam_scan, nvd_search, remediation_plan, sha256

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger('cyberlocal')
BASE = Path(__file__).resolve().parent
DB_URL = os.environ.get('DATABASE_URL', '')
TOKEN = secrets.token_urlsafe(32)
AGENT_TOKEN = os.environ.get('ESP32_AGENT_TOKEN', '')
CLAMAV_HOST = 'clamav'
CLAMAV_PORT = 3310
agent_lock = threading.Lock()
agent_state = {'last_seen': 0.0, 'job': None, 'error': ''}


def db():
    return psycopg.connect(DB_URL, connect_timeout=3)


@asynccontextmanager
async def lifespan(app):
    try:
        with db() as conn:
            conn.execute(
                '''
                CREATE TABLE IF NOT EXISTS scans (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    name TEXT NOT NULL,
                    size BIGINT NOT NULL,
                    digest TEXT NOT NULL,
                    result TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                '''
            )
            conn.execute(
                '''
                CREATE TABLE IF NOT EXISTS radio_scans (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    kind TEXT NOT NULL,
                    payload JSONB NOT NULL DEFAULT '[]'::jsonb,
                    status TEXT NOT NULL DEFAULT 'completed',
                    error TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    finished_at TIMESTAMPTZ
                )
                '''
            )
            conn.execute(
                'ALTER TABLE radio_scans '
                'ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT \'completed\''
            )
            conn.execute(
                'ALTER TABLE radio_scans '
                'ADD COLUMN IF NOT EXISTS error TEXT NOT NULL DEFAULT \'\''
            )
            conn.execute(
                'ALTER TABLE radio_scans '
                'ADD COLUMN IF NOT EXISTS finished_at TIMESTAMPTZ'
            )
            conn.execute(
                '''
                UPDATE radio_scans
                SET status = 'failed',
                    error = 'Le serveur a redémarré pendant le scan.',
                    finished_at = now()
                WHERE status = 'pending'
                '''
            )
            conn.execute(
                '''
                CREATE TABLE IF NOT EXISTS cves (
                    id TEXT PRIMARY KEY,
                    payload JSONB NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                '''
            )
    except psycopg.Error:
        LOG.warning('Base indisponible au démarrage')
    yield


app = FastAPI(title='Cyber Local', docs_url=None, redoc_url=None, lifespan=lifespan)
app.mount('/static', StaticFiles(directory=BASE / 'static'), name='static')


@app.middleware('http')
async def local_only(request, call_next):
    host = request.headers.get('host', '').split(':')[0].lower()
    if host not in ('localhost', '127.0.0.1'):
        return HTMLResponse('Hôte non autorisé', status_code=403)
    if request.method == 'POST':
        origin = request.headers.get('origin')
        origin_is_allowed = (
            not origin
            or (
                urlsplit(origin).netloc.lower()
                == request.headers.get('host', '').lower()
                and urlsplit(origin).scheme == 'http'
            )
        )
        if not origin_is_allowed:
            return HTMLResponse('Origine non autorisée', status_code=403)

        try:
            length = int(request.headers.get('content-length', '-1'))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_FILE + 65536:
            return HTMLResponse('Requête trop volumineuse ou taille inconnue.', status_code=413)

    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'"
    )
    response.headers['Cache-Control'] = 'no-store'
    return response


def e(value):
    return escape(str(value if value is not None else ''))


def page(title, content):
    navigation = [
        ('Tableau de bord', '/'),
        ('Analyse de fichier', '/analyse'),
        ('CVE', '/cve'),
        ('Wi-Fi et Bluetooth', '/esp32'),
        ('Historique', '/historique'),
        ('Paramètres', '/parametres'),
    ]
    links = ''.join(
        f'<a href="{url}">{e(label)}</a>'
        for label, url in navigation
    )

    return HTMLResponse(
        f'''<!doctype html>
<html lang="fr">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{e(title)} — Cyber Local</title>
        <link rel="stylesheet" href="/static/site.css">
    </head>
    <body>
        <header>
            <strong>◈ CYBER LOCAL</strong>
            <nav>{links}</nav>
        </header>
        <main>
            <h1>{e(title)}</h1>
            {content}
        </main>
        <footer>Projet pédagogique local · Les résultats sont des pistes à vérifier.</footer>
    </body>
</html>'''
    )


def token_input():
    return f'<input type="hidden" name="token" value="{TOKEN}">'


def verify(form):
    return secrets.compare_digest(str(form.get('token', '')), TOKEN)


def unavailable():
    return page(
        'Service indisponible',
        '<p>La base de données est indisponible. '
        'Vérifiez les services Docker puis réessayez.</p>',
    )


@app.get('/')
def home():
    return FileResponse(BASE / 'static' / 'index.html')


def clamd_online():
    try:
        with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=1) as connection:
            connection.sendall(b'zPING\0')
            return connection.recv(16).rstrip(b'\0\r\n') == b'PONG'
    except OSError:
        return False


@app.get('/api/status')
def api_status():
    database_status = 'Indisponible'
    analysis_count = None
    threat_count = None
    cve_count = None
    radio_scan_count = None

    try:
        with db() as conn:
            analysis_count, threat_count = conn.execute(
                """
                SELECT count(*), count(*) FILTER (WHERE result = 'Menace détectée')
                FROM scans
                """
            ).fetchone()
            cve_count = conn.execute('SELECT count(*) FROM cves').fetchone()[0]
            radio_scan_count = conn.execute(
                "SELECT count(*) FROM radio_scans WHERE status = 'completed'"
            ).fetchone()[0]
        database_status = 'Connectée'
    except psycopg.Error:
        pass

    with agent_lock:
        esp32_status = 'Connecté' if agent_online() else 'Déconnecté'

    return {
        'application': 'en ligne',
        'antivirus': 'Prêt' if clamd_online() else 'En attente',
        'base_de_donnees': database_status,
        'esp32': esp32_status,
        'analyses': analysis_count,
        'menaces': threat_count,
        'cves': cve_count,
        'scans_radio': radio_scan_count,
    }


@app.get('/analyse')
def analyse_page():
    return page(
        'Analyse de fichier',
        f'''
            <p>
                Le fichier est transmis au moteur ClamAV local pour analyse.
                Il n’est pas exécuté ni conservé volontairement. Limite :
                20 Mio.
            </p>
            <form action="/analyse" method="post" enctype="multipart/form-data">
                {token_input()}
                <label>
                    Choisir un fichier
                    <input required type="file" name="fichier">
                </label>
                <button>Analyser</button>
            </form>
            <p>
                Une absence de détection ne prouve jamais qu’un fichier est
                sain. Les analyses sans détection sont indiquées comme
                incomplètes tant que les limites du moteur ne sont pas vérifiées.
            </p>
        ''',
    )


@app.post('/analyse')
async def analyse(request: Request):
    form = await request.form(max_files=1, max_fields=4)
    if not verify(form):
        return HTMLResponse('Requête refusée.', status_code=403)

    upload = form.get('fichier')
    if not upload or not hasattr(upload, 'read'):
        return HTMLResponse('Fichier manquant.', status_code=400)

    data = await upload.read(MAX_FILE + 1)
    await upload.close()
    if len(data) > MAX_FILE:
        return HTMLResponse('Fichier trop volumineux.', status_code=413)

    name = str(upload.filename or 'fichier').replace('\\', '/').split('/')[-1][:255]
    digest = sha256(data)
    try:
        result, detail = await run_in_threadpool(clam_scan, data)
    except (OSError, TimeoutError):
        result, detail = 'Échec de l’analyse', 'ClamAV indisponible ou délai dépassé.'
    finally:
        del data

    try:
        with db() as conn:
            conn.execute(
                '''
                INSERT INTO scans (name, size, digest, result, detail)
                VALUES (%s, %s, %s, %s, %s)
                ''',
                (name, upload.size or 0, digest, result, detail),
            )
    except psycopg.Error:
        LOG.warning('Impossible de sauvegarder une analyse')
        saved = 'Le résultat n’a pas pu être enregistré : base indisponible.'
    else:
        saved = 'Résultat enregistré dans l’historique.'
    return page(
        'Résultat de l’analyse',
        f'''
            <article>
                <h2>{e(result)}</h2>
                <p>{e(detail)}</p>
                <p>Fichier : {e(name)} · Taille : {e(upload.size)} octets</p>
                <p>SHA-256 : <code>{e(digest)}</code></p>
                <p>{e(saved)}</p>
            </article>
            <p><a href="/analyse">Nouvelle analyse</a></p>
        ''',
    )


@app.get('/cve')
def cve_page(q: str = ''):
    if len(q) > 150:
        return HTMLResponse('Recherche trop longue.', status_code=400)

    error = ''
    try:
        with db() as conn:
            pattern = f'%{q}%'
            rows = conn.execute(
                '''
                SELECT payload
                FROM cves
                WHERE id ILIKE %s OR payload::text ILIKE %s
                ORDER BY updated_at DESC
                LIMIT 20
                ''',
                (pattern, pattern),
            ).fetchall()
        cards = ''.join(cve_card(row[0]) for row in rows)
    except psycopg.Error:
        cards, error = '', '<p>Base indisponible.</p>'
    return page(
        'Vulnérabilités CVE',
        f'''
            <p>
                Recherchez dans les CVE enregistrées ou interrogez la NVD sur
                Internet. Une CVE ne s’applique pas forcément à vos appareils :
                vérifiez toujours le produit et sa version.
            </p>
            <form action="/cve" method="get">
                <input
                    name="q"
                    maxlength="150"
                    value="{e(q)}"
                    placeholder="CVE, produit ou mot-clé"
                >
                <button>Rechercher dans la base locale</button>
            </form>
            <form action="/cve/sync" method="post">
                {token_input()}
                <input
                    name="q"
                    required
                    maxlength="150"
                    value="{e(q)}"
                    placeholder="CVE, produit ou mot-clé"
                >
                <button>Rechercher sur la NVD</button>
            </form>
            {error}
            {cards or '<p>Aucun résultat enregistré pour cette recherche.</p>'}
        ''',
    )


def cve_card(c):
    references = c.get('references') or []
    vendor_advisories = c.get('vendor_advisories') or []

    def render_links(urls):
        return ''.join(
            f'<li><a href="{e(url)}" rel="noreferrer">{e(url)}</a></li>'
            for url in urls
        )

    advisory_links = render_links(vendor_advisories)
    other_references = [
        url for url in references if url not in vendor_advisories
    ]
    other_reference_links = render_links(other_references)
    if vendor_advisories:
        reference_sections = (
            '<h3>Avis éditeur et correctifs</h3>'
            f'<ul>{advisory_links}</ul>'
            + (
                f'<h3>Autres références NVD</h3><ul>{other_reference_links}</ul>'
                if other_reference_links
                else ''
            )
        )
    else:
        reference_links = render_links(references)
        if not reference_links:
            reference_links = '<li>Aucune référence fournie par la NVD.</li>'
        reference_sections = (
            '<h3>Références officielles</h3>'
            f'<ul>{reference_links}</ul>'
        )

    recommendations = c.get('recommendations') or remediation_plan(
        c.get('severity', ''),
        vendor_advisories,
        c.get('cisa_required_action', ''),
    )
    recommendation_items = ''.join(
        f'<li>{e(recommendation)}</li>'
        for recommendation in recommendations
    )

    score = c.get('score')
    score_label = score if score is not None else 'non disponible'

    return f'''
        <article class="cve-card">
            <h2>{e(c.get('id'))}</h2>
            <p>{e(c.get('description'))}</p>
            <p>
                Publié : {e(c.get('published'))} ·
                Modifié : {e(c.get('modified'))} ·
                CVSS : {e(score_label)} {e(c.get('severity'))}
            </p>
            <h3>Pistes de correction proposées</h3>
            <p>
                Ces étapes sont indicatives : Cyber Local ne connaît pas les
                logiciels ni les versions installés sur votre ordinateur.
                Vérifiez l’avis de l’éditeur avant toute modification.
            </p>
            <ol>{recommendation_items}</ol>
            {reference_sections}
        </article>
    '''


@app.post('/cve/sync')
async def cve_sync(request: Request):
    form = await request.form()
    if not verify(form):
        return HTMLResponse('Requête refusée.', status_code=403)
    q = str(form.get('q', '')).strip()
    try:
        rows = await run_in_threadpool(nvd_search, q)
    except ValueError as exc:
        return HTMLResponse(e(exc), status_code=400)
    except Exception:
        LOG.warning('Recherche NVD indisponible')
        return page(
            'Source CVE indisponible',
            '<p>Impossible de joindre la NVD. Vous pouvez consulter les '
            '<a href="/cve">résultats enregistrés</a>.</p>',
        )

    try:
        with db() as conn:
            for row in rows:
                conn.execute(
                    '''
                    INSERT INTO cves (id, payload)
                    VALUES (%s, %s::jsonb)
                    ON CONFLICT (id) DO UPDATE
                    SET payload = EXCLUDED.payload, updated_at = now()
                    ''',
                    (row['id'], json.dumps(row)),
                )
    except psycopg.Error:
        return unavailable()

    result_cards = ''.join(cve_card(row) for row in rows)
    empty_message = '<p>Aucune CVE correspondante renvoyée par la NVD.</p>'
    return page(
        'Résultats NVD',
        f'<p>{len(rows)} résultat(s) reçu(s), maximum 20 par recherche. '
        'Les CVE obtenues sont enregistrées dans PostgreSQL.</p>'
        f'{result_cards or empty_message}'
        '<p><a href="/cve">Retour aux CVE</a></p>',
    )


@app.get('/historique')
def history():
    try:
        with db() as conn:
            rows = conn.execute(
                '''
                SELECT name, size, digest, result, detail, created_at
                FROM scans
                ORDER BY id DESC
                LIMIT 100
                '''
            ).fetchall()
    except psycopg.Error:
        return unavailable()
    content = ''.join(
        f'''
            <article>
                <h2>{e(result)} — {e(name)}</h2>
                <p>{e(created_at)} · {e(size)} octets</p>
                <p>SHA-256 : <code>{e(digest)}</code></p>
                <p>{e(detail)}</p>
            </article>
        '''
        for name, size, digest, result, detail, created_at in rows
    )
    return page(
        'Historique',
        (content or '<p>Aucune analyse enregistrée.</p>')
        + f'''
            <form action="/historique/supprimer" method="post">
                {token_input()}
                <button>Supprimer tout l’historique des analyses</button>
            </form>
        ''',
    )


@app.post('/historique/supprimer')
async def history_delete(request: Request):
    form = await request.form()
    if not verify(form):
        return HTMLResponse('Requête refusée.', status_code=403)
    try:
        with db() as conn:
            conn.execute('DELETE FROM scans')
    except psycopg.Error:
        return unavailable()
    return RedirectResponse('/historique', status_code=303)


def agent_authorized(request):
    value = request.headers.get('authorization', '')
    return len(AGENT_TOKEN) >= 32 and secrets.compare_digest(value, 'Bearer ' + AGENT_TOKEN)


def agent_online():
    return time.monotonic() - agent_state['last_seen'] < 15


def save_radio_scan(kind, status, items=None, error=''):
    finished_at = None if status == 'pending' else datetime.now(timezone.utc)
    with db() as conn:
        row = conn.execute(
            '''
            INSERT INTO radio_scans (kind, payload, status, error, finished_at)
            VALUES (%s, %s::jsonb, %s, %s, %s)
            RETURNING id
            ''',
            (kind, json.dumps(items or []), status, error, finished_at),
        ).fetchone()
    return row[0]


def finish_radio_scan(scan_id, status, items=None, error=''):
    with db() as conn:
        result = conn.execute(
            '''
            UPDATE radio_scans
            SET payload = %s::jsonb,
                status = %s,
                error = %s,
                finished_at = %s
            WHERE id = %s
            ''',
            (
                json.dumps(items or []),
                status,
                error,
                datetime.now(timezone.utc),
                scan_id,
            ),
        )
    return result.rowcount == 1


@app.get('/esp32')
def esp32():
    with agent_lock:
        state = 'Connecté' if agent_online() else 'Déconnecté ou en attente'
        pending = agent_state['job']
        last_error = agent_state['error']
    try:
        with db() as conn:
            rows = conn.execute(
                '''
                SELECT kind, payload, created_at, status, error
                FROM radio_scans
                ORDER BY id DESC
                LIMIT 20
                '''
            ).fetchall()
    except psycopg.Error:
        return unavailable()

    details = []
    status_labels = {
        'pending': 'En cours',
        'completed': 'Terminé',
        'failed': 'Échec',
    }
    for kind, items, date, scan_status, error in rows:
        result_lines = ''.join(
            '<li>'
            + ' · '.join(f'{e(key)} : {e(value)}' for key, value in item.items())
            + '</li>'
            for item in items
        )
        status_text = status_labels.get(scan_status, scan_status)
        error_text = f'<p>Erreur : {e(error)}</p>' if error else ''
        result_text = (
            f'<p>{len(items)} résultat(s), maximum 50.</p><ul>{result_lines}</ul>'
            if scan_status == 'completed'
            else ''
        )
        details.append(
            f'<article><h2>{e(kind.upper())} — {e(date)}</h2>'
            f'<p>État : {e(status_text)}</p>{error_text}{result_text}</article>'
        )

    return page(
        'Wi-Fi et Bluetooth',
        f'''
            <p>Agent : {e(state)}. {"Scan en cours." if pending else ""}</p>
            <p>{e(last_error)}</p>
            <p>
                Détection uniquement : les appareils silencieux peuvent être
                absents, leurs adresses BLE peuvent changer et un appareil
                détecté n’est pas nécessairement vulnérable. Le Wi-Fi est limité
                à 2,4 GHz et le Bluetooth à BLE passif.
            </p>
            <form action="/esp32/scan" method="post">
                {token_input()}
                <button name="kind" value="wifi">Scanner le Wi-Fi</button>
                <button name="kind" value="ble">Scanner le Bluetooth BLE</button>
            </form>
            <p><a href="/esp32">Actualiser l’état et les résultats</a></p>
            {''.join(details) or '<p>Aucun scan enregistré.</p>'}
            <p><a href="/esp32/supprimer">Supprimer les résultats Wi-Fi et BLE</a></p>
        ''',
    )


@app.get('/esp32/supprimer')
def radio_delete_confirm():
    return page(
        'Supprimer les scans radio',
        f'''
            <p>
                Cette action efface tous les résultats Wi-Fi et BLE enregistrés,
                sans supprimer les analyses de fichiers ni les CVE.
            </p>
            <form action="/esp32/supprimer" method="post">
                {token_input()}
                <button>Confirmer la suppression</button>
            </form>
            <a href="/esp32">Annuler</a>
        ''',
    )


@app.post('/esp32/supprimer')
async def radio_delete(request: Request):
    form = await request.form(max_fields=4)
    if not verify(form):
        return HTMLResponse('Requête refusée.', status_code=403)
    with agent_lock:
        try:
            with db() as conn:
                conn.execute('DELETE FROM radio_scans')
        except psycopg.Error:
            return unavailable()
        agent_state['job'] = None
        agent_state['error'] = ''
    return RedirectResponse('/esp32', status_code=303)


@app.post('/esp32/scan')
async def radio_request(request: Request):
    form = await request.form(max_fields=4)
    if not verify(form):
        return HTMLResponse('Requête refusée.', status_code=403)
    kind = str(form.get('kind', ''))
    if kind not in ('wifi', 'ble'):
        return HTMLResponse('Type de scan invalide.', status_code=400)

    with agent_lock:
        if agent_state['job']:
            try:
                save_radio_scan(
                    kind,
                    'failed',
                    error='Un autre scan est déjà en cours.',
                )
            except psycopg.Error:
                return unavailable()
            return page(
                'Scan déjà en cours',
                '<p>Un autre scan est déjà en cours.</p><a href="/esp32">Retour</a>',
            )

        if not agent_online():
            try:
                save_radio_scan(
                    kind,
                    'failed',
                    error='Agent ESP32 déconnecté.',
                )
            except psycopg.Error:
                return unavailable()
            return page(
                'Agent déconnecté',
                '<p>Connectez la carte et démarrez l’agent Windows avant de lancer un scan.</p>'
                '<a href="/esp32">Retour</a>',
            )

        try:
            record_id = save_radio_scan(kind, 'pending')
        except psycopg.Error:
            return unavailable()

        agent_state['error'] = ''
        agent_state['job'] = {
            'id': secrets.token_urlsafe(12),
            'record_id': record_id,
            'kind': kind,
            'claimed': False,
            'started': time.monotonic(),
        }

    return page(
        'Scan demandé',
        '<p>Le scan est en cours. Patientez quelques secondes puis '
        '<a href="/esp32">actualisez les résultats</a>.</p>',
    )


@app.post('/agent/next')
async def agent_next(request: Request):
    if not agent_authorized(request):
        return HTMLResponse('Non autorisé', status_code=403)
    with agent_lock:
        agent_state['last_seen'] = time.monotonic()
        job = agent_state['job']
        if job and time.monotonic() - job['started'] > 60:
            try:
                finish_radio_scan(
                    job['record_id'],
                    'failed',
                    error='Le scan a expiré sans réponse de la carte.',
                )
            except psycopg.Error:
                LOG.warning('Impossible d’enregistrer l’expiration du scan radio')
                return {}
            agent_state['job'] = None
            agent_state['error'] = 'Le scan a expiré sans réponse de la carte.'
            job = None
        if not job or job['claimed']:
            return {}
        job['claimed'] = True
        return {'id':job['id'], 'kind':job['kind']}


@app.post('/agent/result')
async def agent_result(request: Request):
    if not agent_authorized(request):
        return HTMLResponse('Non autorisé', status_code=403)
    try:
        body = await request.json()
    except ValueError:
        return HTMLResponse('JSON invalide', status_code=400)
    if not isinstance(body, dict):
        return HTMLResponse('Message invalide', status_code=400)
    with agent_lock:
        job = agent_state['job']
        if not job or not job['claimed'] or body.get('id') != job['id']:
            return HTMLResponse('Scan inconnu', status_code=409)
        if body.get('error'):
            error = 'Le dernier scan a échoué : vérifiez la connexion série et le firmware.'
            try:
                finish_radio_scan(job['record_id'], 'failed', error=error)
            except psycopg.Error:
                LOG.warning('Impossible d’enregistrer l’échec du scan radio')
                return HTMLResponse('Base indisponible', status_code=503)
            agent_state['error'] = error
            agent_state['job'] = None
            return {'ok': False}

        items = body.get('items')
        valid_items = (
            isinstance(items, list)
            and len(items) <= 50
            and all(
                isinstance(item, dict)
                and len(item) <= 8
                and all(
                    isinstance(key, str)
                    and len(key) <= 32
                    and isinstance(value, (str, int))
                    and len(str(value)) <= 256
                    for key, value in item.items()
                )
                for item in items
            )
        )
        if not valid_items:
            return HTMLResponse('Résultats invalides', status_code=400)

        try:
            saved = finish_radio_scan(
                job['record_id'],
                'completed',
                items=items,
            )
        except psycopg.Error:
            LOG.warning('Impossible de sauvegarder le scan radio')
            return HTMLResponse('Base indisponible', status_code=503)

        if not saved:
            agent_state['job'] = None
            return HTMLResponse('Résultat déjà supprimé', status_code=409)

        agent_state['job'] = None
    return {'ok': True}


@app.get('/parametres')
def settings():
    return page(
        'Paramètres',
        '''
            <p>
                Accès local uniquement. La taille maximale des fichiers est de
                20 Mio. Les résultats restent dans PostgreSQL jusqu’à leur
                suppression manuelle.
            </p>
            <p>
                Les fichiers ne sont envoyés qu’au moteur ClamAV local. Une
                recherche CVE envoie le terme à la NVD uniquement lorsque vous
                cliquez sur le bouton correspondant.
            </p>
        ''',
    )
