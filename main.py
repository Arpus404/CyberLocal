from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

BASE = Path(__file__).resolve().parent
app = FastAPI(title="Cyber Local", docs_url=None, redoc_url=None)
app.mount('/static', StaticFiles(directory=BASE / 'static'), name='static')

@app.get('/')
def home():
    return FileResponse(BASE / 'static' / 'index.html')

@app.get('/api/status')
def status():
    return {'application': 'en ligne', 'antivirus': 'non installé', 'base_de_donnees': 'non installée', 'esp32': 'non configuré'}
