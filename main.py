from html import escape
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

BASE = Path(__file__).resolve().parent
app = FastAPI(title="Cyber Local", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


def service_status():
    return {"application": "en ligne", "antivirus": "non installé",
            "base_de_donnees": "non installée", "esp32": "non configuré"}


@app.get("/", response_class=HTMLResponse)
def home():
    status = service_status()
    template = (BASE / "static" / "index.html").read_text(encoding="utf-8")
    replacements = {
        "{{application_badge}}": "ACTIF" if status["application"] == "en ligne" else "INCONNU",
        "{{application_status}}": "● Serveur en ligne" if status["application"] == "en ligne" else "État inconnu",
    }
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, escape(value))
    return HTMLResponse(template, headers={"Cache-Control": "no-store"})


@app.get("/api/status")
def status():
    return service_status()
