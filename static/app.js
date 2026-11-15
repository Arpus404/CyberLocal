function updateService(name, value, isReady) {
    const status = document.getElementById(`${name}-status`);
    const badge = document.getElementById(`${name}-badge`);

    status.textContent = value;
    badge.textContent = isReady ? "PRÊT" : "INDISPONIBLE";
    badge.classList.toggle("muted", !isReady);
}

function updateCount(id, value) {
    const element = document.getElementById(id);
    element.textContent = Number.isInteger(value) ? value.toLocaleString("fr-FR") : "—";
}

async function refreshStatus() {
    const appStatus = document.getElementById("app-status");
    const appBadge = document.getElementById("app-badge");
    appStatus.textContent = "Vérification en cours…";
    appBadge.textContent = "VÉRIFICATION";

    try {
        const response = await fetch("/api/status", { cache: "no-store" });
        if (!response.ok) {
            throw new Error("Serveur indisponible");
        }

        const data = await response.json();
        appStatus.textContent = "●  Serveur en ligne";
        appBadge.textContent = "ACTIF";
        appBadge.classList.remove("muted");

        const antivirusReady = data.antivirus === "Prêt";
        const databaseReady = data.base_de_donnees === "Connectée";
        const esp32Ready = data.esp32 === "Connecté";

        updateService("antivirus", data.antivirus, antivirusReady);
        updateService("database", data.base_de_donnees, databaseReady);
        updateService("esp32", data.esp32, esp32Ready);

        updateCount("analysis-count", data.analyses);
        updateCount("threat-count", data.menaces);
        updateCount("cve-count", data.cves);
        updateCount("radio-count", data.scans_radio);
    } catch (_) {
        appStatus.textContent = "Serveur indisponible";
        appBadge.textContent = "HORS LIGNE";
        appBadge.classList.add("muted");

        updateService("antivirus", "État inconnu", false);
        updateService("database", "État inconnu", false);
        updateService("esp32", "État inconnu", false);
        updateCount("analysis-count", null);
        updateCount("threat-count", null);
        updateCount("cve-count", null);
        updateCount("radio-count", null);
    }
}

document.getElementById("refresh").addEventListener("click", refreshStatus);
refreshStatus();
