"""Helpers for local file analysis and CVE lookups."""

import hashlib
import json
import socket
import struct
import urllib.parse
import urllib.request


MAX_FILE = 20 * 1024 * 1024
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def sha256(data: bytes) -> str:
    """Return the SHA-256 digest of a file's bytes."""
    return hashlib.sha256(data).hexdigest()


def clam_scan(data: bytes, host: str = "clamav", port: int = 3310) -> tuple[str, str]:
    """Send bytes to the local ClamAV daemon without saving or executing them."""
    with socket.create_connection((host, port), timeout=8) as connection:
        connection.settimeout(90)
        connection.sendall(b"zINSTREAM\0")

        for offset in range(0, len(data), 65536):
            chunk = data[offset : offset + 65536]
            connection.sendall(struct.pack("!I", len(chunk)) + chunk)

        connection.sendall(struct.pack("!I", 0))
        response = bytearray()

        while len(response) < 8192:
            part = connection.recv(1024)
            if not part:
                break

            response.extend(part)
            if b"\0" in part or b"\n" in part:
                break

    result = response.decode("utf-8", "replace").strip("\0\r\n")
    if result.endswith(" FOUND"):
        threat_name = result.partition(": ")[2].removesuffix(" FOUND")
        return "Menace détectée", threat_name

    if result.endswith(" OK"):
        return (
            "Analyse incomplète",
            "Aucune menace détectée par ClamAV ; les limites de couverture ne sont pas vérifiées.",
        )

    return "Échec de l’analyse", "Réponse inattendue du moteur."


def remediation_plan(
    severity: str,
    vendor_advisories: list[str],
    cisa_required_action: str = "",
) -> list[str]:
    """Build cautious remediation steps from NVD and vendor advisory data."""
    steps = [
        "Vérifier que le produit et la version installés correspondent aux versions affectées.",
    ]

    if cisa_required_action:
        steps.append(f"Action prioritaire CISA : {cisa_required_action}")

    normalized_severity = severity.upper()
    if normalized_severity in {"CRITICAL", "HIGH"}:
        steps.append(
            "Traiter en priorité si le produit est exposé ou accessible depuis un réseau."
        )
    elif normalized_severity in {"MEDIUM", "LOW"}:
        steps.append(
            "Planifier la correction selon l’exposition et l’impact sur votre environnement."
        )
    else:
        steps.append(
            "Évaluer la priorité après avoir vérifié l’exposition et l’impact dans votre environnement."
        )

    if vendor_advisories:
        steps.append(
            "Consulter l’avis officiel de l’éditeur et appliquer la version corrigée ou le contournement qu’il indique."
        )
    else:
        steps.append(
            "Rechercher l’avis officiel de l’éditeur à partir de l’identifiant CVE ; "
            "aucune version corrigée n’est déduite ici."
        )

    steps.append(
        "Après la correction, vérifier la version installée et refaire une recherche pour confirmer le résultat."
    )
    return steps


def nvd_search(query: str) -> list[dict]:
    """Search NVD and return a small, display-ready set of CVE records."""
    query = query.strip()
    if not query or len(query) > 150:
        raise ValueError("Saisissez une recherche de 1 à 150 caractères.")

    parameter = "cveId" if query.upper().startswith("CVE-") else "keywordSearch"
    encoded_query = urllib.parse.urlencode(
        {parameter: query, "resultsPerPage": 20}
    )
    request = urllib.request.Request(
        f"{NVD_URL}?{encoded_query}",
        headers={"User-Agent": "CyberLocal/0.3"},
    )

    with urllib.request.urlopen(request, timeout=12) as response:
        result = json.load(response)

    rows = []
    for item in result.get("vulnerabilities", []):
        cve = item.get("cve", {})
        descriptions = cve.get("descriptions") or []
        description = next(
            (
                entry.get("value", "")
                for entry in descriptions
                if entry.get("lang") == "en"
            ),
            "",
        )

        metrics = cve.get("metrics") or {}
        cvss = next(
            (
                metric.get("cvssData") or {}
                for metric_name in (
                    "cvssMetricV40",
                    "cvssMetricV31",
                    "cvssMetricV30",
                    "cvssMetricV2",
                )
                for metric in (metrics.get(metric_name) or [])
            ),
            {},
        )

        references = []
        vendor_advisories = []
        for reference in cve.get("references") or []:
            url = str(reference.get("url", "") or "")
            if not url.startswith(("https://", "http://")):
                continue

            references.append(url)
            tags = {
                str(tag).casefold()
                for tag in (reference.get("tags") or [])
            }
            if tags.intersection({"vendor advisory", "patch"}):
                vendor_advisories.append(url)

        cisa_action = str(cve.get("cisaRequiredAction", "") or "")
        severity = str(cvss.get("baseSeverity", "") or "")
        rows.append(
            {
                "id": cve.get("id", ""),
                "description": description,
                "published": cve.get("published", ""),
                "modified": cve.get("lastModified", ""),
                "score": cvss.get("baseScore"),
                "severity": severity,
                "references": references[:10],
                "vendor_advisories": vendor_advisories[:5],
                "cisa_required_action": cisa_action,
                "recommendations": remediation_plan(
                    severity,
                    vendor_advisories,
                    cisa_action,
                ),
            }
        )

    return rows
