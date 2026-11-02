async function refreshStatus() {
  const status = document.getElementById('app-status');
  const badge = document.getElementById('app-badge');
  status.textContent = 'Vérification en cours…';
  try {
    const response = await fetch('/api/status', {cache: 'no-store'});
    if (!response.ok) throw new Error('Serveur indisponible');
    const data = await response.json();
    status.textContent = data.application === 'en ligne' ? '●  Serveur en ligne' : 'État inconnu';
    badge.textContent = data.application === 'en ligne' ? 'ACTIF' : 'INCONNU';
  } catch (_) {
    status.textContent = 'Serveur indisponible';
    badge.textContent = 'HORS LIGNE';
  }
}
document.getElementById('refresh').addEventListener('click', refreshStatus);
refreshStatus();
