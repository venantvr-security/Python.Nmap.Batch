const tilesContainer = document.getElementById('tiles');
const progressText = document.getElementById('progress-text');
const progressBar = document.getElementById('progress-bar');
const threadTiles = {};  // Stocke les éléments DOM des tuiles actives
const activeThreads = new Set();  // Suit les threads actifs

// Initialiser SSE
const source = new EventSource('/events');

source.onopen = () => {
    console.log('Connexion SSE ouverte');
    progressText.textContent = 'Connecté au serveur';
};

source.onerror = (error) => {
    console.error('Erreur SSE :', error);
    progressText.textContent = 'Erreur de connexion au serveur. Tentative de reconnexion...';
};

source.addEventListener('progress', (event) => {
    const data = JSON.parse(event.data);
    console.log('Reçu progress :', data);
    progressText.textContent = data.message;
    const match = data.message.match(/Progression : (\d+)\/(\d+) \(([\d.]+)%\)/);
    if (match) {
        const percentage = parseFloat(match[3]);
        progressBar.style.width = `${percentage}%`;
        progressBar.setAttribute('aria-valuenow', percentage);
        progressBar.textContent = `${percentage.toFixed(2)}%`;
    } else {
        progressBar.style.width = '0%';
        progressBar.setAttribute('aria-valuenow', 0);
        progressBar.textContent = '';
    }
});

source.addEventListener('thread_update', (event) => {
    const data = JSON.parse(event.data);
    console.log('Reçu thread_update :', data);
    const { thread_id, message } = data;

    // Vérifier si le thread commence
    if (message.includes("Début du scan")) {
        activeThreads.add(thread_id);
        if (!threadTiles[thread_id]) {
            const tile = document.createElement('div');
            tile.className = 'col';
            tile.innerHTML = `
                <div class="card tile">
                    <div class="card-header">Thread ${thread_id.slice(0, 8)}</div>
                    <div class="card-body"></div>
                </div>
            `;
            tilesContainer.appendChild(tile);
            threadTiles[thread_id] = tile.querySelector('.card-body');
        }
    }

    // Ajouter le message si le thread est actif
    if (activeThreads.has(thread_id)) {
        const tile = threadTiles[thread_id];
        const lines = message.split('\n');
        lines.forEach(line => {
            const p = document.createElement('p');
            p.textContent = line;
            tile.appendChild(p);
        });
        tile.scrollTop = tile.scrollHeight;
    }

    // Supprimer la tuile si le thread est terminé
    if (message.includes("terminé avec succès") ||
        message.includes("n’a pas de ports ouverts") ||
        message.includes("Scan interrompu") ||
        message.includes("Nmap a échoué")) {
        if (activeThreads.has(thread_id)) {
            activeThreads.delete(thread_id);
            setTimeout(() => {
                if (!activeThreads.has(thread_id) && threadTiles[thread_id]) {
                    const tile = threadTiles[thread_id].parentElement.parentElement;
                    tilesContainer.removeChild(tile);
                    delete threadTiles[thread_id];
                }
            }, 1000);  // Délai pour laisser le dernier message visible
        }
    }
});

source.addEventListener('ping', (event) => {
    console.log('Ping reçu :', event.data);
});

function startScan() {
    console.log('Envoi de start_scan');
    fetch('/start_scan/stealth-http')  // Utilise la nouvelle stratégie
        .then(response => console.log('Start scan réponse :', response.status))
        .catch(error => console.error('Erreur start_scan :', error));
}

function stopScan() {
    console.log('Envoi de stop_scan');
    fetch('/stop_scan')
        .then(response => console.log('Stop scan réponse :', response.status))
        .catch(error => console.error('Erreur stop_scan :', error));
}