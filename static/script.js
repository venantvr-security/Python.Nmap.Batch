const tilesContainer = document.getElementById('tiles');
const progressText = document.getElementById('progress-text');
const progressBar = document.getElementById('progress-bar');
const threadTiles = {};
const activeThreads = new Set();
const scanners = ['nmap', 'netcat', 'scapy', 'masscan', 'hping3'];

let selectedStrategies = {
    'nmap': null,
    'netcat': null,
    'scapy': null,
    'masscan': null,
    'hping3': null
};

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

    if (message.includes("terminé avec succès") ||
        message.includes("n’a pas de ports ouverts") ||
        message.includes("Scan interrompu") ||
        message.includes("échoué avec le code")) {
        if (activeThreads.has(thread_id)) {
            activeThreads.delete(thread_id);
            setTimeout(() => {
                if (!activeThreads.has(thread_id) && threadTiles[thread_id]) {
                    const tile = threadTiles[thread_id].parentElement.parentElement;
                    tilesContainer.removeChild(tile);
                    delete threadTiles[thread_id];
                }
            }, 1000);
        }
    }
});

source.addEventListener('ping', (event) => {
    console.log('Ping reçu :', event.data);
});

function populateStrategies(scannerType) {
    const dropdown = document.getElementById(`${scannerType}-strategies`);
    fetch(`/get_strategies/${scannerType}`)
        .then(response => {
            if (!response.ok) throw new Error(`Erreur HTTP : ${response.status}`);
            return response.json();
        })
        .then(data => {
            if (data.error) {
                console.error(`Erreur pour ${scannerType} : ${data.error}`);
                progressText.textContent = `Erreur : ${data.error}`;
                return;
            }
            dropdown.innerHTML = '';
            data.strategies.forEach(strategy => {
                const li = document.createElement('li');
                const a = document.createElement('a');
                a.className = 'dropdown-item';
                a.href = '#';
                a.textContent = strategy;
                a.onclick = () => selectStrategy(scannerType, strategy);
                li.appendChild(a);
                dropdown.appendChild(li);
            });
            if (data.strategies.length > 0) selectStrategy(scannerType, data.strategies[0]);
            // Ajout du lien pour les infos
            const infoLi = document.createElement('li');
            const infoA = document.createElement('a');
            infoA.className = 'dropdown-item text-info';
            infoA.href = '#';
            infoA.textContent = 'Détails techniques';
            infoA.onclick = () => showScannerInfo(scannerType);
            infoLi.appendChild(infoA);
            dropdown.appendChild(infoLi);
        })
        .catch(error => {
            console.error(`Erreur pour ${scannerType} :`, error);
            progressText.textContent = `Erreur : ${error.message}`;
        });
}

function selectStrategy(scannerType, strategy) {
    selectedStrategies[scannerType] = strategy;
    console.log(`Stratégie sélectionnée pour ${scannerType} : ${strategy}`);
    let button;
    switch (scannerType) {
        case 'nmap': button = document.querySelector('.btn-primary'); break;
        case 'netcat': button = document.querySelector('.btn-success'); break;
        case 'scapy': button = document.querySelector('.btn-info'); break;
        case 'masscan': button = document.querySelector('.btn-warning'); break;
        case 'hping3': button = document.querySelector('.btn-secondary'); break;
    }
    button.textContent = `Démarrer ${scannerType} (${strategy})`;
}

function startScan(scannerType) {
    const strategy = selectedStrategies[scannerType];
    if (!strategy) {
        progressText.textContent = `Erreur : Aucune stratégie sélectionnée pour ${scannerType}`;
        return;
    }
    console.log(`Envoi de start_scan pour ${scannerType} avec stratégie ${strategy}`);
    fetch(`/start_scan/${scannerType}/${strategy}`)
        .then(response => {
            console.log('Start scan réponse :', response.status);
            if (!response.ok) throw new Error(`Erreur HTTP : ${response.status}`);
        })
        .catch(error => {
            console.error('Erreur start_scan :', error);
            progressText.textContent = `Erreur : ${error.message}`;
        });
}

function stopScan() {
    console.log('Envoi de stop_scan');
    fetch('/stop_scan')
        .then(response => {
            console.log('Stop scan réponse :', response.status);
            if (!response.ok) throw new Error(`Erreur HTTP : ${response.status}`);
        })
        .catch(error => {
            console.error('Erreur stop_scan :', error);
            progressText.textContent = `Erreur : ${error.message}`;
        });
}

function showScannerInfo(scannerType) {
    fetch(`/get_scanner_info/${scannerType}`)
        .then(response => {
            if (!response.ok) throw new Error(`Erreur HTTP : ${response.status}`);
            return response.json();
        })
        .then(data => {
            if (data.error) {
                console.error(`Erreur pour ${scannerType} : ${data.error}`);
                progressText.textContent = `Erreur : ${data.error}`;
                return;
            }
            const contentDiv = document.getElementById('scanner-info-content');
            contentDiv.innerHTML = marked.parse(data.content); // Conversion Markdown en HTML
            document.getElementById('scannerInfoModalLabel').textContent = `Détails du Scanner : ${scannerType.toUpperCase()}`;
            const modal = new bootstrap.Modal(document.getElementById('scannerInfoModal'));
            modal.show();
        })
        .catch(error => {
            console.error('Erreur lors de la récupération des infos :', error);
            progressText.textContent = `Erreur : ${error.message}`;
        });
}

document.addEventListener('DOMContentLoaded', () => {
    scanners.forEach(scanner => populateStrategies(scanner));
});