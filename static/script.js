const tilesContainer = document.getElementById('tiles');
const progressText = document.getElementById('progress-text');
const progressBar = document.getElementById('progress-bar');
const threadTiles = {};
const activeThreads = new Set();

let selectedStrategies = {
    'nmap': null,
    'netcat': null,
    'scapy': null,
    'masscan': null,
    'hping3': null,
    'curl': null,
};

let selectedPorts = null; // Variable pour stocker les ports sélectionnés

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
            setTimeout(() => {
                if (activeThreads.has(thread_id) && threadTiles[thread_id]) {
                    threadTiles[thread_id].innerHTML += '<p>[Timeout] Scan bloqué, forcé à fermer</p>';
                    activeThreads.delete(thread_id);
                    setTimeout(() => {
                        const tile = threadTiles[thread_id].parentElement.parentElement;
                        tilesContainer.removeChild(tile);
                        delete threadTiles[thread_id];
                    }, 10000);
                }
            }, 35000);
        }
    }

    if (activeThreads.has(thread_id)) {
        const tile = threadTiles[thread_id];
        const lines = message.split('\n');
        lines.forEach(line => {
            const p = document.createElement('p');
            p.textContent = line;
            if (line.includes("Début du scan avec")) {
                p.style.fontWeight = 'bold';
            }
            tile.appendChild(p);
        });
        tile.scrollTop = tile.scrollHeight;
    }

    if (message.includes("terminé avec succès") ||
        message.includes("n’a pas de ports ouverts") ||
        message.includes("Scan interrompu") ||
        message.includes("échoué avec le code") ||
        message.includes("Scan timeout après")) {
        if (activeThreads.has(thread_id)) {
            activeThreads.delete(thread_id);
            setTimeout(() => {
                if (!activeThreads.has(thread_id) && threadTiles[thread_id]) {
                    const tile = threadTiles[thread_id].parentElement.parentElement;
                    tilesContainer.removeChild(tile);
                    delete threadTiles[thread_id];
                }
            }, 10000);
        }
    }
});

source.addEventListener('ping', (event) => {
    console.log('Ping reçu :', event.data);
});

// Fonction pour démarrer un scan
function startScan(scannerType) {
    const strategy = selectedStrategies[scannerType];
    if (!strategy) {
        progressText.textContent = `Erreur : Aucune stratégie sélectionnée pour ${scannerType}`;
        return;
    }
    if (!selectedPorts) {
        progressText.textContent = `Erreur : Aucun port sélectionné`;
        return;
    }
    console.log(`Envoi de start_scan pour ${scannerType} avec stratégie ${strategy} et ports ${selectedPorts}`);
    fetch(`/scan/start/${scannerType}/${strategy}?ports=${encodeURIComponent(selectedPorts)}`)
        .then(response => {
            if (!response.ok) throw new Error(`Erreur HTTP : ${response.status}`);
            return response.text();
        })
        .then(message => console.log(message))
        .catch(error => {
            console.error('Erreur start_scan :', error);
            progressText.textContent = `Erreur : ${error.message}`;
        });
}

// Générer dynamiquement les boutons depuis l'API
async function loadScannerButtons() {
    const scannerButtonsContainer = document.getElementById('scanner-buttons');

    try {
        const response = await fetch('/api/scanners');
        const scanners = await response.json();

        scanners.forEach(scanner => {
            const col = document.createElement('div');
            col.className = 'col';

            const btnGroup = document.createElement('div');
            btnGroup.className = 'btn-group w-100';

            const mainButton = document.createElement('button');
            mainButton.className = `btn ${scanner.class}`;
            mainButton.textContent = `Démarrer ${scanner.name.charAt(0).toUpperCase() + scanner.name.slice(1)}`;
            mainButton.onclick = () => startScan(scanner.name);

            const dropdownToggle = document.createElement('button');
            dropdownToggle.className = `btn ${scanner.class} dropdown-toggle dropdown-toggle-split`;
            dropdownToggle.setAttribute('type', 'button');
            dropdownToggle.setAttribute('data-bs-toggle', 'dropdown');
            dropdownToggle.setAttribute('aria-expanded', 'false');
            const visuallyHidden = document.createElement('span');
            visuallyHidden.className = 'visually-hidden';
            visuallyHidden.textContent = 'Sélectionner stratégie';
            dropdownToggle.appendChild(visuallyHidden);

            const dropdownMenu = document.createElement('ul');
            dropdownMenu.className = 'dropdown-menu';
            dropdownMenu.id = `${scanner.name}-strategies`;

            scanner.strategies.forEach(strategy => {
                const item = document.createElement('li');
                const link = document.createElement('a');
                link.className = 'dropdown-item';
                link.href = '#';
                link.textContent = strategy;
                link.onclick = (e) => {
                    e.preventDefault();
                    selectedStrategies[scanner.name] = strategy;
                    mainButton.textContent = `Démarrer ${scanner.name.charAt(0).toUpperCase() + scanner.name.slice(1)} (${strategy})`;
                    console.log(`Stratégie sélectionnée pour ${scanner.name} : ${strategy}`);
                };
                item.appendChild(link);
                dropdownMenu.appendChild(item);
            });

            const infoItem = document.createElement('li');
            const infoLink = document.createElement('a');
            infoLink.className = 'dropdown-item text-info';
            infoLink.href = '#';
            infoLink.textContent = 'Détails techniques';
            infoLink.onclick = () => showScannerInfo(scanner.name);
            infoItem.appendChild(infoLink);
            dropdownMenu.appendChild(infoItem);

            btnGroup.appendChild(mainButton);
            btnGroup.appendChild(dropdownToggle);
            btnGroup.appendChild(dropdownMenu);
            col.appendChild(btnGroup);
            scannerButtonsContainer.appendChild(col);

            if (scanner.strategies.length > 0) {
                selectedStrategies[scanner.name] = scanner.strategies[0];
                mainButton.textContent = `Démarrer ${scanner.name.charAt(0).toUpperCase() + scanner.name.slice(1)} (${scanner.strategies[0]})`;
            }
        });

        const controlCol = document.createElement('div');
        controlCol.className = 'col';
        const controlDiv = document.createElement('div');
        controlDiv.className = 'd-flex gap-2';
        controlDiv.innerHTML = `
            <button class="btn btn-danger w-50" onclick="stopScan()">Arrêter le scan</button>
            <button class="btn btn-warning w-50" onclick="resetProgress()">Réinitialiser</button>
        `;
        controlCol.appendChild(controlDiv);
        scannerButtonsContainer.appendChild(controlCol);

    } catch (error) {
        console.error('Erreur lors du chargement des scanners :', error);
        scannerButtonsContainer.innerHTML = '<p>Erreur lors du chargement des scanners.</p>';
    }
}

// Fonctions pour arrêter et réinitialiser
function stopScan() {
    console.log('Envoi de stop_scan');
    fetch('/scan/stop')
        .then(response => {
            if (!response.ok) throw new Error(`Erreur HTTP : ${response.status}`);
            return response.text();
        })
        .then(message => console.log(message))
        .catch(error => {
            console.error('Erreur stop_scan :', error);
            progressText.textContent = `Erreur : ${error.message}`;
        });
}

function resetProgress() {
    fetch('/progress/reset', { method: 'POST' })
        .then(response => {
            if (!response.ok) throw new Error(`Erreur HTTP : ${response.status}`);
            return response.text();
        })
        .then(message => {
            console.log(message);
            progressBar.style.width = '0%';
            progressBar.setAttribute('aria-valuenow', 0);
            progressBar.textContent = '';
            progressText.textContent = 'En attente...';
        })
        .catch(error => {
            console.error('Erreur reset_progress :', error);
            progressText.textContent = `Erreur : ${error.message}`;
        });
}

function showScannerInfo(scannerType) {
    fetch(`/scanner/info/get/${scannerType}`)
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
            contentDiv.innerHTML = marked.parse(data.content);
            document.getElementById('scannerInfoModalLabel').textContent = `Détails du Scanner : ${scannerType.toUpperCase()}`;
            const modal = new bootstrap.Modal(document.getElementById('scannerInfoModal'));
            modal.show();
        })
        .catch(error => {
            console.error('Erreur lors de la récupération des infos :', error);
            progressText.textContent = `Erreur : ${error.message}`;
        });
}

// Gestion du mode nuit
const toggleButton = document.getElementById('dark-mode-toggle');
const body = document.body;
const icon = toggleButton.querySelector('.dark-mode-icon');

toggleButton.addEventListener('click', () => {
    body.classList.toggle('dark-mode');
    if (body.classList.contains('dark-mode')) {
        icon.textContent = '☀️';
        toggleButton.textContent = ' Mode Jour';
        toggleButton.prepend(icon);
    } else {
        icon.textContent = '🌙';
        toggleButton.textContent = ' Mode Nuit';
        toggleButton.prepend(icon);
    }
    localStorage.setItem('darkMode', body.classList.contains('dark-mode'));
});

if (localStorage.getItem('darkMode') === 'true') {
    body.classList.add('dark-mode');
    icon.textContent = '☀️';
    toggleButton.textContent = ' Mode Jour';
    toggleButton.prepend(icon);
}

// Charger les ports dans la dropdown et mettre à jour le bouton
fetch('/api/ports')
    .then(response => {
        if (!response.ok) throw new Error('Erreur lors du chargement des ports');
        return response.json();
    })
    .then(data => {
        const portsList = document.getElementById('ports-list');
        const portsButton = document.getElementById('portsDropdown');
        portsList.innerHTML = '';
        data.ports.forEach(port => {
            const li = document.createElement('li');
            const a = document.createElement('a');
            a.className = 'dropdown-item';
            a.href = '#';
            a.textContent = port;
            a.onclick = (e) => {
                e.preventDefault();
                selectedPorts = port;
                portsButton.textContent = `Ports : ${port}`;
                console.log(`Ports sélectionnés : ${port}`);
            };
            li.appendChild(a);
            portsList.appendChild(li);
        });
        if (data.ports.length > 0) {
            selectedPorts = data.ports[0];
            portsButton.textContent = `Ports : ${data.ports[0]}`;
        }
    })
    .catch(error => {
        console.error('Erreur :', error);
        document.getElementById('ports-list').innerHTML = '<li><a class="dropdown-item" href="#">Erreur de chargement</a></li>';
    });

// Charger les boutons au démarrage
document.addEventListener('DOMContentLoaded', loadScannerButtons);