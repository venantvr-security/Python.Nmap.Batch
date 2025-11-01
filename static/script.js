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
let originalPortsTemplate = null; // Template original avant randomisation

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

// Fonction pour parser et randomiser les ports
function parseAndRandomizePorts(portString) {
    let ports = [];
    const items = portString.split(',');

    for (let item of items) {
        item = item.trim();
        if (item.includes('-')) {
            const [start, end] = item.split('-').map(x => parseInt(x.trim()));
            for (let p = start; p <= end; p++) {
                ports.push(p);
            }
        } else {
            ports.push(parseInt(item));
        }
    }

    // Randomiser l'ordre
    for (let i = ports.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [ports[i], ports[j]] = [ports[j], ports[i]];
    }

    return ports.join(',');
}

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

    let portsToScan = selectedPorts;
    const randomize = document.getElementById('randomize-ports-checkbox').checked;

    if (randomize) {
        portsToScan = parseAndRandomizePorts(selectedPorts);
        console.log(`Ports randomisés: ${portsToScan}`);
    }

    console.log(`Envoi de start_scan pour ${scannerType} avec stratégie ${strategy} et ports ${portsToScan}`);
    fetch(`/scan/start/${scannerType}/${strategy}?ports=${encodeURIComponent(portsToScan)}`)
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
const modeText = toggleButton.querySelector('.dark-mode-text');

toggleButton.addEventListener('click', () => {
    body.classList.toggle('dark-mode');
    if (body.classList.contains('dark-mode')) {
        icon.textContent = '☀️';
        modeText.textContent = 'Light';
    } else {
        icon.textContent = '🌙';
        modeText.textContent = 'Dark';
    }
    localStorage.setItem('darkMode', body.classList.contains('dark-mode'));
});

if (localStorage.getItem('darkMode') === 'true') {
    body.classList.add('dark-mode');
    icon.textContent = '☀️';
    modeText.textContent = 'Light';
}

// Charger les ports dans la dropdown et mettre à jour le bouton
fetch('/api/ports')
    .then(response => {
        if (!response.ok) throw new Error('Erreur lors du chargement des ports');
        return response.json();
    })
    .then(data => {
        const portsList = document.getElementById('ports-list-nav');
        const portsNavText = document.getElementById('ports-nav-text');
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
                originalPortsTemplate = port;
                portsNavText.textContent = `Ports: ${port.substring(0, 20)}${port.length > 20 ? '...' : ''}`;
                console.log(`Ports sélectionnés : ${port}`);
            };
            li.appendChild(a);
            portsList.appendChild(li);
        });
        if (data.ports.length > 0) {
            selectedPorts = data.ports[0];
            originalPortsTemplate = data.ports[0];
            portsNavText.textContent = `Ports: ${data.ports[0].substring(0, 20)}${data.ports[0].length > 20 ? '...' : ''}`;
        }
    })
    .catch(error => {
        console.error('Erreur :', error);
        document.getElementById('ports-list-nav').innerHTML = '<li><a class="dropdown-item" href="#">Erreur de chargement</a></li>';
    });

// Fonctions TOR
function checkTorStatus() {
    fetch('/api/tor/status')
        .then(response => response.json())
        .then(data => {
            const statusDiv = document.getElementById('tor-status');
            const statusText = document.getElementById('tor-status-text');
            const indicator = document.getElementById('tor-indicator');
            if (data.tor_enabled) {
                statusDiv.className = 'badge bg-success';
                indicator.textContent = '✓';
                statusText.textContent = 'TOR Active';
            } else {
                statusDiv.className = 'badge bg-danger';
                indicator.textContent = '✗';
                statusText.textContent = 'TOR Off';
            }
        })
        .catch(error => {
            console.error('Erreur vérification TOR:', error);
            const statusDiv = document.getElementById('tor-status');
            const statusText = document.getElementById('tor-status-text');
            const indicator = document.getElementById('tor-indicator');
            statusDiv.className = 'badge bg-warning';
            indicator.textContent = '⚠';
            statusText.textContent = 'Error';
        });
}

function changeTorIdentity() {
    fetch('/api/tor/identity/change', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Identité TOR changée avec succès');
                checkTorStatus();
            } else {
                alert('Erreur: ' + data.error);
            }
        })
        .catch(error => {
            console.error('Erreur changement identité:', error);
            alert('Erreur lors du changement d\'identité TOR');
        });
}

function setTorFrequency() {
    const frequency = document.getElementById('tor-frequency').value;
    fetch('/api/tor/identity/frequency', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ frequency: parseInt(frequency) })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`Fréquence définie à ${data.frequency} secondes`);
            }
        })
        .catch(error => {
            console.error('Erreur définition fréquence:', error);
            alert('Erreur lors de la définition de la fréquence');
        });
}

function showMeekInfo() {
    const modal = new bootstrap.Modal(document.getElementById('meekModal'));
    modal.show();
}

function showSnowflakeInfo() {
    const modal = new bootstrap.Modal(document.getElementById('snowflakeModal'));
    modal.show();
}

function showAIEvasionInfo() {
    const modal = new bootstrap.Modal(document.getElementById('aiEvasionModal'));
    modal.show();
}

// Filtrage par mot-clé
function filterStrategies() {
    const query = document.getElementById('search-filter').value.toLowerCase().trim();

    // Filtrer AI Evasion dropdown
    const evasionSelect = document.getElementById('evasion-preset');
    const optgroups = evasionSelect.querySelectorAll('optgroup');

    optgroups.forEach(optgroup => {
        let hasVisibleOptions = false;
        const options = optgroup.querySelectorAll('option');

        options.forEach(option => {
            const text = option.textContent.toLowerCase();
            const value = option.value.toLowerCase();
            const label = optgroup.label.toLowerCase();

            if (query === '' || text.includes(query) || value.includes(query) || label.includes(query)) {
                option.style.display = '';
                hasVisibleOptions = true;
            } else {
                option.style.display = 'none';
            }
        });

        // Masquer optgroup si aucune option visible
        optgroup.style.display = hasVisibleOptions ? '' : 'none';
    });

    // Filtrer boutons scanners
    const scannerButtons = document.querySelectorAll('#scanner-buttons .col');
    scannerButtons.forEach(col => {
        const btnGroup = col.querySelector('.btn-group');
        if (!btnGroup) return;

        const mainButton = btnGroup.querySelector('button:first-child');
        const dropdownMenu = btnGroup.querySelector('.dropdown-menu');

        if (!mainButton || !dropdownMenu) return;

        const scannerName = mainButton.textContent.toLowerCase();
        let hasVisibleStrategies = false;

        // Vérifier items dropdown
        const dropdownItems = dropdownMenu.querySelectorAll('li a.dropdown-item:not(.text-info)');
        dropdownItems.forEach(item => {
            const strategyText = item.textContent.toLowerCase();

            if (query === '' || scannerName.includes(query) || strategyText.includes(query)) {
                item.parentElement.style.display = '';
                hasVisibleStrategies = true;
            } else {
                item.parentElement.style.display = 'none';
            }
        });

        // Masquer scanner si aucune correspondance
        if (query === '' || scannerName.includes(query) || hasVisibleStrategies) {
            col.style.display = '';
        } else {
            col.style.display = 'none';
        }
    });
}

// Charger les boutons au démarrage
document.addEventListener('DOMContentLoaded', () => {
    loadScannerButtons();
    checkTorStatus();
    setInterval(checkTorStatus, 30000);

    // Attacher filtrage
    document.getElementById('search-filter').addEventListener('input', filterStrategies);
});