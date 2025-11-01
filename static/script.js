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

    // Récupérer IP ranges
    const ipRangesInput = document.getElementById('ip-ranges-input').value.trim();

    console.log(`Envoi de start_scan pour ${scannerType} avec stratégie ${strategy}, ports ${portsToScan}, IP ranges ${ipRangesInput}`);

    // Construire URL avec paramètres
    let url = `/scan/start/${scannerType}/${strategy}?ports=${encodeURIComponent(portsToScan)}`;
    if (ipRangesInput) {
        url += `&ip_ranges=${encodeURIComponent(ipRangesInput)}`;
    }

    fetch(url)
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

            scanner.strategies.forEach(strategyObj => {
                const item = document.createElement('li');
                const link = document.createElement('a');
                link.className = 'dropdown-item';
                link.href = '#';

                // Support ancien format (string) et nouveau format (object)
                const strategyName = strategyObj.name || strategyObj;
                const complexity = Math.min(strategyObj.complexity || 1, 3); // Max 3
                const strategyType = strategyObj.type || 'basic';

                // Afficher étoiles de complexité (0-3)
                const stars = complexity > 0 ? '⭐'.repeat(complexity) : '○';

                // Badge type avec couleur
                const typeColors = {
                    'basic': 'secondary',
                    'advanced': 'primary',
                    'geo': 'warning',
                    'realtime': 'info',
                    'anti-detection': 'danger',
                    'ml-evasion': 'success',
                    'behavioral': 'info',
                    'anti-forensic': 'dark',
                    'contextual': 'secondary',
                    'emerging': 'warning',
                    'exotic': 'danger',
                    'stealth': 'primary',
                    'reconnaissance': 'secondary',
                    'vulnerability': 'danger',
                    'authenticated': 'warning'
                };
                const badgeColor = typeColors[strategyType] || 'secondary';

                link.innerHTML = `
                    <span style="float: right; display: flex; align-items: center; gap: 5px;">
                        <span class="badge bg-${badgeColor}" style="font-size: 0.6rem;">${strategyType}</span>
                        <span style="font-size: 0.75rem; opacity: 0.8;">${stars}</span>
                    </span>
                    ${strategyName}
                `;

                link.onclick = (e) => {
                    e.preventDefault();
                    selectedStrategies[scanner.name] = strategyName;
                    mainButton.textContent = `Démarrer ${scanner.name.charAt(0).toUpperCase() + scanner.name.slice(1)} (${strategyName})`;
                    console.log(`Stratégie sélectionnée pour ${scanner.name} : ${strategyName}`);
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
                const firstStrategy = scanner.strategies[0];
                const firstStrategyName = firstStrategy.name || firstStrategy;
                selectedStrategies[scanner.name] = firstStrategyName;
                mainButton.textContent = `Démarrer ${scanner.name.charAt(0).toUpperCase() + scanner.name.slice(1)} (${firstStrategyName})`;
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
        data.ports.forEach(portEntry => {
            const li = document.createElement('li');
            const a = document.createElement('a');
            a.className = 'dropdown-item';
            a.href = '#';
            const label = portEntry.label || portEntry.value || portEntry;
            const value = portEntry.value || portEntry;
            a.textContent = label;
            a.onclick = (e) => {
                e.preventDefault();
                selectedPorts = value;
                originalPortsTemplate = value;
                portsNavText.textContent = `Ports: ${label}`;
                console.log(`Ports sélectionnés : ${value}`);
            };
            li.appendChild(a);
            portsList.appendChild(li);
        });
        if (data.ports.length > 0) {
            const firstEntry = data.ports[0];
            const firstValue = firstEntry.value || firstEntry;
            const firstLabel = firstEntry.label || firstEntry;
            selectedPorts = firstValue;
            originalPortsTemplate = firstValue;
            portsNavText.textContent = `Ports: ${firstLabel}`;
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

// Fonctions pour la documentation
function loadDocList() {
    fetch('/api/docs/list')
        .then(response => response.json())
        .then(files => {
            const docList = document.getElementById('doc-list-nav');
            docList.innerHTML = '';
            files.forEach(file => {
                const li = document.createElement('li');
                const a = document.createElement('a');
                a.className = 'dropdown-item';
                a.href = '#';
                a.textContent = file.replace('.md', '').replace(/-/g, ' ');
                a.onclick = (e) => {
                    e.preventDefault();
                    showDoc(file);
                };
                li.appendChild(a);
                docList.appendChild(li);
            });
        })
        .catch(error => {
            console.error('Erreur chargement doc list:', error);
            document.getElementById('doc-list-nav').innerHTML = '<li><a class="dropdown-item" href="#">Erreur</a></li>';
        });
}

function showDoc(filename) {
    fetch(`/api/docs/content/${filename}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert('Erreur: ' + data.error);
                return;
            }
            document.getElementById('docModalLabel').textContent = data.title.replace('.md', '').replace(/-/g, ' ');
            const modalBody = document.getElementById('doc-modal-body');
            modalBody.innerHTML = marked.parse(data.content);
            const docModal = new bootstrap.Modal(document.getElementById('docModal'));
            docModal.show();
        })
        .catch(error => {
            console.error('Erreur chargement doc content:', error);
            alert('Erreur de chargement du document.');
        });
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

// Charger IP_RANGES depuis .env et pré-remplir
fetch('/api/ip-ranges')
    .then(response => response.json())
    .then(data => {
        if (data.ip_ranges) {
            document.getElementById('ip-ranges-input').placeholder = data.ip_ranges;
        }
    })
    .catch(error => console.error('Erreur chargement IP ranges:', error));

// Charger les boutons au démarrage
document.addEventListener('DOMContentLoaded', () => {
    loadScannerButtons();
    checkTorStatus();
    loadDocList(); // Charger la liste des documents
    setInterval(checkTorStatus, 30000);

    // Attacher filtrage
    document.getElementById('search-filter').addEventListener('input', filterStrategies);
});