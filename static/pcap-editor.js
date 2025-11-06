// PCAP Editor functionality
let pcapCurrentFile = null;
let pcapPackets = [];
let pcapSelectedIndices = new Set();
let pcapDeletedIndices = new Set();
let pcapIpCache = {}; // Cache des informations IP enrichies
let pcapFilesList = []; // Liste complète des fichiers PCAP avec métadonnées
let pcapFilesMetadata = {}; // Métadonnées IP pour chaque fichier

function showPcapEditor() {
    const modal = new bootstrap.Modal(document.getElementById('pcapEditorModal'));
    modal.show();
    loadPcapExistingFiles();
}

function loadPcapExistingFiles() {
    fetch('/api/pcap/list')
        .then(r => r.json())
        .then(data => {
            pcapFilesList = data.files;

            // Charger les métadonnées IP pour chaque fichier
            const metadataPromises = pcapFilesList.map(f =>
                fetch(`/api/pcap/ip-cache/${encodeURIComponent(f.filename)}`)
                    .then(r => r.ok ? r.json() : {})
                    .then(meta => {
                        pcapFilesMetadata[f.filename] = meta;
                        return meta;
                    })
                    .catch(() => ({}))
            );

            Promise.all(metadataPromises).then(() => {
                renderPcapFilesList(pcapFilesList);
            });
        });
}

function renderPcapFilesList(files, searchTerm = '') {
    const container = document.getElementById('pcap-existing-files');

    if (files.length === 0) {
        container.innerHTML = '<p class="text-muted">No files found</p>';
        return;
    }

    container.innerHTML = files.map(f => {
        const metadata = pcapFilesMetadata[f.filename] || {};
        const ipCount = Object.keys(metadata).length;

        // Construire badges de métadonnées
        let badges = '';
        if (ipCount > 0) {
            badges += `<span class="badge bg-info pcap-search-badge me-1">${ipCount} IPs</span>`;

            // Compter pays uniques
            const countries = new Set(Object.values(metadata).map(m => m.country).filter(Boolean));
            if (countries.size > 0) {
                badges += `<span class="badge bg-success pcap-search-badge me-1">${countries.size} countries</span>`;
            }

            // Compter ports uniques
            const allPorts = new Set();
            Object.values(metadata).forEach(m => {
                if (m.ports) {
                    m.ports.forEach(p => allPorts.add(p));
                }
            });
            if (allPorts.size > 0) {
                badges += `<span class="badge bg-primary pcap-search-badge me-1">${allPorts.size} ports</span>`;
            }
        }

        return `
            <div class="pcap-file-item d-flex justify-content-between align-items-center mb-2 p-2 border rounded"
                 style="cursor: pointer;"
                 onclick="loadPcapExistingFile('${f.filename}')"
                 data-filename="${f.filename}">
                <div class="flex-grow-1">
                    <div class="fw-bold">${f.filename}</div>
                    <small class="text-muted">${(f.size / 1024).toFixed(1)} KB</small>
                    ${badges ? `<div class="mt-1">${badges}</div>` : ''}
                </div>
                <span class="text-primary">👁️</span>
            </div>
        `;
    }).join('');
}

function searchPcapFiles() {
    const searchTerm = document.getElementById('pcap-search-input').value.toLowerCase().trim();

    if (!searchTerm) {
        renderPcapFilesList(pcapFilesList);
        document.getElementById('pcap-search-results').textContent = '';
        return;
    }

    const results = [];

    pcapFilesList.forEach(file => {
        let matchReasons = [];
        let score = 0;

        // Recherche dans le nom de fichier
        if (file.filename.toLowerCase().includes(searchTerm)) {
            matchReasons.push('filename');
            score += 10;
        }

        // Recherche dans les métadonnées IP
        const metadata = pcapFilesMetadata[file.filename] || {};

        for (const [ip, info] of Object.entries(metadata)) {
            // Recherche par IP
            if (ip.includes(searchTerm)) {
                matchReasons.push(`IP: ${ip}`);
                score += 5;
            }

            // Recherche par hostname
            if (info.hostname && info.hostname.toLowerCase().includes(searchTerm)) {
                matchReasons.push(`host: ${info.hostname}`);
                score += 8;
            }

            // Recherche par pays
            if (info.country && info.country.toLowerCase().includes(searchTerm)) {
                matchReasons.push(`country: ${info.country}`);
                score += 3;
            }

            // Recherche par ville
            if (info.city && info.city.toLowerCase().includes(searchTerm)) {
                matchReasons.push(`city: ${info.city}`);
                score += 3;
            }

            // Recherche par ISP
            if (info.isp && info.isp.toLowerCase().includes(searchTerm)) {
                matchReasons.push(`ISP: ${info.isp}`);
                score += 6;
            }

            // Recherche par organisation
            if (info.org && info.org.toLowerCase().includes(searchTerm)) {
                matchReasons.push(`org: ${info.org}`);
                score += 6;
            }

            // Recherche par port
            if (info.ports && info.ports.some(p => String(p).includes(searchTerm))) {
                const matchingPorts = info.ports.filter(p => String(p).includes(searchTerm));
                matchReasons.push(`port: ${matchingPorts.join(',')}`);
                score += 7;
            }
        }

        if (matchReasons.length > 0) {
            results.push({
                file: file,
                reasons: matchReasons,
                score: score
            });
        }
    });

    // Trier par score décroissant
    results.sort((a, b) => b.score - a.score);

    // Afficher résultats
    if (results.length === 0) {
        document.getElementById('pcap-search-results').textContent = 'No matches found';
        document.getElementById('pcap-existing-files').innerHTML = '<p class="text-muted">No matches</p>';
        return;
    }

    document.getElementById('pcap-search-results').textContent = `Found ${results.length} match(es)`;

    // Render avec highlight
    const container = document.getElementById('pcap-existing-files');
    container.innerHTML = results.map(result => {
        const f = result.file;
        const metadata = pcapFilesMetadata[f.filename] || {};
        const ipCount = Object.keys(metadata).length;

        // Limiter les raisons affichées
        const reasonsText = result.reasons.slice(0, 3).join(', ');
        const moreText = result.reasons.length > 3 ? ` +${result.reasons.length - 3} more` : '';

        let badges = `<span class="badge bg-warning pcap-search-badge me-1">Match: ${reasonsText}${moreText}</span>`;
        if (ipCount > 0) {
            badges += `<span class="badge bg-info pcap-search-badge me-1">${ipCount} IPs</span>`;
        }

        return `
            <div class="pcap-file-item pcap-search-match d-flex justify-content-between align-items-center mb-2 p-2 border rounded"
                 style="cursor: pointer;"
                 onclick="loadPcapExistingFile('${f.filename}')"
                 data-filename="${f.filename}">
                <div class="flex-grow-1">
                    <div class="fw-bold">${f.filename}</div>
                    <small class="text-muted">${(f.size / 1024).toFixed(1)} KB</small>
                    <div class="mt-1">${badges}</div>
                </div>
                <span class="text-primary">👁️</span>
            </div>
        `;
    }).join('');
}

function loadPcapExistingFile(filename) {
    document.getElementById('pcap-status').textContent = 'Loading ' + filename + '...';
    document.getElementById('pcap-status').className = 'alert alert-info';

    fetch('/api/pcap/load/' + encodeURIComponent(filename))
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                document.getElementById('pcap-status').className = 'alert alert-danger';
                document.getElementById('pcap-status').textContent = 'Error: ' + data.error;
                return;
            }

            pcapCurrentFile = data;
            pcapPackets = data.packets;
            pcapSelectedIndices.clear();
            pcapDeletedIndices.clear();

            renderPcapPackets();
            document.getElementById('pcap-status').className = 'alert alert-success';
            document.getElementById('pcap-status').textContent = `Loaded ${data.packet_count} packets from ${data.filename}`;
            document.getElementById('pcap-packets-table-container').style.display = 'block';
            document.getElementById('pcap-save-section').style.display = 'block';
            document.getElementById('pcap-save-filename').value = data.filename.replace(/\.(pcap|pcapng)$/, '_edited.pcap');
            document.getElementById('pcap-select-all-btn').disabled = false;
            document.getElementById('pcap-invert-btn').disabled = false;
            document.getElementById('pcap-delete-btn').disabled = false;
            updatePcapCounts();
            console.log('File loaded successfully, packets:', pcapPackets.length);

            // Charger le cache IP et enrichir
            loadAndEnrichIPs(data.filename, data.ip_port_summary || null);
        })
        .catch(err => {
            document.getElementById('pcap-status').className = 'alert alert-danger';
            document.getElementById('pcap-status').textContent = 'Load failed: ' + err;
            console.error('Load error:', err);
        });
}

function extractIPsFromPackets() {
    const ips = new Set();
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

    pcapPackets.forEach(pkt => {
        // Extraire IPs depuis layers et summary
        const text = (pkt.layers || '') + ' ' + (pkt.summary || '');
        const matches = text.match(ipRegex);
        if (matches) {
            matches.forEach(ip => ips.add(ip));
        }
    });

    return Array.from(ips);
}

function loadAndEnrichIPs(filename, ipPortSummary = null) {
    const ips = extractIPsFromPackets();
    if (ips.length === 0) {
        console.log('No IPs found in packets');
        return;
    }

    console.log('Found IPs:', ips);

    // Tenter de charger le cache JSON existant
    fetch(`/api/pcap/ip-cache/${encodeURIComponent(filename)}`)
        .then(r => {
            if (r.ok) {
                return r.json();
            }
            return null;
        })
        .then(cached => {
            if (cached) {
                console.log('Loaded IP cache from JSON');
                pcapIpCache = cached;
                renderPcapPackets(); // Re-render avec les IPs enrichies
            }

            // Enrichir les IPs manquantes en background
            const missingIps = ips.filter(ip => !cached || !cached[ip]);
            if (missingIps.length > 0) {
                console.log('Enriching missing IPs:', missingIps.length);
                enrichIPs(missingIps, filename, ipPortSummary);
            }
        })
        .catch(() => {
            // Pas de cache, enrichir toutes les IPs
            console.log('No cache found, enriching all IPs');
            enrichIPs(ips, filename, ipPortSummary);
        });
}

function enrichIPs(ips, filename, ipPortSummary = null) {
    // Utiliser les ports du backend si disponibles, sinon extraire avec regex
    let ipPortDataJSON = {};

    if (ipPortSummary) {
        // Utiliser directement les données du backend
        console.log('Using backend ip_port_summary');
        ipPortDataJSON = ipPortSummary;
    } else {
        // Fallback : extraire les ports associés aux IPs depuis les paquets avec regex
        console.log('Extracting ports with regex (fallback)');
        const ipPortData = {};
        const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
        const portRegex = /(?:TCP|UDP)\s+(\d+)\s+>\s+(\d+)/g;

        pcapPackets.forEach(pkt => {
            const text = (pkt.layers || '') + ' ' + (pkt.summary || '');
            const ipMatches = text.match(ipRegex);
            const portMatches = [...text.matchAll(portRegex)];

            if (ipMatches && portMatches.length > 0) {
                ipMatches.forEach(ip => {
                    if (!ipPortData[ip]) {
                        ipPortData[ip] = {ports: new Set(), ips_contacted: new Set()};
                    }
                    portMatches.forEach(match => {
                        const srcPort = parseInt(match[1]);
                        const dstPort = parseInt(match[2]);
                        ipPortData[ip].ports.add(srcPort);
                        ipPortData[ip].ports.add(dstPort);
                    });
                });
            }
        });

        // Convertir sets en arrays pour JSON
        for (const [ip, data] of Object.entries(ipPortData)) {
            ipPortDataJSON[ip] = {
                ports: Array.from(data.ports).sort((a, b) => a - b),
                ips_contacted: Array.from(data.ips_contacted)
            };
        }
    }

    fetch('/api/pcap/enrich-ips', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            ips: ips,
            filename: filename,
            ip_port_data: ipPortDataJSON
        })
    })
    .then(r => r.json())
    .then(data => {
        console.log('IP enrichment complete:', Object.keys(data.enriched).length);
        Object.assign(pcapIpCache, data.enriched);
        renderPcapPackets(); // Re-render avec les nouvelles infos
    })
    .catch(err => console.error('IP enrichment failed:', err));
}

function wrapIPsInText(text) {
    if (!text) return text;

    const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

    return text.replace(ipRegex, (ip) => {
        const info = pcapIpCache[ip];
        if (!info) {
            return `<span class="ip-address ip-loading" data-ip="${ip}">${ip}</span>`;
        }

        // Construire le tooltip
        let tooltip = `<strong>${ip}</strong><br>`;
        if (info.ports && info.ports.length > 0) {
            const portsStr = info.ports.slice(0, 10).join(', ');
            const moreStr = info.ports.length > 10 ? ` +${info.ports.length - 10} more` : '';
            tooltip += `🔌 Ports: ${portsStr}${moreStr}<br>`;
        }
        if (info.hostname) tooltip += `🏠 ${info.hostname}<br>`;
        if (info.country) tooltip += `🌍 ${info.city || ''}, ${info.country} (${info.countryCode})<br>`;
        if (info.isp) tooltip += `🏢 ${info.isp}<br>`;
        if (info.org) tooltip += `🏛️ ${info.org}<br>`;
        if (info.as) tooltip += `📡 ${info.as}<br>`;
        if (info.is_private) tooltip += `🔒 Private IP<br>`;
        if (info.is_loopback) tooltip += `🔁 Loopback<br>`;
        if (info.lat && info.lon) tooltip += `📍 ${info.lat}, ${info.lon}`;

        return `<span class="ip-address" data-bs-toggle="tooltip" data-bs-html="true" title="${tooltip}" data-ip="${ip}">${ip}</span>`;
    });
}

function uploadPcapFile() {
    const fileInput = document.getElementById('pcap-file-input');
    if (!fileInput.files.length) {
        alert('Please select a file');
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    document.getElementById('pcap-status').textContent = 'Uploading...';

    fetch('/api/pcap/upload', {
        method: 'POST',
        body: formData
    })
    .then(r => r.json())
    .then(data => {
        if (data.error) {
            document.getElementById('pcap-status').className = 'alert alert-danger';
            document.getElementById('pcap-status').textContent = 'Error: ' + data.error;
            return;
        }

        pcapCurrentFile = data;
        pcapPackets = data.packets;
        pcapSelectedIndices.clear();
        pcapDeletedIndices.clear();

        renderPcapPackets();
        document.getElementById('pcap-status').className = 'alert alert-success';
        document.getElementById('pcap-status').textContent = `Loaded ${data.packet_count} packets from ${data.filename}`;
        document.getElementById('pcap-packets-table-container').style.display = 'block';
        document.getElementById('pcap-save-section').style.display = 'block';
        document.getElementById('pcap-save-filename').value = data.filename.replace(/\.(pcap|pcapng)$/, '_edited.pcap');
        document.getElementById('pcap-select-all-btn').disabled = false;
        document.getElementById('pcap-invert-btn').disabled = false;
        document.getElementById('pcap-delete-btn').disabled = false;
        updatePcapCounts();

        // Charger le cache IP et enrichir
        loadAndEnrichIPs(data.filename, data.ip_port_summary || null);
    })
    .catch(err => {
        document.getElementById('pcap-status').className = 'alert alert-danger';
        document.getElementById('pcap-status').textContent = 'Upload failed: ' + err;
    });
}

function renderPcapPackets() {
    const tbody = document.getElementById('pcap-packets-table');
    if (!pcapPackets || pcapPackets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No packets</td></tr>';
        return;
    }

    tbody.innerHTML = pcapPackets.map((pkt, i) => {
        const classes = ['pcap-packet-row'];
        if (pcapSelectedIndices.has(i)) classes.push('selected');
        if (pcapDeletedIndices.has(i)) classes.push('deleted');

        // Wrapper les IPs avec tooltips
        const layersWithIPs = wrapIPsInText(pkt.layers || 'Unknown');
        const summaryWithIPs = wrapIPsInText(pkt.summary);

        return `
            <tr class="${classes.join(' ')}" data-index="${i}">
                <td onclick="togglePcapPacket(${i})">${i}</td>
                <td onclick="togglePcapPacket(${i})" style="font-family: monospace; font-size: 0.85rem;">${layersWithIPs}</td>
                <td onclick="togglePcapPacket(${i})" style="font-size: 0.9rem;">${summaryWithIPs}</td>
                <td onclick="togglePcapPacket(${i})">${pkt.length}</td>
                <td onclick="togglePcapPacket(${i})">${new Date(pkt.time * 1000).toLocaleTimeString()}</td>
                <td><button class="btn btn-sm btn-outline-secondary" onclick="showPcapHex(${i}); event.stopPropagation();">📄</button></td>
            </tr>
        `;
    }).join('');

    // Initialiser les tooltips Bootstrap
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    [...tooltipTriggerList].map(el => new bootstrap.Tooltip(el));
}

function showPcapHex(index) {
    const pkt = pcapPackets[index];
    if (!pkt || !pkt.hex) {
        alert('No hex data available');
        return;
    }

    let formatted = '';
    for (let i = 0; i < pkt.hex.length; i += 32) {
        const offset = (i / 2).toString(16).padStart(4, '0');
        const hexBytes = pkt.hex.substring(i, i + 32).match(/.{1,2}/g) || [];

        // Formater hex en 2 groupes de 8 bytes
        const hex1 = hexBytes.slice(0, 8).join(' ').padEnd(23, ' ');
        const hex2 = hexBytes.slice(8, 16).join(' ').padEnd(23, ' ');

        // Convertir en ASCII
        let ascii = '';
        for (const hexByte of hexBytes) {
            const byte = parseInt(hexByte, 16);
            // Afficher le caractère si imprimable (32-126), sinon '.'
            if (byte >= 32 && byte <= 126) {
                ascii += String.fromCharCode(byte);
            } else {
                ascii += '.';
            }
        }

        formatted += `${offset}: ${hex1} ${hex2} |${ascii}|\n`;
    }

    document.getElementById('pcap-hex-content').textContent = formatted;
    const modal = new bootstrap.Modal(document.getElementById('pcapHexModal'));
    modal.show();
}

function togglePcapPacket(index) {
    if (pcapDeletedIndices.has(index)) return;

    if (pcapSelectedIndices.has(index)) {
        pcapSelectedIndices.delete(index);
    } else {
        pcapSelectedIndices.add(index);
    }
    renderPcapPackets();
    updatePcapCounts();
}

function pcapSelectAll() {
    console.log('pcapSelectAll() called, packets:', pcapPackets.length, 'deleted:', pcapDeletedIndices.size);
    pcapSelectedIndices.clear();
    for (let i = 0; i < pcapPackets.length; i++) {
        if (!pcapDeletedIndices.has(i)) {
            pcapSelectedIndices.add(i);
        }
    }
    console.log('Selected:', pcapSelectedIndices.size);
    renderPcapPackets();
    updatePcapCounts();
}

function pcapInvertSelection() {
    console.log('pcapInvertSelection() called');
    const newSelected = new Set();
    for (let i = 0; i < pcapPackets.length; i++) {
        if (!pcapDeletedIndices.has(i) && !pcapSelectedIndices.has(i)) {
            newSelected.add(i);
        }
    }
    pcapSelectedIndices = newSelected;
    console.log('Inverted to:', pcapSelectedIndices.size);
    renderPcapPackets();
    updatePcapCounts();
}

function pcapDeleteSelected() {
    console.log('pcapDeleteSelected() called, selected:', pcapSelectedIndices.size);
    if (pcapSelectedIndices.size === 0) {
        alert('No packets selected');
        return;
    }

    const confirmMsg = `Delete ${pcapSelectedIndices.size} packet(s)?`;
    if (!confirm(confirmMsg)) return;

    pcapSelectedIndices.forEach(i => pcapDeletedIndices.add(i));
    console.log('Deleted, total deleted now:', pcapDeletedIndices.size);
    pcapSelectedIndices.clear();
    renderPcapPackets();
    updatePcapCounts();
}

function updatePcapCounts() {
    const remaining = pcapPackets.length - pcapDeletedIndices.size;
    document.getElementById('pcap-selected-count').textContent = pcapSelectedIndices.size;
    document.getElementById('pcap-total-count').textContent = remaining;

    const statusEl = document.getElementById('pcap-selection-status');
    if (pcapPackets.length === 0) {
        statusEl.textContent = 'No packets loaded';
    } else {
        statusEl.textContent = `Selected: ${pcapSelectedIndices.size} | Deleted: ${pcapDeletedIndices.size} | Total: ${pcapPackets.length}`;
        statusEl.className = pcapSelectedIndices.size > 0 ? 'text-success fw-bold' : 'text-muted';
    }
}

function savePcapFile() {
    const filename = document.getElementById('pcap-save-filename').value.trim();
    if (!filename) {
        alert('Please enter a filename');
        return;
    }

    const keepIndices = [];
    for (let i = 0; i < pcapPackets.length; i++) {
        if (!pcapDeletedIndices.has(i)) {
            keepIndices.push(i);
        }
    }

    fetch('/api/pcap/save', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            temp_path: pcapCurrentFile.temp_path,
            filename: filename,
            selected_indices: keepIndices
        })
    })
    .then(r => r.json())
    .then(data => {
        if (data.error) {
            alert('Error: ' + data.error);
            return;
        }
        alert(`Saved ${data.packet_count} packets to ${data.filename}`);
        loadPcapExistingFiles();
    })
    .catch(err => alert('Save failed: ' + err));
}
