// PCAP Editor functionality
let pcapCurrentFile = null;
let pcapPackets = [];
let pcapSelectedIndices = new Set();
let pcapDeletedIndices = new Set();

function showPcapEditor() {
    const modal = new bootstrap.Modal(document.getElementById('pcapEditorModal'));
    modal.show();
    loadPcapExistingFiles();
}

function loadPcapExistingFiles() {
    fetch('/api/pcap/list')
        .then(r => r.json())
        .then(data => {
            const container = document.getElementById('pcap-existing-files');
            if (data.files.length === 0) {
                container.innerHTML = '<p class="text-muted">No files found</p>';
                return;
            }
            container.innerHTML = data.files.map(f => `
                <div class="d-flex justify-content-between align-items-center mb-2 p-2 border rounded"
                     style="cursor: pointer;"
                     onclick="loadPcapExistingFile('${f.filename}')">
                    <div>
                        <div class="fw-bold">${f.filename}</div>
                        <small class="text-muted">${(f.size / 1024).toFixed(1)} KB</small>
                    </div>
                    <span class="text-primary">👁️</span>
                </div>
            `).join('');
        });
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
        })
        .catch(err => {
            document.getElementById('pcap-status').className = 'alert alert-danger';
            document.getElementById('pcap-status').textContent = 'Load failed: ' + err;
            console.error('Load error:', err);
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

        return `
            <tr class="${classes.join(' ')}" data-index="${i}">
                <td onclick="togglePcapPacket(${i})">${i}</td>
                <td onclick="togglePcapPacket(${i})" style="font-family: monospace; font-size: 0.85rem;">${pkt.layers || 'Unknown'}</td>
                <td onclick="togglePcapPacket(${i})" style="font-size: 0.9rem;">${pkt.summary}</td>
                <td onclick="togglePcapPacket(${i})">${pkt.length}</td>
                <td onclick="togglePcapPacket(${i})">${new Date(pkt.time * 1000).toLocaleTimeString()}</td>
                <td><button class="btn btn-sm btn-outline-secondary" onclick="showPcapHex(${i}); event.stopPropagation();">📄</button></td>
            </tr>
        `;
    }).join('');
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
        const hexLine = pkt.hex.substring(i, i + 32).match(/.{1,2}/g).join(' ');
        formatted += `${offset}: ${hexLine}\n`;
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
