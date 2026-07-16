// Aegis NetSec Dashboard Javascript Logic

// Chart Instances
let protocolChartInstance = null;
let connectionChartInstance = null;
let timelineChartInstance = null;
let alertCategoryChartInstance = null;

// Dashboard State
let currentData = null;
let alertPage = 1;
const alertsPerPage = 10;
let filteredAlerts = [];

document.addEventListener('DOMContentLoaded', () => {
    initUploadDropzone();
    initTabNavigation();
    initAlertFilters();
    initExportButtons();
    
    // Check if Scapy is ready
    checkEngineStatus();
});

// Server engine diagnostics check
function checkEngineStatus() {
    // Just a placeholder since the app is running
    const statusBox = document.getElementById('scapy-status');
    if (statusBox) {
        statusBox.innerHTML = '<i class="fa-solid fa-circle-check text-green"></i> Scapy Engine: Active';
    }
}

// Upload & Drag-and-Drop Handlers
function initUploadDropzone() {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');
    const btnRemove = document.getElementById('btn-remove-file');
    
    // Trigger file dialog
    dropzone.addEventListener('click', (e) => {
        if (e.target.tagName !== 'LABEL' && e.target.tagName !== 'BUTTON') {
            fileInput.click();
        }
    });
    
    fileInput.addEventListener('change', (e) => {
        if (fileInput.files.length > 0) {
            handleSelectedFile(fileInput.files[0]);
        }
    });
    
    // Drag events
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add('dragover');
        }, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove('dragover');
        }, false);
    });
    
    dropzone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            fileInput.files = files;
            handleSelectedFile(files[0]);
        }
    });
    
    // Remove file
    btnRemove.addEventListener('click', (e) => {
        e.stopPropagation();
        resetUploadState();
    });
}

function handleSelectedFile(file) {
    const nameEl = document.getElementById('selected-file-name');
    const sizeEl = document.getElementById('selected-file-size');
    const fileInfo = document.getElementById('file-info-container');
    const dropzoneText = document.querySelector('.dropzone-text');
    const fileHint = document.querySelector('.file-format-hint');
    const uploadBtn = document.querySelector('.btn-upload');
    const uploadIcon = document.querySelector('.upload-icon');
    
    nameEl.textContent = file.name;
    sizeEl.textContent = formatBytes(file.size);
    
    // Hide upload icon & label details to display file selection
    uploadIcon.style.display = 'none';
    dropzoneText.style.display = 'none';
    fileHint.style.display = 'none';
    uploadBtn.style.display = 'none';
    fileInfo.style.display = 'flex';
    
    // Upload immediately
    uploadFileToServer(file);
}

function resetUploadState() {
    const fileInput = document.getElementById('file-input');
    const fileInfo = document.getElementById('file-info-container');
    const dropzoneText = document.querySelector('.dropzone-text');
    const fileHint = document.querySelector('.file-format-hint');
    const uploadBtn = document.querySelector('.btn-upload');
    const uploadIcon = document.querySelector('.upload-icon');
    
    fileInput.value = '';
    fileInfo.style.display = 'none';
    
    uploadIcon.style.display = 'block';
    dropzoneText.style.display = 'block';
    fileHint.style.display = 'block';
    uploadBtn.style.display = 'inline-flex';
}

// Upload file request
function uploadFileToServer(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    const loadingOverlay = document.getElementById('loading-overlay');
    loadingOverlay.style.display = 'flex';
    
    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { throw new Error(err.error || 'Gagal mengunggah file'); });
        }
        return response.json();
    })
    .then(data => {
        showToast('Analisis Berhasil!', 'File berhasil dianalisis.', 'success');
        renderDashboard(data);
    })
    .catch(err => {
        console.error(err);
        showToast('Terjadi Kesalahan', err.message, 'error');
        resetUploadState();
    })
    .finally(() => {
        loadingOverlay.style.display = 'none';
    });
}

// Load mock test file directly from server
function loadMockFile(filename) {
    const loadingOverlay = document.getElementById('loading-overlay');
    loadingOverlay.style.display = 'flex';
    
    fetch(`/load_mock?file=${filename}`)
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { throw new Error(err.error || 'Gagal memuat file simulasi'); });
        }
        return response.json();
    })
    .then(data => {
        showToast('Simulasi Berhasil!', `Memuat data uji ${filename}.`, 'success');
        // Simulate file UI selection
        const nameEl = document.getElementById('selected-file-name');
        const sizeEl = document.getElementById('selected-file-size');
        const fileInfo = document.getElementById('file-info-container');
        const dropzoneText = document.querySelector('.dropzone-text');
        const fileHint = document.querySelector('.file-format-hint');
        const uploadBtn = document.querySelector('.btn-upload');
        const uploadIcon = document.querySelector('.upload-icon');
        
        nameEl.textContent = filename;
        sizeEl.textContent = filename.endsWith('.pcap') ? "14.5 KB" : "8.2 KB";
        
        uploadIcon.style.display = 'none';
        dropzoneText.style.display = 'none';
        fileHint.style.display = 'none';
        uploadBtn.style.display = 'none';
        fileInfo.style.display = 'flex';
        
        renderDashboard(data);
    })
    .catch(err => {
        console.error(err);
        showToast('Gagal Memuat Data', err.message, 'error');
    })
    .finally(() => {
        loadingOverlay.style.display = 'none';
    });
}

// Render Dashboard Data
function renderDashboard(data) {
    currentData = data;
    
    // Toggle displays
    document.getElementById('empty-state').style.display = 'none';
    document.getElementById('dashboard-content').style.display = 'flex';
    
    const activeFileDisplay = document.getElementById('active-file-display');
    const badgeFile = document.getElementById('file-badge');
    const activeFilename = document.getElementById('active-filename');
    
    activeFileDisplay.style.display = 'flex';
    activeFilename.textContent = data.filename;
    
    // Enable Exports
    document.getElementById('btn-export-csv').disabled = false;
    document.getElementById('btn-export-pdf').disabled = false;
    
    const isPcap = data.type === 'pcap';
    
    if (isPcap) {
        badgeFile.textContent = 'PCAP';
        badgeFile.className = 'badge badge-file';
        document.getElementById('nav-alerts-tab').style.display = 'none';
        
        // Update labels
        document.getElementById('metric-label-1').textContent = 'Total Paket';
        document.getElementById('metric-label-2').textContent = 'Total Volume';
        document.getElementById('metric-label-3').textContent = 'Durasi';
        document.getElementById('metric-label-4').textContent = 'Temuan Ancaman (IoC)';
        
        // Update values
        document.getElementById('metric-1').textContent = formatNumber(data.metrics.total_packets);
        document.getElementById('metric-2').textContent = formatBytes(data.metrics.total_bytes);
        document.getElementById('metric-3').textContent = formatDuration(data.metrics.duration_seconds);
        
        const iocCount = data.metrics.ioc_count;
        const iocMetric = document.getElementById('metric-4');
        iocMetric.textContent = iocCount;
        if (iocCount > 0) {
            iocMetric.className = 'metric-value text-red';
        } else {
            iocMetric.className = 'metric-value';
        }
        
        // Update Chart titles
        document.getElementById('chart-title-1').textContent = 'Distribusi Protokol Jaringan';
        document.getElementById('chart-title-2').textContent = 'Koneksi Paling Aktif (Berdasarkan Bytes)';
        
        // Switch to overview tab automatically (renders overview charts)
        switchTab('overview');
        
    } else {
        // Suricata log
        badgeFile.textContent = 'SURICATA';
        badgeFile.className = 'badge badge-file bg-red';
        document.getElementById('nav-alerts-tab').style.display = 'block';
        
        // Update labels
        document.getElementById('metric-label-1').textContent = 'Total Alert';
        document.getElementById('metric-label-2').textContent = 'Aturan Unik';
        document.getElementById('metric-label-3').textContent = 'Kategori';
        document.getElementById('metric-label-4').textContent = 'Temuan Ancaman (IoC)';
        
        // Update values
        document.getElementById('metric-1').textContent = formatNumber(data.metrics.total_alerts);
        document.getElementById('metric-2').textContent = formatNumber(data.metrics.unique_signatures);
        
        // Show severity breakdown on duration card or signature count
        document.getElementById('metric-3').textContent = `${data.metrics.severity_1} / ${data.metrics.severity_2} / ${data.metrics.severity_3}`;
        document.getElementById('metric-label-3').innerHTML = 'S1 / S2 / S3 Alerts';
        
        const iocCount = data.metrics.ioc_count;
        const iocMetric = document.getElementById('metric-4');
        iocMetric.textContent = iocCount;
        if (iocCount > 0) {
            iocMetric.className = 'metric-value text-red';
        } else {
            iocMetric.className = 'metric-value';
        }
        
        // Update Chart titles based on whether alerts were found
        if (data.has_alerts) {
            document.getElementById('chart-title-1').textContent = 'Distribusi Tingkat Bahaya (Severity)';
            document.getElementById('chart-title-2').textContent = 'Aturan Keamanan Paling Sering Terpicu (Top 10)';
        } else {
            document.getElementById('chart-title-1').textContent = 'Distribusi Tipe Event Jaringan';
            document.getElementById('chart-title-2').textContent = 'Koneksi Paling Aktif (Berdasarkan Jumlah Event)';
        }
        
        switchTab('overview');
        
        // Alert tab specifics
        renderAlertsCategoryChart(data.connections);
        filteredAlerts = [...data.alerts];
        alertPage = 1;
        renderAlertsTable();
    }
    
    // Render IoC Table
    renderIoCTable(data.iocs);
}

// Chart: Protocol Distribution
function renderProtocolChart(dataList, type) {
    const wrapper = document.getElementById('protocolChart').parentElement;
    wrapper.innerHTML = '<canvas id="protocolChart"></canvas>';
    
    if (window.Chart) {
        const ctx = document.getElementById('protocolChart').getContext('2d');
        if (protocolChartInstance) {
            protocolChartInstance.destroy();
        }
        
        const labels = dataList.map(item => item.name);
        const dataValues = dataList.map(item => item.count);
        
        const colors = (type === 'packets' || type === 'events') 
            ? ['#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#ec4899', '#6366f1'] 
            : ['#ef4444', '#f59e0b', '#3b82f6'];
            
        protocolChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: dataValues,
                    backgroundColor: colors,
                    borderWidth: 1,
                    borderColor: 'rgba(255, 255, 255, 0.08)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#9aa2b5',
                            font: { family: 'Outfit', size: 12 }
                        }
                    }
                },
                cutout: '65%'
            }
        });
    } else {
        const colors = (type === 'packets' || type === 'events') 
            ? ['#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#ec4899', '#6366f1'] 
            : ['#ef4444', '#f59e0b', '#3b82f6'];
        renderSvgDoughnut(wrapper, dataList, colors);
    }
}

// Chart: Top Connections / Rules
function renderConnectionChart(dataList, type) {
    const wrapper = document.getElementById('connectionChart').parentElement;
    wrapper.innerHTML = '<canvas id="connectionChart"></canvas>';
    
    if (window.Chart) {
        const ctx = document.getElementById('connectionChart').getContext('2d');
        if (connectionChartInstance) {
            connectionChartInstance.destroy();
        }
        
        let labels, dataValues, labelName, barColor;
        
        if (type === 'bytes') {
            labels = dataList.map(item => `${item.source.substring(0,15)} -> ${item.destination.substring(0,15)}`);
            dataValues = dataList.map(item => item.bytes / 1024);
            labelName = 'Volume Lalu Lintas (KB)';
            barColor = 'rgba(6, 182, 212, 0.85)';
        } else if (type === 'events') {
            labels = dataList.map(item => `${item.source.substring(0,15)} -> ${item.destination.substring(0,15)}`);
            dataValues = dataList.map(item => item.count);
            labelName = 'Jumlah Event';
            barColor = 'rgba(16, 185, 129, 0.85)';
        } else {
            labels = dataList.map(item => item.name.length > 35 ? item.name.substring(0, 35) + '...' : item.name);
            dataValues = dataList.map(item => item.count);
            labelName = 'Jumlah Pemicu (Alert)';
            barColor = 'rgba(139, 92, 246, 0.85)';
        }
        
        connectionChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: labelName,
                    data: dataValues,
                    backgroundColor: barColor,
                    borderRadius: 4,
                    borderWidth: 0
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.04)' },
                        ticks: { color: '#626a7e', font: { family: 'Outfit' } }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#9aa2b5', font: { family: 'Outfit', size: 11 } }
                    }
                }
            }
        });
    } else {
        renderSvgBar(wrapper, dataList, type);
    }
}

// Chart: Timeline of Traffic / Alerts
function renderTimelineChart(dataList, fileType) {
    const wrapper = document.getElementById('timelineChart').parentElement;
    wrapper.innerHTML = '<canvas id="timelineChart"></canvas>';
    
    // Pad dataList if it has only 1 data point to render line chart beautifully
    let displayList = [...dataList];
    if (dataList.length === 1) {
        const singlePoint = dataList[0];
        const timeParts = singlePoint.time.split(':');
        if (timeParts.length === 3) {
            const h = parseInt(timeParts[0]);
            const m = parseInt(timeParts[1]);
            const s = parseInt(timeParts[2]);
            
            // 10s before
            const beforeDate = new Date();
            beforeDate.setHours(h, m, s - 10);
            const beforeTimeStr = beforeDate.toTimeString().split(' ')[0];
            
            // 10s after
            const afterDate = new Date();
            afterDate.setHours(h, m, s + 10);
            const afterTimeStr = afterDate.toTimeString().split(' ')[0];
            
            if (fileType === 'pcap') {
                displayList.unshift({ time: beforeTimeStr, packets: 0, bytes: 0 });
                displayList.push({ time: afterTimeStr, packets: 0, bytes: 0 });
            } else {
                displayList.unshift({ time: beforeTimeStr, count: 0 });
                displayList.push({ time: afterTimeStr, count: 0 });
            }
        }
    }
    
    if (window.Chart) {
        const ctx = document.getElementById('timelineChart').getContext('2d');
        if (timelineChartInstance) {
            timelineChartInstance.destroy();
        }
        
        const labels = displayList.map(item => item.time);
        let dataset;
        
        if (fileType === 'pcap') {
            const packetsData = displayList.map(item => item.packets);
            const bytesData = displayList.map(item => item.bytes / 1024);
            
            dataset = [
                {
                    label: 'Paket / Interval',
                    data: packetsData,
                    borderColor: '#8b5cf6',
                    backgroundColor: 'rgba(139, 92, 246, 0.08)',
                    fill: true,
                    tension: 0.3,
                    yAxisID: 'y',
                    pointRadius: 5,
                    pointHoverRadius: 7,
                    pointBackgroundColor: '#8b5cf6'
                },
                {
                    label: 'Volume (KB) / Interval',
                    data: bytesData,
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.04)',
                    fill: false,
                    tension: 0.3,
                    yAxisID: 'y1',
                    pointRadius: 5,
                    pointHoverRadius: 7,
                    pointBackgroundColor: '#06b6d4'
                }
            ];
        } else {
            const alertData = displayList.map(item => item.count);
            dataset = [
                {
                    label: 'Alert Frekuensi',
                    data: alertData,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.08)',
                    fill: true,
                    tension: 0.3,
                    yAxisID: 'y',
                    pointRadius: 5,
                    pointHoverRadius: 7,
                    pointBackgroundColor: '#ef4444'
                }
            ];
        }
        
        const scalesConfig = {
            x: {
                grid: { color: 'rgba(255, 255, 255, 0.04)' },
                ticks: { color: '#9aa2b5', font: { family: 'Outfit' } }
            },
            y: {
                position: 'left',
                grid: { color: 'rgba(255, 255, 255, 0.04)' },
                ticks: { color: '#9aa2b5', font: { family: 'Outfit' } },
                title: { display: true, text: 'Jumlah', color: '#9aa2b5' }
            }
        };
        
        if (fileType === 'pcap') {
            scalesConfig.y1 = {
                position: 'right',
                grid: { drawOnChartArea: false },
                ticks: { color: '#06b6d4', font: { family: 'Outfit' } },
                title: { display: true, text: 'KiloBytes (KB)', color: '#06b6d4' }
            };
        }
        
        timelineChartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: dataset
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#9aa2b5', font: { family: 'Outfit' } }
                    }
                },
                scales: scalesConfig
            }
        });
    } else {
        renderSvgTimeline(wrapper, displayList, fileType);
    }
}

// Chart: Suricata Alert Categories in Sidebar
function renderAlertsCategoryChart(dataList) {
    const wrapper = document.getElementById('alertCategoryChart').parentElement;
    wrapper.innerHTML = '<canvas id="alertCategoryChart"></canvas>';
    
    if (!dataList || dataList.length === 0 || (dataList.length > 0 && !dataList[0].name)) {
        wrapper.innerHTML = '<div class="no-data-msg">Tidak ada alert terdeteksi</div>';
        return;
    }
    
    if (window.Chart) {
        const ctx = document.getElementById('alertCategoryChart').getContext('2d');
        if (alertCategoryChartInstance) {
            alertCategoryChartInstance.destroy();
        }
        
        const topRules = dataList.slice(0, 5);
        const labels = topRules.map(item => item.name.length > 20 ? item.name.substring(0, 20) + '...' : item.name);
        const dataValues = topRules.map(item => item.count);
        
        alertCategoryChartInstance = new Chart(ctx, {
            type: 'polarArea',
            data: {
                labels: labels,
                datasets: [{
                    data: dataValues,
                    backgroundColor: [
                        'rgba(239, 68, 68, 0.7)',
                        'rgba(245, 158, 11, 0.7)',
                        'rgba(59, 130, 246, 0.7)',
                        'rgba(16, 185, 129, 0.7)',
                        'rgba(139, 92, 246, 0.7)'
                    ],
                    borderWidth: 1,
                    borderColor: 'rgba(255, 255, 255, 0.08)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    r: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        angleLines: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { display: false }
                    }
                }
            }
        });
    } else {
        const topRules = dataList.slice(0, 5);
        renderSvgDoughnut(wrapper, topRules, [
            'rgba(239, 68, 68, 0.8)',
            'rgba(245, 158, 11, 0.8)',
            'rgba(59, 130, 246, 0.8)',
            'rgba(16, 185, 129, 0.8)',
            'rgba(139, 92, 246, 0.8)'
        ]);
    }
}

// Helper: Render SVG Doughnut Chart
function renderSvgDoughnut(container, dataList, colors) {
    const total = dataList.reduce((sum, item) => sum + item.count, 0);
    if (total === 0) {
        container.innerHTML = '<div class="no-data-msg">Tidak ada data untuk diagram</div>';
        return;
    }
    
    let cumulativePercent = 0;
    let svgContent = `<svg viewBox="0 0 100 100" width="100%" height="100%">`;
    
    dataList.forEach((item, idx) => {
        const percent = item.count / total;
        const color = colors[idx % colors.length];
        
        const radius = 30;
        const circ = 2 * Math.PI * radius;
        const strokeLength = percent * circ;
        const strokeOffset = circ - (cumulativePercent * circ);
        
        svgContent += `<circle cx="50" cy="50" r="${radius}" fill="transparent" 
            stroke="${color}" stroke-width="12" 
            stroke-dasharray="${strokeLength} ${circ - strokeLength}" 
            stroke-dashoffset="${strokeOffset}" 
            transform="rotate(-90 50 50)">
            <title>${item.name}: ${item.count} (${(percent * 100).toFixed(1)}%)</title>
        </circle>`;
        
        cumulativePercent += percent;
    });
    
    svgContent += `</svg>`;
    
    // Add Legend
    let legendHtml = '<div class="svg-legend">';
    dataList.forEach((item, idx) => {
        const percent = (item.count / total * 100).toFixed(1);
        const color = colors[idx % colors.length];
        legendHtml += `<div class="legend-item" title="${item.name}: ${item.count}">
            <span class="legend-dot" style="background-color: ${color}"></span>
            <span class="legend-label">${item.name.length > 18 ? item.name.substring(0, 16) + '..' : item.name} (${percent}%)</span>
        </div>`;
    });
    legendHtml += '</div>';
    
    container.innerHTML = `<div class="svg-doughnut-layout">${svgContent}${legendHtml}</div>`;
}

// Helper: Render SVG Horizontal Bar Chart
function renderSvgBar(container, dataList, type) {
    if (!dataList || dataList.length === 0) {
        container.innerHTML = '<div class="no-data-msg">Tidak ada data untuk diagram batang</div>';
        return;
    }
    
    let maxVal = 0;
    if (type === 'bytes') {
        maxVal = Math.max(...dataList.map(item => item.bytes));
    } else {
        maxVal = Math.max(...dataList.map(item => item.count));
    }
    if (maxVal === 0) maxVal = 1;
    
    let html = '<div class="svg-bar-chart">';
    dataList.forEach(item => {
        let label, val, displayVal;
        if (type === 'bytes') {
            label = `${item.source} ➔ ${item.destination}`;
            val = item.bytes;
            displayVal = formatBytes(val);
        } else if (type === 'events') {
            label = `${item.source} ➔ ${item.destination}`;
            val = item.count;
            displayVal = `${val} event`;
        } else {
            label = item.name;
            val = item.count;
            displayVal = `${val} alert`;
        }
        
        const percent = (val / maxVal * 100).toFixed(1);
        
        html += `<div class="bar-chart-row">
            <div class="bar-chart-label" title="${label}">${label}</div>
            <div class="bar-chart-track-container">
                <div class="bar-chart-track">
                    <div class="bar-chart-fill" style="width: ${percent}%;"></div>
                </div>
                <div class="bar-chart-value">${displayVal}</div>
            </div>
        </div>`;
    });
    html += '</div>';
    
    container.innerHTML = html;
}

// Helper: Render SVG Timeline Chart
function renderSvgTimeline(container, dataList, fileType) {
    if (!dataList || dataList.length === 0) {
        container.innerHTML = '<div class="no-data-msg">Tidak ada data garis waktu</div>';
        return;
    }
    
    const width = 600;
    const height = 250;
    const padding = 45;
    
    let maxPackets = 0;
    let maxBytes = 0;
    let maxAlerts = 0;
    
    if (fileType === 'pcap') {
        maxPackets = Math.max(...dataList.map(item => item.packets));
        maxBytes = Math.max(...dataList.map(item => item.bytes));
    } else {
        maxAlerts = Math.max(...dataList.map(item => item.count));
    }
    
    if (maxPackets === 0) maxPackets = 1;
    if (maxBytes === 0) maxBytes = 1;
    if (maxAlerts === 0) maxAlerts = 1;
    
    const count = dataList.length;
    const xStep = (width - padding * 2) / (count > 1 ? count - 1 : 1);
    
    let points1 = [];
    let points2 = [];
    
    dataList.forEach((item, idx) => {
        const x = padding + idx * xStep;
        if (fileType === 'pcap') {
            const yPackets = height - padding - ((item.packets / maxPackets) * (height - padding * 2));
            const yBytes = height - padding - ((item.bytes / maxBytes) * (height - padding * 2));
            points1.push(`${x},${yPackets}`);
            points2.push(`${x},${yBytes}`);
        } else {
            const yAlerts = height - padding - ((item.count / maxAlerts) * (height - padding * 2));
            points1.push(`${x},${yAlerts}`);
        }
    });
    
    let svgContent = `<svg viewBox="0 0 ${width} ${height}" width="100%" height="100%" class="svg-timeline-chart">`;
    
    // Grid lines
    for (let i = 0; i <= 4; i++) {
        const y = padding + i * ((height - padding * 2) / 4);
        svgContent += `<line x1="${padding}" y1="${y}" x2="${width - padding}" y2="${y}" stroke="rgba(255,255,255,0.04)" stroke-width="1"/>`;
    }
    
    // Axis lines
    svgContent += `<line x1="${padding}" y1="${height - padding}" x2="${width - padding}" y2="${height - padding}" stroke="rgba(255,255,255,0.2)" stroke-width="1.5"/>`;
    svgContent += `<line x1="${padding}" y1="${padding}" x2="${padding}" y2="${height - padding}" stroke="rgba(255,255,255,0.2)" stroke-width="1.5"/>`;
    
    if (fileType === 'pcap') {
        // Draw packets line (purple)
        svgContent += `<polyline fill="none" stroke="#8b5cf6" stroke-width="2.5" points="${points1.join(' ')}"/>`;
        // Draw bytes line (cyan)
        svgContent += `<polyline fill="none" stroke="#06b6d4" stroke-width="2" stroke-dasharray="4" points="${points2.join(' ')}"/>`;
    } else {
        // Draw alerts line (red)
        svgContent += `<polyline fill="none" stroke="#ef4444" stroke-width="2.5" points="${points1.join(' ')}"/>`;
        const areaPoints = [`${padding},${height - padding}`, ...points1, `${width - padding},${height - padding}`];
        svgContent += `<polygon fill="rgba(239, 68, 68, 0.08)" points="${areaPoints.join(' ')}"/>`;
    }
    
    // Draw timestamps
    if (count > 0) {
        svgContent += `<text x="${padding}" y="${height - padding + 18}" fill="#626a7e" font-size="10" text-anchor="start">${dataList[0].time}</text>`;
        svgContent += `<text x="${width - padding}" y="${height - padding + 18}" fill="#626a7e" font-size="10" text-anchor="end">${dataList[count - 1].time}</text>`;
    }
    
    svgContent += `</svg>`;
    
    let legendHtml = '<div class="svg-legend">';
    if (fileType === 'pcap') {
        legendHtml += `
            <div class="legend-item"><span class="legend-line" style="background-color: #8b5cf6"></span><span class="legend-label">Paket / Interval (Max: ${maxPackets})</span></div>
            <div class="legend-item"><span class="legend-line" style="background-color: #06b6d4; border-style: dashed;"></span><span class="legend-label">Volume / Interval (Max: ${formatBytes(maxBytes)})</span></div>
        `;
    } else {
        legendHtml += `
            <div class="legend-item"><span class="legend-line" style="background-color: #ef4444"></span><span class="legend-label">Frekuensi Alert (Max: ${maxAlerts})</span></div>
        `;
    }
    legendHtml += '</div>';
    
    container.innerHTML = `<div class="svg-timeline-layout">${svgContent}${legendHtml}</div>`;
}

// Render Alerts Detail Table
function renderAlertsTable() {
    const tbody = document.getElementById('alerts-table-body');
    tbody.innerHTML = '';
    
    const startIdx = (alertPage - 1) * alertsPerPage;
    const endIdx = startIdx + alertsPerPage;
    const pageItems = filteredAlerts.slice(startIdx, endIdx);
    
    if (pageItems.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Tidak ada alert yang cocok</td></tr>';
        document.getElementById('alert-page-num').textContent = `Halaman 0 dari 0`;
        return;
    }
    
    pageItems.forEach(alert => {
        const tr = document.createElement('tr');
        
        // Shorten timestamp
        const timeShort = alert.timestamp.split('+')[0].replace('T', ' ');
        // Shorten signature
        const sigShort = alert.signature.length > 50 ? alert.signature.substring(0, 50) + '...' : alert.signature;
        
        tr.innerHTML = `
            <td>${timeShort}</td>
            <td title="${alert.signature}">
                <div style="font-weight: 500;">${sigShort}</div>
                <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">ID Aturan: ${alert.id} | Klasifikasi: ${alert.category}</div>
            </td>
            <td><span class="severity-badge severity-${alert.severity}">Severity ${alert.severity}</span></td>
            <td>${alert.src_ip}:${alert.src_port}</td>
            <td>${alert.dest_ip}:${alert.dest_port}</td>
            <td><span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-secondary);">${alert.proto}</span></td>
        `;
        tbody.appendChild(tr);
    });
    
    const totalPages = Math.ceil(filteredAlerts.length / alertsPerPage);
    document.getElementById('alert-page-num').textContent = `Halaman ${alertPage} dari ${totalPages}`;
    
    document.getElementById('alert-prev').disabled = alertPage === 1;
    document.getElementById('alert-next').disabled = alertPage === totalPages || totalPages === 0;
}

// Render IoCs Table
function renderIoCTable(iocs) {
    const tbody = document.getElementById('iocs-table-body');
    const tableEl = document.getElementById('iocs-table');
    const safeMessageEl = document.getElementById('no-ioc-message');
    
    tbody.innerHTML = '';
    
    if (!iocs || iocs.length === 0) {
        tableEl.style.display = 'none';
        safeMessageEl.style.display = 'flex';
        return;
    }
    
    tableEl.style.display = 'table';
    safeMessageEl.style.display = 'none';
    
    iocs.forEach(ioc => {
        const tr = document.createElement('tr');
        
        let badgeColorClass = 'threat-low';
        if (ioc.threat_level.toLowerCase() === 'high') badgeColorClass = 'threat-high';
        else if (ioc.threat_level.toLowerCase() === 'medium') badgeColorClass = 'threat-medium';
        
        tr.innerHTML = `
            <td style="font-weight: 600; color: var(--accent-blue);">${ioc.ioc}</td>
            <td>${ioc.type}</td>
            <td><span class="threat-level-badge ${badgeColorClass}">${ioc.threat_level}</span></td>
            <td style="white-space: normal; line-height: 1.4;">${ioc.description}</td>
            <td style="text-align: center; font-weight: 700;">${ioc.count}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Tabs Navigation Logic
function initTabNavigation() {
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetPaneId = tab.getAttribute('data-tab');
            switchTab(targetPaneId);
        });
    });
}

function switchTab(paneId) {
    // Update active tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        if (btn.getAttribute('data-tab') === paneId) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
    
    // Update active content panes
    document.querySelectorAll('.tab-pane').forEach(pane => {
        if (pane.id === paneId) {
            pane.classList.add('active');
        } else {
            pane.classList.remove('active');
        }
    });
    
    // Redraw charts after container is visible (avoids Chart.js 0-width bug)
    if (currentData) {
        if (paneId === 'overview') {
            if (currentData.type === 'pcap') {
                renderProtocolChart(currentData.protocols, 'packets');
                renderConnectionChart(currentData.connections, 'bytes');
            } else {
                if (currentData.has_alerts) {
                    renderProtocolChart(currentData.protocols, 'alerts');
                    renderConnectionChart(currentData.connections, 'alerts');
                } else {
                    renderProtocolChart(currentData.protocols, 'events');
                    renderConnectionChart(currentData.connections, 'events');
                }
            }
        } else if (paneId === 'timeline') {
            if (currentData.type === 'pcap') {
                renderTimelineChart(currentData.timeline, 'pcap');
            } else {
                renderTimelineChart(currentData.timeline, 'alerts');
            }
        } else if (paneId === 'alerts-tab') {
            renderAlertsCategoryChart(currentData.connections);
        }
    }
}

// Alert filters & search logic
function initAlertFilters() {
    const searchInput = document.getElementById('alert-search');
    
    searchInput.addEventListener('input', () => {
        const query = searchInput.value.toLowerCase();
        if (!currentData || !currentData.alerts) return;
        
        filteredAlerts = currentData.alerts.filter(alert => {
            return alert.signature.toLowerCase().includes(query) ||
                   alert.category.toLowerCase().includes(query) ||
                   alert.src_ip.includes(query) ||
                   alert.dest_ip.includes(query) ||
                   alert.proto.toLowerCase().includes(query);
        });
        
        alertPage = 1;
        renderAlertsTable();
    });
    
    document.getElementById('alert-prev').addEventListener('click', () => {
        if (alertPage > 1) {
            alertPage--;
            renderAlertsTable();
        }
    });
    
    document.getElementById('alert-next').addEventListener('click', () => {
        const totalPages = Math.ceil(filteredAlerts.length / alertsPerPage);
        if (alertPage < totalPages) {
            alertPage++;
            renderAlertsTable();
        }
    });
}

// Exporters
function initExportButtons() {
    document.getElementById('btn-export-csv').addEventListener('click', () => {
        window.location.href = '/export/csv';
    });
    
    document.getElementById('btn-export-pdf').addEventListener('click', () => {
        window.location.href = '/export/pdf';
    });
}

// Toast System
function showToast(title, message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const iconClass = type === 'success' ? 'fa-circle-check text-green' : 'fa-circle-exclamation text-red';
    
    toast.innerHTML = `
        <i class="fa-solid ${iconClass}" style="font-size: 18px;"></i>
        <div>
            <div style="font-weight: 600;">${title}</div>
            <div style="font-size: 11.5px; color: var(--text-secondary); margin-top: 2px;">${message}</div>
        </div>
    `;
    
    container.appendChild(toast);
    
    // Auto dismiss
    setTimeout(() => {
        toast.style.animation = 'fadeIn 0.2s reverse ease';
        setTimeout(() => toast.remove(), 200);
    }, 4000);
}

// Utils
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ".");
}

function formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`;
    const mins = Math.floor(seconds / 60);
    const secs = Math.round(seconds % 60);
    return `${mins}m ${secs}s`;
}
