/* ═══════════════════════════════════════════════════════════════════════
   SNMP Manager Admin Panel — Network Discovery & Topology Module
   ═══════════════════════════════════════════════════════════════════════ */

(() => {
    'use strict';

    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);
    const API_BASE = '/api/v1';

    let scanStatusTimer = null;
    let scanResults = [];
    let networkGraph = null;

    // Load vis-network dynamically for topology if not present
    function loadVisNetwork() {
        return new Promise((resolve) => {
            if (window.vis) return resolve();
            const link = document.createElement('link');
            link.href = 'https://unpkg.com/vis-network/standalone/umd/vis-network.min.css';
            link.rel = 'stylesheet';
            document.head.appendChild(link);

            const script = document.createElement('script');
            script.src = 'https://unpkg.com/vis-network/standalone/umd/vis-network.min.js';
            script.onload = () => resolve();
            document.head.appendChild(script);
        });
    }

    async function dApiCall(method, endpoint, body = null) {
        const apiKey = localStorage.getItem('snmp_access_token') || localStorage.getItem('snmp_api_key') || '';
        const headers = { 'Content-Type': 'application/json' };
        if (apiKey) {
            if (apiKey.includes('.')) headers['Authorization'] = `Bearer ${apiKey}`;
            else headers['X-API-Key'] = apiKey;
        }
        const opts = { method, headers };
        if (body) opts.body = JSON.stringify(body);
        
        try {
            const res = await fetch(`${API_BASE}${endpoint}`, opts);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
            return data;
        } catch (e) {
            showToast(e.message, 'error');
            throw e;
        }
    }

    function showToast(message, type = 'info') {
        const container = $('#toastContainer');
        if(!container) return;
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `<span>${message}</span>`;
        container.appendChild(toast);
        setTimeout(() => { toast.classList.add('toast-removing'); setTimeout(() => toast.remove(), 300); }, 4000);
    }

    async function loadDiscoveryPage() {
        setupTabs();
        checkScanStatus();
        loadTopologyMap();
    }

    function setupTabs() {
        const tabs = $$('#discoveryTabNav .tab-item');
        tabs.forEach(t => {
            t.onclick = () => {
                tabs.forEach(x => x.classList.remove('active'));
                t.classList.add('active');
                $$('.tab-pane').forEach(p => p.classList.remove('active'));
                $(`#tab-disc-${t.dataset.tab}`).classList.add('active');
                
                if (t.dataset.tab === 'topo' && networkGraph) {
                    // Redraw graph when it becomes visible
                    setTimeout(() => networkGraph.fit(), 100);
                }
            };
        });
    }

    // ── Topology Map ──────────────────────────────────────────────────
    async function loadTopologyMap() {
        try {
            await loadVisNetwork();
            const data = await dApiCall('GET', '/topology');
            renderTopology(data);
        } catch (err) {
            $('#topologyContainer').innerHTML = `<p class="text-muted">Failed to load topology: ${err.message}</p>`;
        }
    }

    async function refreshTopology() {
        $('#topologyContainer').innerHTML = `<div class="loading-state"><div class="spinner"></div><p>Rebuilding topology map... This may take a few seconds.</p></div>`;
        try {
            await loadVisNetwork();
            const data = await dApiCall('POST', '/topology/refresh');
            renderTopology(data.topology);
            showToast('Topology refreshed successfully', 'success');
        } catch (err) {
            $('#topologyContainer').innerHTML = `<p class="text-muted" style="color:var(--accent-red)">Error: ${err.message}</p>`;
        }
    }

    function renderTopology(topoData) {
        if (!window.vis) return;
        const container = $('#topologyContainer');
        if (!topoData || !topoData.nodes || topoData.nodes.length === 0) {
            container.innerHTML = `<p class="text-muted">No topology data available. Discover devices first.</p>`;
            return;
        }
        
        container.innerHTML = ''; // clear loading

        const nodesList = topoData.nodes.map(n => {
            let icon = 'f233'; // server
            let color = '#4dabf7';
            if (n.device_type === 'router') { icon = 'f0e8'; color = '#ff922b'; }
            if (n.device_type === 'switch') { icon = 'f0e8'; color = '#20c997'; }
            if (n.device_type === 'firewall') { icon = 'f132'; color = '#ff6b6b'; }
            
            return {
                id: n.id,
                label: n.label || n.ip,
                title: `IP: ${n.ip}\nVendor: ${n.vendor}\nType: ${n.device_type}\nInterfaces: ${n.interfaces}`,
                group: n.device_type,
                shape: 'dot',
                color: { background: color, border: '#1c1c1e' },
                font: { color: '#e0e0e0', face: 'Inter' }
            };
        });

        const edgesList = topoData.links.map(l => ({
            id: l.id,
            from: l.source,
            to: l.target,
            title: `Port: ${l.source_port} → ${l.target_port}\nProtocol: ${l.protocol}`,
            color: { color: '#444' },
            smooth: { type: 'continuous' }
        }));

        const data = {
            nodes: new vis.DataSet(nodesList),
            edges: new vis.DataSet(edgesList)
        };
        const options = {
            physics: {
                barnesHut: { gravitationalConstant: -2000, centralGravity: 0.1, springLength: 150 },
                stabilization: { iterations: 100 }
            },
            interaction: {
                hover: true,
                tooltipDelay: 100
            }
        };

        networkGraph = new vis.Network(container, data, options);
    }

    // ── Scan Logic ────────────────────────────────────────────────────
    async function startScan(e) {
        e.preventDefault();
        const subnets = $('#discSubnets').value.split(',').map(s => s.trim()).filter(Boolean);
        const communities = $('#discCommunities').value.split(',').map(s => s.trim()).filter(Boolean);
        
        try {
            await dApiCall('POST', '/discovery/scan', { subnets, communities });
            showToast('Scan started', 'success');
            $('#discoveryScanControl').style.display = 'none';
            checkScanStatus();
        } catch (err) {}
    }

    async function checkScanStatus() {
        try {
            const status = await dApiCall('GET', '/discovery/status');
            if (status && status.state === 'running') {
                renderStatusProgress(status);
                if (!scanStatusTimer) scanStatusTimer = setInterval(checkScanStatus, 1500);
            } else if (status && (status.state === 'completed' || status.state === 'cancelled')) {
                clearInterval(scanStatusTimer);
                scanStatusTimer = null;
                showToast(`Scan ${status.state}`, 'info');
                loadScanResults();
                $('#discoveryScanControl').style.display = 'block';
            } else {
                $('#discoveryScanControl').style.display = 'block';
            }
        } catch (err) {
            console.error('Scan status error:', err);
        }
    }

    function renderStatusProgress(status) {
        $('#discoveryEmpty').innerHTML = `
            <div style="font-size:1.1rem;margin-bottom:10px;">Scanning Network...</div>
            <div style="width:100%;background:#333;height:8px;border-radius:4px;overflow:hidden;margin:0 auto 15px;">
                <div style="height:100%;width:${status.percent}%;background:var(--accent-blue);transition:width 0.3s;"></div>
            </div>
            <div style="display:flex;justify-content:space-around;color:var(--text-muted);font-size:0.9rem;">
                <span>Scanned: ${status.scanned_ips} / ${status.total_ips}</span>
                <span>Found: ${status.found_devices}</span>
                <span>Errors: ${status.errors}</span>
            </div>
            <button class="btn btn-ghost btn-sm" id="cancelScanBtn" style="margin-top:15px;color:var(--accent-red);">Cancel Scan</button>
        `;
        const cb = $('#cancelScanBtn');
        if (cb) cb.onclick = async () => {
            await dApiCall('POST', '/discovery/cancel');
            checkScanStatus();
        };
    }

    async function loadScanResults() {
        try {
            const data = await dApiCall('GET', '/discovery/results');
            scanResults = data.devices || [];
            renderScanResults();
        } catch (err) {}
    }

    function renderScanResults() {
        const table = $('#discoveryResultsTable');
        const tbody = table.querySelector('tbody');
        const empty = $('#discoveryEmpty');
        const regBtn = $('#discoveryRegisterBtn');
        
        if (scanResults.length === 0) {
            table.style.display = 'none';
            regBtn.style.display = 'none';
            empty.innerHTML = 'Scan completed but no active SNMP devices found.';
            empty.style.display = 'block';
            return;
        }

        table.style.display = 'table';
        empty.style.display = 'none';
        regBtn.style.display = 'block';
        tbody.innerHTML = '';

        scanResults.forEach((d, i) => {
            const tr = document.createElement('tr');
            const isReg = d.registered;
            tr.innerHTML = `
                <td><input type="checkbox" class="dev-select" value="${d.ip}" ${isReg ? 'disabled' : 'checked'}></td>
                <td><strong>${d.ip}</strong></td>
                <td>${escapeHtml(d.sys_name) || `<span class="text-muted">N/A</span>`}</td>
                <td>${d.vendor} <span class="text-muted">/</span> ${d.device_type}</td>
                <td><span class="badge ${d.matched_template ? 'badge-primary' : ''}">${d.matched_template || 'Generic'}</span></td>
                <td>${isReg ? `<span style="color:var(--accent-green)">Already Registered</span>` : `<span style="color:var(--accent-blue)">New Device</span>`}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    async function registerSelected() {
        const checkboxes = $$('.dev-select:checked');
        const ips = Array.from(checkboxes).map(c => c.value);
        if (ips.length === 0) {
            showToast('No devices selected', 'error');
            return;
        }

        try {
            const res = await dApiCall('POST', '/discovery/register', { ips });
            showToast(res.message, 'success');
            loadScanResults();
            // Automatically switch back to topology down the line?
        } catch(err) {}
    }

    // Expose globals
    window.loadDiscoveryPage = loadDiscoveryPage;

    // Events
    document.addEventListener('DOMContentLoaded', () => {
        $('#discoveryScanBtn')?.addEventListener('click', () => {
            $('#tab-disc-scan')?.classList.add('active');
            $('#tab-disc-topo')?.classList.remove('active');
            $$('#discoveryTabNav .tab-item')[1]?.click();
            $('#discoveryScanControl').style.display = 'block';
            $('#discoveryResultsTable').style.display = 'none';
            $('#discoveryEmpty').style.display = 'none';
            $('#discSubnets').focus();
        });

        $('#discoveryRefreshBtn')?.addEventListener('click', refreshTopology);
        $('#discoveryForm')?.addEventListener('submit', startScan);
        $('#discoveryRegisterBtn')?.addEventListener('click', registerSelected);
    });

})();
