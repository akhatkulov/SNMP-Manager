/* ═══════════════════════════════════════════════════════════════════════
   SNMP Manager Admin Panel — Application Logic
   ═══════════════════════════════════════════════════════════════════════ */

(() => {
    'use strict';

    // ── Configuration ─────────────────────────────────────────────────
    const API_BASE = '/api/v1';
    const REFRESH_INTERVAL = 10_000; // 10 seconds
    let apiKey = localStorage.getItem('snmp_api_key') || '';
    let refreshTimer = null;
    let progressTimer = null;
    let currentEditDevice = null;
    let isLoggedIn = !!apiKey;

    // ── DOM References ────────────────────────────────────────────────
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    // ── API Helpers ───────────────────────────────────────────────────

    async function apiCall(method, endpoint, body = null) {
        const opts = {
            method,
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json',
            },
        };
        if (body) opts.body = JSON.stringify(body);

        const res = await fetch(`${API_BASE}${endpoint}`, opts);
        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.error || `HTTP ${res.status}`);
        }
        return data;
    }

    // ── Toast Notifications ───────────────────────────────────────────

    function showToast(message, type = 'info') {
        const container = $('#toastContainer');
        const icons = {
            success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
            error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
            info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
        };

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `${icons[type] || icons.info}<span>${message}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('toast-removing');
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    // ── Navigation ────────────────────────────────────────────────────

    function navigateTo(page) {
        $$('.page').forEach(p => p.classList.remove('active'));
        $$('.nav-item').forEach(n => n.classList.remove('active'));

        $(`#page-${page}`)?.classList.add('active');
        $(`#nav-${page}`)?.classList.add('active');

        // Close mobile sidebar
        $('#sidebar').classList.remove('open');

        // Load page data
        switch (page) {
            case 'dashboard': loadDashboard(); break;
            case 'devices': loadDevices(); break;
            case 'traps': loadTraps(); break;
            case 'mibs': loadMIBs(); break;
            case 'settings': loadOutputs(); break;
        }
    }

    // ── Dashboard ─────────────────────────────────────────────────────

    async function loadDashboard() {
        try {
            const [stats, devicesData] = await Promise.all([
                apiCall('GET', '/stats'),
                apiCall('GET', '/devices'),
            ]);

            // Update stat cards
            const d = stats.devices || {};
            const p = stats.poller || {};
            const t = stats.traps || {};

            $('#statTotalValue').textContent = d.total ?? 0;
            $('#statUpValue').textContent = d.up ?? 0;
            $('#statDownValue').textContent = (d.down ?? 0) + (d.error ?? 0);
            $('#statPollsValue').textContent = formatNumber(p.total_polls ?? 0);
            $('#statTrapsValue').textContent = formatNumber(t.total_received ?? 0);
            $('#statUptimeValue').textContent = formatUptime(stats.uptime || '0s');

            // Update device table
            renderDeviceTable(devicesData.devices || [], '#dashDeviceTable', true);

            // Load poll progress
            loadPollProgress();

            updateServerStatus(true);
        } catch (err) {
            console.error('Dashboard load error:', err);
            updateServerStatus(false);
        }
    }

    // ── Devices Page ──────────────────────────────────────────────────

    async function loadDevices() {
        try {
            const data = await apiCall('GET', '/devices');
            renderDeviceTable(data.devices || [], '#devicesTableContainer', false);
            updateServerStatus(true);
        } catch (err) {
            console.error('Devices load error:', err);
            updateServerStatus(false);
            $('#devicesTableContainer').innerHTML = `
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    <p>Failed to load devices</p>
                </div>`;
        }
    }

    function renderDeviceTable(devices, containerSel, compact) {
        const container = $(containerSel);
        if (!devices.length) {
            container.innerHTML = `
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                    <p>No devices configured</p>
                    <button class="btn btn-primary btn-sm" onclick="document.getElementById('addDeviceBtn')?.click() || document.getElementById('dashAddDeviceBtn')?.click()">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                        Add Your First Device
                    </button>
                </div>`;
            return;
        }

        const rows = devices.map(d => `
            <tr>
                <td>
                    <span class="device-name">${escapeHtml(d.name)}</span>
                </td>
                <td><span class="device-ip">${escapeHtml(d.ip)}</span></td>
                <td>${getStatusBadge(d.status, d.enabled)}</td>
                <td>${d.snmp_version?.toUpperCase() || 'v2c'}</td>
                ${compact ? '' : `
                    <td>${escapeHtml(d.vendor || '—')}</td>
                    <td>${escapeHtml(d.device_type || '—')}</td>
                `}
                <td><span style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem;">${formatNumber(d.poll_count || 0)}</span></td>
                ${compact ? '' : `
                    <td><span style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem;">${formatNumber(d.trap_count || 0)}</span></td>
                    <td>${d.last_poll ? formatTime(d.last_poll) : '—'}</td>
                `}
                <td>
                    <div class="actions-cell">
                        <button class="btn-icon btn-icon-blue" onclick="window._pollDevice('${escapeHtml(d.name)}')" title="Poll now">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                        </button>
                        <button class="btn-icon btn-icon-blue" onclick="window._editDevice('${escapeHtml(d.name)}')" title="Edit">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                        </button>
                        <button class="btn-icon btn-icon-danger" onclick="window._confirmDelete('${escapeHtml(d.name)}')" title="Delete">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');

        container.innerHTML = `
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>IP Address</th>
                        <th>Status</th>
                        <th>Version</th>
                        ${compact ? '' : '<th>Vendor</th><th>Type</th>'}
                        <th>Polls</th>
                        ${compact ? '' : '<th>Traps</th><th>Last Poll</th>'}
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>`;
    }

    function getStatusBadge(status, enabled) {
        if (!enabled) return '<span class="badge badge-disabled">Disabled</span>';
        const map = {
            up: 'badge-up',
            down: 'badge-down',
            error: 'badge-error',
            unreachable: 'badge-down',
        };
        const cls = map[status] || 'badge-unknown';
        return `<span class="badge ${cls}">${status || 'unknown'}</span>`;
    }

    // ── Traps Page ────────────────────────────────────────────────────

    async function loadTraps() {
        try {
            const stats = await apiCall('GET', '/stats');
            const t = stats.traps || {};

            $('#trapTotalValue').textContent = formatNumber(t.total_received ?? 0);
            $('#trapProcessedValue').textContent = formatNumber(t.total_processed ?? 0);
            $('#trapErrorsValue').textContent = formatNumber(t.errors ?? 0);

            const items = [
                { label: 'Listen Address', value: t.listen_address || '0.0.0.0:162' },
                { label: 'Total Received', value: t.total_received ?? 0 },
                { label: 'Processed', value: t.total_processed ?? 0 },
                { label: 'Unknown Sources', value: t.unknown_source ?? 0 },
                { label: 'Errors', value: t.errors ?? 0 },
                { label: 'Uptime', value: formatUptime(stats.uptime || '0s') },
            ];

            $('#trapInfoGrid').innerHTML = items.map(i => `
                <div class="info-item">
                    <div class="info-label">${i.label}</div>
                    <div class="info-value">${i.value}</div>
                </div>
            `).join('');

            // Also load pipeline stats + recent logs
            loadPipelineStats();
            loadRecentLogs();

            updateServerStatus(true);
        } catch (err) {
            console.error('Traps load error:', err);
            updateServerStatus(false);
        }
    }

    // ── MIBs Page ─────────────────────────────────────────────────────

    async function loadMIBs() {
        try {
            const [countData, groupsData] = await Promise.all([
                apiCall('GET', '/mibs/count'),
                apiCall('GET', '/mibs/groups'),
            ]);

            const groups = groupsData.groups || {};
            const totalOIDs = countData.total_oids || 0;
            const groupKeys = Object.keys(groups);

            $('#mibTotalOids').textContent = totalOIDs;
            $('#mibTotalGroups').textContent = groupKeys.length;

            if (groupKeys.length) {
                $('#mibGroupsContainer').innerHTML = `
                    <div class="mib-groups-grid">
                        ${groupKeys.sort().map(g => `
                            <div class="mib-group-card">
                                <div class="mib-group-name">${escapeHtml(g)}</div>
                                <div class="mib-group-count">${groups[g]} OIDs</div>
                            </div>
                        `).join('')}
                    </div>`;
            } else {
                $('#mibGroupsContainer').innerHTML = '<div class="empty-state"><p>No MIB groups loaded</p></div>';
            }

            updateServerStatus(true);
        } catch (err) {
            console.error('MIBs load error:', err);
            updateServerStatus(false);
        }
    }

    // ── OID Resolver ──────────────────────────────────────────────────

    async function resolveOID() {
        const oid = $('#oidLookupInput').value.trim();
        if (!oid) return;

        const resultEl = $('#oidResult');
        try {
            const data = await apiCall('GET', `/mibs/resolve/${oid}`);
            resultEl.classList.remove('hidden');
            resultEl.innerHTML = `
                <div class="oid-result-item"><span class="oid-result-label">OID:</span><span class="oid-result-value">${escapeHtml(data.oid || oid)}</span></div>
                <div class="oid-result-item"><span class="oid-result-label">Name:</span><span class="oid-result-value">${escapeHtml(data.name || '—')}</span></div>
                <div class="oid-result-item"><span class="oid-result-label">Module:</span><span class="oid-result-value">${escapeHtml(data.module || '—')}</span></div>
                <div class="oid-result-item"><span class="oid-result-label">Type:</span><span class="oid-result-value">${escapeHtml(data.syntax || '—')}</span></div>
                <div class="oid-result-item"><span class="oid-result-label">Description:</span><span class="oid-result-value">${escapeHtml(data.description || '—')}</span></div>
            `;
        } catch (err) {
            resultEl.classList.remove('hidden');
            resultEl.innerHTML = `<div class="oid-result-item"><span class="oid-result-label">Error:</span><span class="oid-result-value" style="color: var(--accent-red);">${escapeHtml(err.message)}</span></div>`;
        }
    }

    // ── Device Modal ──────────────────────────────────────────────────

    function openAddModal() {
        currentEditDevice = null;
        $('#modalTitle').textContent = 'Add Device';
        $('#modalSubmitBtn').textContent = 'Add Device';
        $('#deviceForm').reset();
        $('#devEnabled').checked = true;
        $('#devPort').value = 161;
        updateVersionFields();
        showModal('deviceModal');
    }

    async function openEditModal(name) {
        try {
            const device = await apiCall('GET', `/devices/${name}`);
            currentEditDevice = name;
            $('#modalTitle').textContent = 'Edit Device';
            $('#modalSubmitBtn').textContent = 'Save Changes';

            $('#devName').value = device.name || '';
            $('#devIP').value = device.ip || '';
            $('#devPort').value = device.port || 161;
            $('#devVersion').value = device.snmp_version || 'v2c';
            $('#devCommunity').value = device.community || '';
            $('#devEnabled').checked = device.enabled !== false;
            $('#devTagLocation').value = device.tags?.location || '';
            $('#devTagCriticality').value = device.tags?.criticality || 'high';

            // OID groups
            $$('#oidGroupCheckboxes input').forEach(cb => {
                cb.checked = (device.oid_groups || []).includes(cb.value);
            });

            // Poll interval
            const intervalSec = (device.poll_interval || 60000000000) / 1e9;
            const intervalStr = intervalSec >= 60 ? `${intervalSec}s` : `${intervalSec}s`;
            const intervalOpts = ['15s', '30s', '60s', '120s', '300s', '600s'];
            const matchVal = `${intervalSec}s`;
            $('#devPollInterval').value = intervalOpts.includes(matchVal) ? matchVal : '60s';

            // Disable name field in edit mode
            $('#devName').disabled = true;

            updateVersionFields();
            showModal('deviceModal');
        } catch (err) {
            showToast(`Failed to load device: ${err.message}`, 'error');
        }
    }

    function updateVersionFields() {
        const version = $('#devVersion').value;
        if (version === 'v3') {
            $('#communityGroup').classList.add('hidden');
            $('#v3CredentialsGroup').classList.remove('hidden');
        } else {
            $('#communityGroup').classList.remove('hidden');
            $('#v3CredentialsGroup').classList.add('hidden');
        }
    }

    async function handleDeviceSubmit(e) {
        e.preventDefault();

        const version = $('#devVersion').value;
        const oidGroups = [];
        $$('#oidGroupCheckboxes input:checked').forEach(cb => oidGroups.push(cb.value));

        const tags = {};
        const loc = $('#devTagLocation').value.trim();
        const crit = $('#devTagCriticality').value;
        if (loc) tags.location = loc;
        if (crit) tags.criticality = crit;

        const body = {
            name: $('#devName').value.trim(),
            ip: $('#devIP').value.trim(),
            port: parseInt($('#devPort').value) || 161,
            snmp_version: version,
            poll_interval: $('#devPollInterval').value,
            oid_groups: oidGroups.length ? oidGroups : ['system'],
            tags: Object.keys(tags).length ? tags : undefined,
            enabled: $('#devEnabled').checked,
        };

        if (version === 'v1' || version === 'v2c') {
            body.community = $('#devCommunity').value.trim();
            if (!body.community) {
                showToast('Community string is required', 'error');
                return;
            }
        } else if (version === 'v3') {
            body.credentials = {
                username: $('#devV3User').value.trim(),
                auth_protocol: $('#devV3AuthProto').value,
                auth_passphrase: $('#devV3AuthPass').value,
                priv_protocol: $('#devV3PrivProto').value,
                priv_passphrase: $('#devV3PrivPass').value,
            };
            if (!body.credentials.username) {
                showToast('SNMPv3 username is required', 'error');
                return;
            }
        }

        try {
            if (currentEditDevice) {
                await apiCall('PUT', `/devices/${currentEditDevice}`, body);
                showToast(`Device "${currentEditDevice}" updated`, 'success');
            } else {
                await apiCall('POST', '/devices', body);
                showToast(`Device "${body.name}" added successfully`, 'success');
            }
            hideModal('deviceModal');
            $('#devName').disabled = false;
            refreshCurrentPage();
        } catch (err) {
            showToast(err.message, 'error');
        }
    }

    // ── Delete ────────────────────────────────────────────────────────

    let deviceToDelete = null;

    function confirmDelete(name) {
        deviceToDelete = name;
        $('#deleteDeviceName').textContent = name;
        showModal('deleteModal');
    }

    async function deleteDevice() {
        if (!deviceToDelete) return;
        try {
            await apiCall('DELETE', `/devices/${deviceToDelete}`);
            showToast(`Device "${deviceToDelete}" deleted`, 'success');
            hideModal('deleteModal');
            deviceToDelete = null;
            refreshCurrentPage();
        } catch (err) {
            showToast(err.message, 'error');
        }
    }

    // ── Poll Device ───────────────────────────────────────────────────

    async function pollDevice(name) {
        try {
            const data = await apiCall('POST', `/devices/${name}/poll`);
            showToast(`Polled "${name}": ${data.events || 0} events`, 'success');
            refreshCurrentPage();
        } catch (err) {
            showToast(`Poll failed: ${err.message}`, 'error');
        }
    }

    // ── Modal Helpers ─────────────────────────────────────────────────

    function showModal(id) {
        $(`#${id}`).classList.add('active');
        document.body.style.overflow = 'hidden';
    }

    function hideModal(id) {
        $(`#${id}`).classList.remove('active');
        document.body.style.overflow = '';
    }

    // ── Server Status ─────────────────────────────────────────────────

    function updateServerStatus(online) {
        const el = $('#serverStatus');
        const dot = el.querySelector('.status-dot');
        const text = el.querySelector('span');

        dot.className = `status-dot ${online ? 'status-online' : 'status-offline'}`;
        text.textContent = online ? 'Connected' : 'Disconnected';
    }

    // ── API Key ───────────────────────────────────────────────────────

    function openApiKeyModal() {
        $('#apiKeyInput').value = apiKey;
        showModal('apiKeyModal');
    }

    function saveApiKey() {
        const key = $('#apiKeyInput').value.trim();
        if (key) {
            apiKey = key;
            localStorage.setItem('snmp_api_key', key);
            showToast('API key saved', 'success');
            hideModal('apiKeyModal');
            refreshCurrentPage();
        }
    }

    // ── Utility Functions ─────────────────────────────────────────────

    function escapeHtml(str) {
        if (typeof str !== 'string') return str;
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function formatNumber(n) {
        if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
        if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
        return String(n);
    }

    function formatUptime(s) {
        // Parse Go duration string (e.g., "5m32.123s", "1h2m3s", "47.308050361s")
        let totalSeconds = 0;
        const hMatch = s.match(/(\d+)h/);
        const mMatch = s.match(/(\d+)m/);
        const sMatch = s.match(/([\d.]+)s/);
        if (hMatch) totalSeconds += parseInt(hMatch[1]) * 3600;
        if (mMatch) totalSeconds += parseInt(mMatch[1]) * 60;
        if (sMatch) totalSeconds += parseFloat(sMatch[1]);

        if (totalSeconds <= 0) return '0s';

        const days = Math.floor(totalSeconds / 86400);
        const hours = Math.floor((totalSeconds % 86400) / 3600);
        const mins = Math.floor((totalSeconds % 3600) / 60);
        const secs = Math.floor(totalSeconds % 60);

        if (days > 0) return `${days}d ${hours}h`;
        if (hours > 0) return `${hours}h ${mins}m`;
        if (mins > 0) return `${mins}m ${secs}s`;
        return `${secs}s`;
    }

    function formatTime(isoStr) {
        if (!isoStr || isoStr === '0001-01-01T00:00:00Z') return '—';
        const d = new Date(isoStr);
        const now = new Date();
        const diffSec = (now - d) / 1000;

        if (diffSec < 60) return 'just now';
        if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
        if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
        return d.toLocaleDateString();
    }

    function refreshCurrentPage() {
        const active = document.querySelector('.nav-item.active');
        const page = active?.dataset.page || 'dashboard';
        switch (page) {
            case 'dashboard': loadDashboard(); break;
            case 'devices': loadDevices(); break;
            case 'traps': loadTraps(); break;
            case 'mibs': loadMIBs(); break;
        }
    }

    // ── Load Outputs (Settings page) ──────────────────────────────────
    async function loadOutputs() {
        const container = document.getElementById('outputsContainer');
        if (!container) return;

        try {
            const resp = await fetch(`${API_BASE}/config/outputs`, { headers: { 'X-API-Key': apiKey } });
            const data = await resp.json();
            const outputs = data.outputs || [];

            if (outputs.length === 0) {
                container.innerHTML = '<div class="empty-state"><p>No outputs configured</p></div>';
                return;
            }

            const icons = {
                file: '📁', stdout: '🖥️', syslog: '📡',
                http: '🔗', tcp: '🔌', elasticsearch: '🔍'
            };

            const colors = {
                file: 'var(--accent-blue)', stdout: 'var(--accent-teal)',
                syslog: 'var(--accent-orange)', http: 'var(--accent-purple)',
                tcp: 'var(--accent-green)', elasticsearch: 'var(--accent-yellow)'
            };

            let html = '<div class="info-grid">';
            outputs.forEach(o => {
                const icon = icons[o.type] || '⚙️';
                const color = colors[o.type] || 'var(--text-secondary)';
                const status = o.enabled
                    ? '<span style="color:var(--accent-green);font-weight:600;">● Active</span>'
                    : '<span style="color:var(--text-muted);font-weight:600;">○ Disabled</span>';

                html += `
                    <div class="info-item" style="border-left:3px solid ${color};padding-left:12px;">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                            <span class="info-label">${icon} ${o.type.toUpperCase()}</span>
                            ${status}
                        </div>
                        <code style="font-size:0.8rem;word-break:break-all;">${o.target || 'N/A'}</code>
                        ${o.format ? '<br><span class="text-muted" style="font-size:0.75rem;">Format: ' + o.format + '</span>' : ''}
                    </div>`;
            });
            html += '</div>';
            container.innerHTML = html;
        } catch (err) {
            container.innerHTML = `<div class="empty-state"><p>Error loading outputs: ${err.message}</p></div>`;
        }
    }

    // ── Global functions for inline onclick ────────────────────────────
    window._editDevice = openEditModal;
    window._confirmDelete = confirmDelete;
    window._pollDevice = pollDevice;

    // ── Login / Logout ────────────────────────────────────────────────

    async function doLogin() {
        const username = $('#loginUsername').value.trim();
        const password = $('#loginPassword').value.trim();
        const errorEl = $('#loginError');
        errorEl.textContent = '';

        if (!username || !password) {
            errorEl.textContent = 'Username and password are required';
            return;
        }

        try {
            const res = await fetch(`${API_BASE}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
            });
            const data = await res.json();

            if (!res.ok) {
                errorEl.textContent = data.error || 'Login failed';
                return;
            }

            if (data.mode === 'api_key') {
                errorEl.textContent = 'Enter API key directly';
                return;
            }

            apiKey = data.token;
            isLoggedIn = true;
            localStorage.setItem('snmp_api_key', apiKey);
            $('#loginOverlay').classList.remove('active');
            showToast('Login successful', 'success');
            loadDashboard();
            refreshTimer = setInterval(refreshCurrentPage, REFRESH_INTERVAL);
        } catch (err) {
            errorEl.textContent = 'Connection error';
        }
    }

    function doLogout() {
        apiKey = '';
        isLoggedIn = false;
        localStorage.removeItem('snmp_api_key');
        if (refreshTimer) clearInterval(refreshTimer);
        $('#loginOverlay').classList.add('active');
        $('#loginUsername').value = '';
        $('#loginPassword').value = '';
        showToast('Logged out', 'info');
    }

    function showLoginScreen() {
        $('#loginOverlay').classList.add('active');
    }

    // ── Poll Progress (Real-time) ─────────────────────────────────────

    async function loadPollProgress() {
        try {
            const data = await apiCall('GET', '/poller/progress');
            const container = $('#pollProgressContainer');
            if (!container) return;

            const progress = data.progress || {};
            const entries = Object.values(progress);
            const activePolls = entries.filter(p => p.polling);

            if (activePolls.length === 0) {
                container.innerHTML = '';
                container.style.display = 'none';
                // Stop fast polling if no active polls
                if (progressTimer) {
                    clearInterval(progressTimer);
                    progressTimer = null;
                }
                return;
            }

            container.style.display = 'block';

            // Start fast polling interval if not already running
            if (!progressTimer) {
                progressTimer = setInterval(loadPollProgress, 2000);
            }

            container.innerHTML = activePolls.map(p => {
                const pct = Math.min(p.percent || 0, 100).toFixed(1);
                const elapsed = p.elapsed || '...';
                const currentOid = p.current_oid || '...';
                const pdus = p.pdus_found || 0;

                return `
                    <div class="poll-progress-card">
                        <div class="poll-progress-header">
                            <div class="poll-progress-device">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                                    <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                                </svg>
                                <strong>${escapeHtml(p.device)}</strong>
                                <span class="poll-progress-badge">Polling...</span>
                            </div>
                            <div class="poll-progress-stats">
                                <span>${p.progress}/${p.total} OIDs</span>
                                <span class="poll-progress-elapsed">${elapsed}</span>
                            </div>
                        </div>
                        <div class="poll-progress-bar-track">
                            <div class="poll-progress-bar-fill" style="width: ${pct}%"></div>
                        </div>
                        <div class="poll-progress-footer">
                            <span class="poll-progress-oid" title="${escapeHtml(currentOid)}">🔍 ${escapeHtml(currentOid)}</span>
                            <span class="poll-progress-pdus">${formatNumber(pdus)} PDUs collected</span>
                        </div>
                    </div>
                `;
            }).join('');

        } catch (err) {
            console.error('Poll progress error:', err);
        }
    }

    // ── Pipeline Stats ────────────────────────────────────────────────

    async function loadPipelineStats() {
        try {
            const data = await apiCall('GET', '/pipeline/stats');
            const el = $('#pipelineStatsContainer');
            if (!el) return;
            el.innerHTML = `
                <div class="info-grid">
                    <div class="info-item"><div class="info-label">Events In</div><div class="info-value">${formatNumber(data.events_in || 0)}</div></div>
                    <div class="info-item"><div class="info-label">Events Out</div><div class="info-value">${formatNumber(data.events_out || 0)}</div></div>
                    <div class="info-item"><div class="info-label">Dropped</div><div class="info-value">${formatNumber(data.events_dropped || 0)}</div></div>
                    <div class="info-item"><div class="info-label">Errors</div><div class="info-value">${formatNumber(data.events_errored || 0)}</div></div>
                    <div class="info-item"><div class="info-label">Raw Queue</div><div class="info-value">${data.raw_queue_len || 0} / ${data.raw_queue_cap || 0}</div></div>
                    <div class="info-item"><div class="info-label">Output Queue</div><div class="info-value">${data.output_queue_len || 0}</div></div>
                </div>`;
        } catch (err) {
            console.error('Pipeline stats error:', err);
        }
    }

    // ── Recent Logs ───────────────────────────────────────────────────

    async function loadRecentLogs() {
        try {
            const data = await apiCall('GET', '/logs/recent');
            const el = $('#recentLogsContainer');
            if (!el) return;

            const logs = data.logs || [];
            if (!logs.length) {
                el.innerHTML = '<div class="empty-state"><p>No log entries yet</p></div>';
                return;
            }

            el.innerHTML = `
                <div style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 8px;">Total: ${data.total || 0} entries (showing last ${logs.length})</div>
                <div class="table-responsive"><table><thead><tr>
                    <th>Time</th><th>Source</th><th>Type</th><th>OID</th><th>Resolved Name</th><th>Description</th><th>Value</th><th>Severity</th>
                </tr></thead><tbody>${logs.map(e => {
                    try {
                        // Handle raw lines that failed JSON parse
                        if (e.raw) {
                            return `<tr><td colspan="8" style="font-family:'JetBrains Mono',monospace; font-size:0.75rem; color:var(--text-muted); word-break:break-all;">${escapeHtml(e.raw)}</td></tr>`;
                        }
                        const snmp = e.snmp || {};
                        const source = e.source || {};
                        const oid = snmp.oid || '—';
                        const oidName = snmp.oid_name || oid;
                        const oidResolved = snmp.oid_resolved || oidName;
                        const oidDesc = snmp.oid_description || '';
                        const oidSyntax = snmp.oid_syntax || '';
                        const value = snmp.value_string || (snmp.value != null ? String(snmp.value) : '—');
                        const sourceLabel = source.hostname || source.sys_name || source.ip || '—';
                        const eventType = e.event_type || '—';
                        const severity = e.severity_label || 'info';
                        const sevClass = severity === 'critical' ? 'badge-down' : severity === 'high' ? 'badge-error' : severity === 'medium' ? 'badge-disabled' : severity === 'low' ? 'badge-unknown' : 'badge-up';

                        // Determine event type badge color
                        const typeBadge = eventType === 'trap' ? 'badge-error' : eventType === 'poll' ? 'badge-up' : 'badge-unknown';

                        // Build description cell content
                        const descHtml = oidDesc
                            ? `<span style="font-size:0.8rem; color:var(--text-secondary);">${escapeHtml(oidDesc)}</span>${oidSyntax ? `<br><span style="font-size:0.68rem; color:var(--text-muted); font-style:italic;">${escapeHtml(oidSyntax)}</span>` : ''}`
                            : `<span style="font-size:0.78rem; color:var(--text-muted); font-style:italic;">—</span>`;

                        return `<tr>
                            <td style="white-space:nowrap; font-family:'JetBrains Mono',monospace; font-size:0.75rem;">${e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—'}</td>
                            <td><span class="device-ip" style="font-size:0.82rem;">${escapeHtml(sourceLabel)}</span></td>
                            <td><span class="badge ${typeBadge}" style="font-size:0.7rem; padding:2px 6px;">${escapeHtml(eventType)}</span></td>
                            <td style="font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:var(--text-muted); max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(oid)}">${escapeHtml(oid)}</td>
                            <td style="font-family:'JetBrains Mono',monospace; font-size:0.82rem; color:var(--accent-cyan); font-weight:500;" title="${escapeHtml(oidResolved)}">${escapeHtml(oidResolved)}</td>
                            <td style="max-width:220px;">${descHtml}</td>
                            <td style="font-size:0.82rem; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(value)}">${escapeHtml(truncateValue(value, 40))}</td>
                            <td><span class="badge ${sevClass}" style="font-size:0.7rem; padding:2px 6px;">${escapeHtml(severity)}</span></td>
                        </tr>`;
                    } catch { return ''; }
                }).join('')}</tbody></table></div>`;
        } catch (err) {
            console.error('Logs error:', err);
        }
    }

    function truncateValue(val, maxLen) {
        if (!val || val.length <= maxLen) return val;
        return val.substring(0, maxLen) + '…';
    }

    // ── Event Listeners ───────────────────────────────────────────────

    function init() {
        // Login form
        $('#loginBtn')?.addEventListener('click', doLogin);
        $('#loginPassword')?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') doLogin();
        });
        $('#logoutBtn')?.addEventListener('click', doLogout);

        // Check login state
        if (!isLoggedIn) {
            showLoginScreen();
        }

        // Navigation
        $$('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                navigateTo(item.dataset.page);
            });
        });

        // Mobile menu
        $('#menuToggle').addEventListener('click', () => {
            $('#sidebar').classList.toggle('open');
        });

        // Add device buttons
        $('#addDeviceBtn')?.addEventListener('click', openAddModal);
        $('#dashAddDeviceBtn')?.addEventListener('click', openAddModal);

        // Device form
        $('#deviceForm').addEventListener('submit', handleDeviceSubmit);
        $('#devVersion').addEventListener('change', updateVersionFields);

        // Modal close buttons
        $('#modalClose').addEventListener('click', () => {
            hideModal('deviceModal');
            $('#devName').disabled = false;
        });
        $('#modalCancelBtn').addEventListener('click', () => {
            hideModal('deviceModal');
            $('#devName').disabled = false;
        });

        // Delete modal
        $('#deleteModalClose').addEventListener('click', () => hideModal('deleteModal'));
        $('#deleteCancelBtn').addEventListener('click', () => hideModal('deleteModal'));
        $('#deleteConfirmBtn').addEventListener('click', deleteDevice);

        // API Key modal
        $('#apiKeyIndicator').addEventListener('click', openApiKeyModal);
        $('#apiKeyModalClose').addEventListener('click', () => hideModal('apiKeyModal'));
        $('#apiKeyCancelBtn').addEventListener('click', () => hideModal('apiKeyModal'));
        $('#apiKeySaveBtn').addEventListener('click', saveApiKey);

        // Refresh button
        $('#refreshBtn').addEventListener('click', () => {
            $('#refreshBtn').classList.add('spinning');
            refreshCurrentPage();
            setTimeout(() => $('#refreshBtn').classList.remove('spinning'), 800);
        });

        // OID lookup
        $('#oidLookupBtn')?.addEventListener('click', resolveOID);
        $('#oidLookupInput')?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') resolveOID();
        });

        // Device search
        $('#deviceSearch')?.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            $$('#devicesTableContainer tbody tr').forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            });
        });

        // Close modals on overlay click
        $$('.modal-overlay').forEach(overlay => {
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay) {
                    hideModal(overlay.id);
                    $('#devName').disabled = false;
                }
            });
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                $$('.modal-overlay.active').forEach(m => {
                    hideModal(m.id);
                    $('#devName').disabled = false;
                });
            }
        });

        // Initial load (only if logged in)
        if (isLoggedIn) {
            loadDashboard();
            refreshTimer = setInterval(refreshCurrentPage, REFRESH_INTERVAL);
            // Start checking for active polls every 3 seconds
            progressTimer = setInterval(loadPollProgress, 3000);
        }
    }

    // Start when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
