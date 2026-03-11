/* ═══════════════════════════════════════════════════════════════════════
   SNMP Manager Admin Panel — Application Logic v2
   ═══════════════════════════════════════════════════════════════════════ */
(() => {
    'use strict';

    const API_BASE = '/api/v1';
    const REFRESH_INTERVAL = 10_000;
    let apiKey = localStorage.getItem('snmp_api_key') || '';
    let refreshTimer = null;
    let progressTimer = null;
    let countdownTimer = null;
    let countdownValue = 10;
    let currentEditDevice = null;
    let isLoggedIn = !!apiKey;
    let cachedLogs = [];
    let currentLogFilter = 'all';

    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    // ── API ───────────────────────────────────────────────────────────
    async function apiCall(method, endpoint, body = null) {
        const opts = { method, headers: { 'X-API-Key': apiKey, 'Content-Type': 'application/json' } };
        if (body) opts.body = JSON.stringify(body);
        const res = await fetch(`${API_BASE}${endpoint}`, opts);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
        return data;
    }

    // ── Toast ─────────────────────────────────────────────────────────
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
        setTimeout(() => { toast.classList.add('toast-removing'); setTimeout(() => toast.remove(), 300); }, 4000);
    }

    // ── Navigation ────────────────────────────────────────────────────
    function navigateTo(page) {
        $$('.page').forEach(p => p.classList.remove('active'));
        $$('.nav-item').forEach(n => n.classList.remove('active'));
        $(`#page-${page}`)?.classList.add('active');
        $(`#nav-${page}`)?.classList.add('active');
        $('#sidebar').classList.remove('open');
        window.location.hash = page;
        switch (page) {
            case 'dashboard': loadDashboard(); break;
            case 'devices': loadDevices(); break;
            case 'traps': loadTraps(); break;
            case 'mibs': loadMIBs(); break;
            case 'settings': loadSettings(); break;
        }
    }

    // ── Dashboard ─────────────────────────────────────────────────────
    async function loadDashboard() {
        try {
            const [stats, devicesData] = await Promise.all([apiCall('GET', '/stats'), apiCall('GET', '/devices')]);
            const d = stats.devices || {}, p = stats.poller || {}, t = stats.traps || {};
            animateCounter('statTotalValue', d.total ?? 0);
            animateCounter('statUpValue', d.up ?? 0);
            animateCounter('statDownValue', (d.down ?? 0) + (d.error ?? 0));
            animateCounter('statPollsValue', p.total_polls ?? 0, true);
            animateCounter('statTrapsValue', t.total_received ?? 0, true);
            $('#statUptimeValue').textContent = formatUptime(stats.uptime || '0s');
            renderDeviceTable(devicesData.devices || [], '#dashDeviceTable', true);
            loadPollProgress();
            updateServerStatus(true);
        } catch (err) {
            console.error('Dashboard load error:', err);
            updateServerStatus(false);
        }
    }

    function animateCounter(id, target, formatted = false) {
        const el = $(`#${id}`);
        if (!el) return;
        const display = formatted ? formatNumber(target) : String(target);
        el.textContent = display;
    }

    // ── Devices ───────────────────────────────────────────────────────
    async function loadDevices() {
        try {
            const data = await apiCall('GET', '/devices');
            renderDeviceTable(data.devices || [], '#devicesTableContainer', false);
            updateServerStatus(true);
        } catch (err) {
            console.error('Devices load error:', err);
            updateServerStatus(false);
            $('#devicesTableContainer').innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><p>Failed to load devices</p></div>';
        }
    }

    function renderDeviceTable(devices, containerSel, compact) {
        const container = $(containerSel);
        if (!devices.length) {
            container.innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg><p>No devices configured</p><button class="btn btn-primary btn-sm" onclick="document.getElementById(\'addDeviceBtn\')?.click() || document.getElementById(\'dashAddDeviceBtn\')?.click()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Add First Device</button></div>';
            return;
        }
        const rows = devices.map(d => `
            <tr>
                <td><span class="device-name">${esc(d.name)}</span></td>
                <td><span class="device-ip">${esc(d.ip)}</span></td>
                <td>${getStatusBadge(d.status, d.enabled)}</td>
                <td><span class="mono" style="font-size:0.82rem;">${d.snmp_version?.toUpperCase() || 'v2c'}</span></td>
                ${compact ? '' : `<td>${esc(d.vendor || '—')}</td><td>${esc(d.device_type || '—')}</td>`}
                <td><span class="mono" style="font-size:0.8rem;">${formatNumber(d.poll_count || 0)}</span></td>
                ${compact ? '' : `<td><span class="mono" style="font-size:0.8rem;">${formatNumber(d.trap_count || 0)}</span></td><td style="font-size:0.82rem;">${d.last_poll ? formatTime(d.last_poll) : '—'}</td>`}
                <td><div class="actions-cell">
                    <button class="btn-icon btn-icon-green" onclick="window._pollDevice('${esc(d.name)}')" title="Poll now"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg></button>
                    <button class="btn-icon btn-icon-blue" onclick="window._editDevice('${esc(d.name)}')" title="Edit"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
                    <button class="btn-icon btn-icon-danger" onclick="window._confirmDelete('${esc(d.name)}')" title="Delete"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>
                </div></td>
            </tr>`).join('');
        container.innerHTML = `<table><thead><tr><th>Name</th><th>IP Address</th><th>Status</th><th>Version</th>${compact ? '' : '<th>Vendor</th><th>Type</th>'}<th>Polls</th>${compact ? '' : '<th>Traps</th><th>Last Poll</th>'}<th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`;
    }

    function getStatusBadge(status, enabled) {
        if (!enabled) return '<span class="badge badge-disabled">Disabled</span>';
        const m = { up:'badge-up', down:'badge-down', error:'badge-error', unreachable:'badge-down' };
        return `<span class="badge ${m[status] || 'badge-unknown'}">${status || 'unknown'}</span>`;
    }

    // ── Traps / Logs ──────────────────────────────────────────────────
    async function loadTraps() {
        try {
            const stats = await apiCall('GET', '/stats');
            const t = stats.traps || {};
            animateCounter('trapTotalValue', t.total_received ?? 0);
            animateCounter('trapProcessedValue', t.total_processed ?? 0);
            animateCounter('trapErrorsValue', t.errors ?? 0);
            const items = [
                { label: 'Listen Address', value: t.listen_address || '0.0.0.0:162' },
                { label: 'Total Received', value: t.total_received ?? 0 },
                { label: 'Processed', value: t.total_processed ?? 0 },
                { label: 'Unknown Sources', value: t.unknown_source ?? 0 },
                { label: 'Errors', value: t.errors ?? 0 },
                { label: 'Uptime', value: formatUptime(stats.uptime || '0s') },
            ];
            $('#trapInfoGrid').innerHTML = items.map(i => `<div class="info-item"><div class="info-label">${i.label}</div><div class="info-value">${i.value}</div></div>`).join('');
            loadPipelineStats();
            loadRecentLogs();
            updateServerStatus(true);
        } catch (err) { console.error('Traps load error:', err); updateServerStatus(false); }
    }

    async function loadPipelineStats() {
        try {
            const data = await apiCall('GET', '/pipeline/stats');
            const el = $('#pipelineStatsContainer');
            if (!el) return;
            el.innerHTML = `<div class="info-grid">
                <div class="info-item"><div class="info-label">Events In</div><div class="info-value">${formatNumber(data.events_in || 0)}</div></div>
                <div class="info-item"><div class="info-label">Events Out</div><div class="info-value">${formatNumber(data.events_out || 0)}</div></div>
                <div class="info-item"><div class="info-label">Dropped</div><div class="info-value">${formatNumber(data.events_dropped || 0)}</div></div>
                <div class="info-item"><div class="info-label">Errors</div><div class="info-value">${formatNumber(data.events_errored || 0)}</div></div>
                <div class="info-item"><div class="info-label">Raw Queue</div><div class="info-value">${data.raw_queue_len||0} / ${data.raw_queue_cap||0}</div></div>
                <div class="info-item"><div class="info-label">Output Queue</div><div class="info-value">${data.output_queue_len||0}</div></div>
            </div>`;
        } catch (err) { console.error('Pipeline stats error:', err); }
    }

    async function loadRecentLogs() {
        try {
            const data = await apiCall('GET', '/logs/recent');
            cachedLogs = data.logs || [];
            renderLogs();
        } catch (err) { console.error('Logs error:', err); }
    }

    function renderLogs() {
        const el = $('#recentLogsContainer');
        if (!el) return;
        let logs = cachedLogs;
        const searchQuery = ($('#logSearchInput')?.value || '').toLowerCase();

        // Filter
        if (currentLogFilter !== 'all') {
            logs = logs.filter(e => {
                if (currentLogFilter === 'poll') return e.event_type === 'poll';
                if (currentLogFilter === 'trap') return e.event_type === 'trap';
                if (currentLogFilter === 'critical') return e.severity_label === 'critical';
                if (currentLogFilter === 'high') return e.severity_label === 'high';
                return true;
            });
        }
        if (searchQuery) {
            logs = logs.filter(e => JSON.stringify(e).toLowerCase().includes(searchQuery));
        }

        if (!logs.length) {
            el.innerHTML = '<div class="empty-state"><p>No log entries' + (currentLogFilter !== 'all' ? ' matching filter' : '') + '</p></div>';
            return;
        }

        el.innerHTML = `<div style="font-size:0.74rem;color:var(--text-muted);margin-bottom:6px;">Total: ${cachedLogs.length} entries (showing ${logs.length})</div>
            <div class="table-responsive"><table><thead><tr><th>Time</th><th>Source</th><th>Type</th><th>OID</th><th>Resolved Name</th><th>Description</th><th>Value</th><th>Severity</th></tr></thead><tbody>${logs.map(e => {
                try {
                    if (e.raw) return `<tr><td colspan="8" style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:var(--text-muted);word-break:break-all;">${esc(e.raw)}</td></tr>`;
                    const snmp = e.snmp || {}, source = e.source || {};
                    const oid = snmp.oid || '—', oidResolved = snmp.oid_resolved || snmp.oid_name || oid;
                    const oidDesc = snmp.oid_description || '';
                    const value = snmp.value_string || (snmp.value != null ? String(snmp.value) : '—');
                    const sourceLabel = source.hostname || source.sys_name || source.ip || '—';
                    const eventType = e.event_type || '—';
                    const severity = e.severity_label || 'info';
                    const sevClass = severity === 'critical' ? 'badge-down' : severity === 'high' ? 'badge-error' : severity === 'low' ? 'badge-unknown' : 'badge-up';
                    const typeBadge = eventType === 'trap' ? 'badge-error' : eventType === 'poll' ? 'badge-up' : 'badge-unknown';
                    const rowClass = eventType === 'trap' ? 'log-row-trap' : 'log-row-poll';

                    return `<tr class="${rowClass}">
                        <td style="white-space:nowrap;font-family:'JetBrains Mono',monospace;font-size:0.72rem;">${e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—'}</td>
                        <td><span class="device-ip" style="font-size:0.8rem;">${esc(sourceLabel)}</span></td>
                        <td><span class="badge ${typeBadge}" style="font-size:0.68rem;padding:2px 6px;">${esc(eventType)}</span></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:var(--text-muted);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(oid)}">${esc(oid)}</td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;color:var(--accent-cyan);font-weight:500;" title="${esc(oidResolved)}">${esc(truncate(oidResolved, 30))}</td>
                        <td style="max-width:200px;">${oidDesc ? `<span style="font-size:0.78rem;color:var(--text-secondary);">${esc(truncate(oidDesc, 50))}</span>` : '<span style="color:var(--text-dim);">—</span>'}</td>
                        <td style="font-size:0.8rem;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(value)}">${esc(truncate(value, 35))}</td>
                        <td><span class="badge ${sevClass}" style="font-size:0.68rem;padding:2px 6px;">${esc(severity)}</span></td>
                    </tr>`;
                } catch { return ''; }
            }).join('')}</tbody></table></div>`;
    }

    // ── MIBs ──────────────────────────────────────────────────────────
    async function loadMIBs() {
        try {
            const [countData, groupsData] = await Promise.all([apiCall('GET', '/mibs/count'), apiCall('GET', '/mibs/groups')]);
            const groups = groupsData.groups || {};
            const groupKeys = Object.keys(groups);
            animateCounter('mibTotalOids', countData.total_oids || 0);
            animateCounter('mibTotalGroups', groupKeys.length);
            if (groupKeys.length) {
                $('#mibGroupsContainer').innerHTML = `<div class="mib-groups-grid">${groupKeys.sort().map(g => `<div class="mib-group-card"><div class="mib-group-name">${esc(g)}</div><div class="mib-group-count">${groups[g]} OIDs</div></div>`).join('')}</div>`;
            } else {
                $('#mibGroupsContainer').innerHTML = '<div class="empty-state"><p>No MIB groups loaded</p></div>';
            }
            updateServerStatus(true);
        } catch (err) { console.error('MIBs load error:', err); updateServerStatus(false); }
    }

    async function resolveOID() {
        const oid = $('#oidLookupInput').value.trim();
        if (!oid) return;
        const resultEl = $('#oidResult');
        try {
            const data = await apiCall('GET', `/mibs/resolve/${oid}`);
            resultEl.classList.remove('hidden');
            resultEl.innerHTML = [
                ['OID', data.oid||oid], ['Name', data.name||'—'], ['Module', data.module||'—'],
                ['Type', data.syntax||'—'], ['Description', data.description||'—']
            ].map(([l,v]) => `<div class="oid-result-item"><span class="oid-result-label">${l}:</span><span class="oid-result-value">${esc(v)}</span></div>`).join('');
        } catch (err) {
            resultEl.classList.remove('hidden');
            resultEl.innerHTML = `<div class="oid-result-item"><span class="oid-result-label">Error:</span><span class="oid-result-value" style="color:var(--accent-red);">${esc(err.message)}</span></div>`;
        }
    }

    // ── Settings ──────────────────────────────────────────────────────
    function loadSettings() {
        loadOutputs();
        loadSystemInfo();
        loadServerConfig();
    }

    async function loadOutputs() {
        const container = $('#outputsContainer');
        const statsGrid = $('#outputStatsGrid');
        if (!container) return;
        try {
            const data = await apiCall('GET', '/config/outputs');
            const outputs = data.outputs || [];

            // Stats grid
            const activeCount = outputs.filter(o => o.enabled).length;
            const totalCount = outputs.length;
            const disabledCount = totalCount - activeCount;
            if (statsGrid) {
                statsGrid.innerHTML = `
                    <div class="stat-card"><div class="stat-icon stat-icon-blue"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg></div><div class="stat-info"><span class="stat-value">${totalCount}</span><span class="stat-label">Total Outputs</span></div></div>
                    <div class="stat-card"><div class="stat-icon stat-icon-green"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div><div class="stat-info"><span class="stat-value">${activeCount}</span><span class="stat-label">Active</span></div></div>
                    <div class="stat-card"><div class="stat-icon stat-icon-red"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg></div><div class="stat-info"><span class="stat-value">${disabledCount}</span><span class="stat-label">Disabled</span></div></div>`;
            }

            if (!outputs.length) { container.innerHTML = '<div class="empty-state"><p>No outputs configured</p><button class="btn btn-primary btn-sm" onclick="document.getElementById(\'addOutputBtn\')?.click()">+ Add First Output</button></div>'; return; }

            cachedOutputs = outputs;
            const typeColors = { file:'var(--accent-blue)', stdout:'var(--accent-teal)', syslog:'var(--accent-orange)', http:'var(--accent-purple)', tcp:'var(--accent-green)', elasticsearch:'var(--accent-cyan)' };
            const typeIcons = { file:'📁', stdout:'🖥️', syslog:'📡', http:'🔗', tcp:'🔌', elasticsearch:'🔍' };

            container.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px;">${outputs.map((o, i) => {
                const color = typeColors[o.type] || 'var(--text-secondary)';
                const icon = typeIcons[o.type] || '⚙️';
                const status = o.enabled
                    ? '<span style="color:var(--accent-green);font-weight:600;font-size:0.78rem;">● Active</span>'
                    : '<span style="color:var(--text-muted);font-weight:600;font-size:0.78rem;">○ Disabled</span>';

                // Build details based on output type
                let details = [];
                details.push(['Target', o.target || 'N/A']);

                switch (o.type) {
                    case 'file':
                        if (o.path) details.push(['Path', o.path]);
                        if (o.max_size_mb) details.push(['Max Size', o.max_size_mb + ' MB']);
                        if (o.max_backups) details.push(['Backups', o.max_backups]);
                        if (o.compress) details.push(['Compress', '✓ Enabled']);
                        break;
                    case 'syslog':
                        if (o.protocol) details.push(['Protocol', o.protocol.toUpperCase()]);
                        if (o.format) details.push(['Format', o.format.toUpperCase()]);
                        if (o.tls) details.push(['TLS', '✓ Enabled']);
                        break;
                    case 'http':
                        if (o.tls_skip_verify) details.push(['TLS Verify', '✗ Skipped']);
                        if (o.headers && Object.keys(o.headers).length) details.push(['Headers', Object.keys(o.headers).join(', ')]);
                        break;
                    case 'elasticsearch':
                        if (o.index) details.push(['Index', o.index + '-*']);
                        if (o.addresses && o.addresses.length > 1) details.push(['Nodes', o.addresses.length + ' nodes']);
                        if (o.username) details.push(['Auth', o.username + ':***']);
                        if (o.tls_skip_verify) details.push(['TLS Verify', '✗ Skipped']);
                        break;
                    case 'tcp':
                        details.push(['Protocol', 'TCP (json_lines)']);
                        break;
                    case 'stdout':
                        details.push(['Format', 'Pretty JSON']);
                        break;
                }

                const detailsHtml = details.map(([k, v]) =>
                    `<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--border-light);">
                        <span style="font-size:0.74rem;color:var(--text-muted);">${k}</span>
                        <span style="font-size:0.74rem;color:var(--text-secondary);font-family:'JetBrains Mono',monospace;text-align:right;max-width:65%;word-break:break-all;">${esc(String(v))}</span>
                    </div>`
                ).join('');

                return `<div class="output-card"><div class="output-card-stripe" style="background:${color};"></div>
                    <div class="output-card-header"><span class="output-card-type">${icon} ${o.type.toUpperCase()}</span>${status}</div>
                    <div style="margin-top:10px;">${detailsHtml}</div>
                    <div style="display:flex;gap:6px;margin-top:10px;padding-top:8px;border-top:1px solid var(--border-color);">
                        <button class="btn btn-ghost btn-sm" onclick="window._toggleOutput(${i})" title="${o.enabled ? 'Disable' : 'Enable'}">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>
                            ${o.enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button class="btn btn-ghost btn-sm" onclick="window._editOutput(${i})" title="Edit">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                            Edit
                        </button>
                        <button class="btn btn-ghost btn-sm" onclick="window._confirmDeleteOutput(${i}, '${esc(o.type)}')" title="Delete" style="color:var(--accent-red);">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                            Delete
                        </button>
                    </div>
                </div>`;
            }).join('')}</div>`;
        } catch (err) { container.innerHTML = `<div class="empty-state"><p>Error loading outputs: ${err.message}</p></div>`; }
    }

    // ── Output CRUD ───────────────────────────────────────────────────
    let currentEditOutputIdx = null;
    let cachedOutputs = [];

    function updateOutputTypeFields() {
        const type = $('#outType').value;
        ['outFileFields','outSyslogFields','outHttpFields','outTcpFields','outEsFields'].forEach(id => {
            $(`#${id}`).classList.add('hidden');
        });
        const fieldMap = { file:'outFileFields', syslog:'outSyslogFields', http:'outHttpFields', tcp:'outTcpFields', elasticsearch:'outEsFields' };
        if (fieldMap[type]) $(`#${fieldMap[type]}`).classList.remove('hidden');
    }

    function openAddOutputModal() {
        currentEditOutputIdx = null;
        $('#outputModalTitle').textContent = 'Add Output';
        $('#outputSubmitBtn').textContent = 'Add Output';
        $('#outputForm').reset();
        $('#outEnabled').checked = true;
        $('#outType').disabled = false;
        updateOutputTypeFields();
        showModal('outputModal');
    }

    function openEditOutputModal(idx) {
        const o = cachedOutputs[idx];
        if (!o) return;
        currentEditOutputIdx = idx;
        $('#outputModalTitle').textContent = 'Edit Output';
        $('#outputSubmitBtn').textContent = 'Save Changes';
        $('#outType').value = o.type;
        $('#outType').disabled = true;
        $('#outEnabled').checked = o.enabled;

        // Fill type-specific fields
        switch (o.type) {
            case 'file':
                $('#outFilePath').value = o.path || '';
                $('#outFileMaxSize').value = o.max_size_mb || 100;
                $('#outFileBackups').value = o.max_backups || 5;
                $('#outFileCompress').checked = !!o.compress;
                break;
            case 'syslog':
                $('#outSyslogAddress').value = o.target?.replace(/^(udp|tcp):\/\//, '') || '';
                $('#outSyslogProtocol').value = o.protocol || 'udp';
                $('#outSyslogFormat').value = o.format || 'cef';
                break;
            case 'http':
                $('#outHttpUrl').value = o.target || '';
                $('#outHttpTlsSkip').checked = !!o.tls_skip_verify;
                $('#outHttpHeaders').value = o.headers ? JSON.stringify(o.headers) : '';
                break;
            case 'tcp':
                $('#outTcpAddress').value = o.target?.replace(/^tcp:\/\//, '') || '';
                break;
            case 'elasticsearch':
                $('#outEsAddresses').value = (o.addresses || []).join(', ');
                $('#outEsIndex').value = o.index || '';
                $('#outEsUsername').value = o.username || '';
                $('#outEsPassword').value = '';
                $('#outEsTlsSkip').checked = !!o.tls_skip_verify;
                break;
        }
        updateOutputTypeFields();
        showModal('outputModal');
    }

    function buildOutputBody() {
        const type = $('#outType').value;
        const body = { type, enabled: $('#outEnabled').checked };

        switch (type) {
            case 'file':
                body.path = $('#outFilePath').value.trim();
                body.max_size_mb = parseInt($('#outFileMaxSize').value) || 100;
                body.max_backups = parseInt($('#outFileBackups').value) || 5;
                body.compress = $('#outFileCompress').checked;
                if (!body.path) { showToast('File path is required', 'error'); return null; }
                break;
            case 'syslog':
                body.address = $('#outSyslogAddress').value.trim();
                body.protocol = $('#outSyslogProtocol').value;
                body.format = $('#outSyslogFormat').value;
                if (!body.address) { showToast('Syslog address is required', 'error'); return null; }
                break;
            case 'http':
                body.url = $('#outHttpUrl').value.trim();
                body.tls_skip_verify = $('#outHttpTlsSkip').checked;
                const hdrs = $('#outHttpHeaders').value.trim();
                if (hdrs) { try { body.headers = JSON.parse(hdrs); } catch { showToast('Invalid headers JSON', 'error'); return null; } }
                if (!body.url) { showToast('URL is required', 'error'); return null; }
                break;
            case 'tcp':
                body.address = $('#outTcpAddress').value.trim();
                if (!body.address) { showToast('TCP address is required', 'error'); return null; }
                break;
            case 'elasticsearch':
                const addrs = $('#outEsAddresses').value.trim();
                body.addresses = addrs ? addrs.split(',').map(a => a.trim()).filter(Boolean) : [];
                body.index = $('#outEsIndex').value.trim();
                body.username = $('#outEsUsername').value.trim();
                const pw = $('#outEsPassword').value;
                if (pw) body.password = pw;
                body.tls_skip_verify = $('#outEsTlsSkip').checked;
                if (!body.addresses.length) { showToast('At least one ES address is required', 'error'); return null; }
                break;
        }
        return body;
    }

    async function handleOutputSubmit(e) {
        e.preventDefault();
        const body = buildOutputBody();
        if (!body) return;

        try {
            if (currentEditOutputIdx !== null) {
                await apiCall('PUT', `/config/outputs/${currentEditOutputIdx}`, body);
                showToast(`Output updated. Restart to apply.`, 'success');
            } else {
                await apiCall('POST', '/config/outputs', body);
                showToast(`Output added. Restart to activate.`, 'success');
            }
            hideModal('outputModal');
            $('#outType').disabled = false;
            loadOutputs();
        } catch (err) { showToast(err.message, 'error'); }
    }

    let outputToDelete = null;
    function confirmDeleteOutput(idx, typeName) {
        outputToDelete = idx;
        $('#deleteOutputName').textContent = typeName.toUpperCase();
        showModal('deleteOutputModal');
    }
    async function deleteOutputConfirm() {
        if (outputToDelete === null) return;
        try {
            await apiCall('DELETE', `/config/outputs/${outputToDelete}`);
            showToast('Output deleted. Restart to apply.', 'success');
            hideModal('deleteOutputModal');
            outputToDelete = null;
            loadOutputs();
        } catch (err) { showToast(err.message, 'error'); }
    }

    async function toggleOutput(idx) {
        try {
            const data = await apiCall('PATCH', `/config/outputs/${idx}/toggle`);
            showToast(data.message, 'success');
            loadOutputs();
        } catch (err) { showToast(err.message, 'error'); }
    }

    // Expose to inline onclick
    window._toggleOutput = toggleOutput;
    window._editOutput = openEditOutputModal;
    window._confirmDeleteOutput = confirmDeleteOutput;

    async function loadSystemInfo() {
        const container = $('#systemInfoContainer');
        if (!container) return;
        try {
            const data = await apiCall('GET', '/system/info');
            const mem = data.memory || {};
            container.innerHTML = `<div class="sys-info-grid">
                <div class="sys-info-item"><div class="sys-info-value">${esc(data.go_version || '—')}</div><div class="sys-info-label">Go Version</div></div>
                <div class="sys-info-item"><div class="sys-info-value">${data.cpus || '—'}</div><div class="sys-info-label">CPU Cores</div></div>
                <div class="sys-info-item"><div class="sys-info-value">${data.goroutines || '—'}</div><div class="sys-info-label">Goroutines</div></div>
                <div class="sys-info-item"><div class="sys-info-value">${mem.alloc_mb || '—'} MB</div><div class="sys-info-label">Memory In Use</div></div>
                <div class="sys-info-item"><div class="sys-info-value">${mem.sys_mb || '—'} MB</div><div class="sys-info-label">System Memory</div></div>
                <div class="sys-info-item"><div class="sys-info-value">${mem.num_gc || 0}</div><div class="sys-info-label">GC Cycles</div></div>
                <div class="sys-info-item"><div class="sys-info-value">${formatNumber(mem.heap_objects || 0)}</div><div class="sys-info-label">Heap Objects</div></div>
                <div class="sys-info-item"><div class="sys-info-value">${data.os || '—'}/${data.arch || '—'}</div><div class="sys-info-label">OS / Arch</div></div>
                <div class="sys-info-item"><div class="sys-info-value">${data.device_count || 0}</div><div class="sys-info-label">Devices</div></div>
                <div class="sys-info-item"><div class="sys-info-value">${formatUptime(data.uptime || '0s')}</div><div class="sys-info-label">Uptime</div></div>
                <div class="sys-info-item" style="grid-column:span 2;"><div class="sys-info-value" style="font-size:0.88rem;">${data.start_time ? new Date(data.start_time).toLocaleString() : '—'}</div><div class="sys-info-label">Started At</div></div>
            </div>`;
        } catch (err) { container.innerHTML = `<div class="empty-state"><p>System info unavailable: ${err.message}</p></div>`; }
    }

    async function loadServerConfig() {
        const serverEl = $('#serverConfigContainer');
        const trapEl = $('#trapConfigContainer');
        if (!serverEl) return;
        try {
            const data = await apiCall('GET', '/config/server');
            const srv = data.server || {}, poll = data.poller || {}, pipe = data.pipeline || {};
            const tr = data.trap_receiver || {}, apiCfg = data.api || {}, metrics = data.metrics || {};
            const mibCfg = data.mib || {};
            const norm = pipe.normalizer || {};

            serverEl.innerHTML = `<div class="info-grid">
                <div class="info-item"><div class="info-label">Server Name</div><div class="info-value">${esc(srv.name || '—')}</div></div>
                <div class="info-item"><div class="info-label">Log Level</div><div class="info-value">${esc(srv.log_level || '—')}</div></div>
                <div class="info-item"><div class="info-label">Log Format</div><div class="info-value">${esc(srv.log_format || '—')}</div></div>
                <div class="info-item"><div class="info-label">API Listen</div><div class="info-value">${esc(apiCfg.listen_address || '—')}</div></div>
                <div class="info-item"><div class="info-label">Auth Type</div><div class="info-value">${esc(apiCfg.auth_type || '—')}</div></div>
                <div class="info-item"><div class="info-label">API Keys</div><div class="info-value">${apiCfg.api_keys_count || 0} configured</div></div>
                <div class="info-item"><div class="info-label">Poller Workers</div><div class="info-value">${poll.workers || '—'}</div></div>
                <div class="info-item"><div class="info-label">Poll Interval</div><div class="info-value">${esc(poll.default_interval || '—')}</div></div>
                <div class="info-item"><div class="info-label">SNMP Timeout</div><div class="info-value">${esc(poll.timeout || '—')}</div></div>
                <div class="info-item"><div class="info-label">Retries</div><div class="info-value">${poll.retries || '—'}</div></div>
                <div class="info-item"><div class="info-label">Max OIDs/Request</div><div class="info-value">${poll.max_oids_per_request || '—'}</div></div>
                <div class="info-item"><div class="info-label">Pipeline Workers</div><div class="info-value">${pipe.workers || '—'}</div></div>
                <div class="info-item"><div class="info-label">Buffer Size</div><div class="info-value">${formatNumber(pipe.buffer_size || 0)}</div></div>
                <div class="info-item"><div class="info-label">Batch Size</div><div class="info-value">${pipe.batch_size || '—'}</div></div>
                <div class="info-item"><div class="info-label">Flush Interval</div><div class="info-value">${esc(pipe.flush_interval || '—')}</div></div>
                <div class="info-item"><div class="info-label">OID Resolution</div><div class="info-value">${norm.resolve_oid_names ? '✓ Enabled' : '✗ Disabled'}</div></div>
                <div class="info-item"><div class="info-label">DNS Resolution</div><div class="info-value">${norm.resolve_hostnames ? '✓ Enabled' : '✗ Disabled'}</div></div>
                <div class="info-item"><div class="info-label">Metrics</div><div class="info-value">${metrics.enabled ? metrics.listen_address + metrics.path : '✗ Disabled'}</div></div>
                <div class="info-item"><div class="info-label">System MIBs</div><div class="info-value">${mibCfg.load_system_mibs ? '✓ Loaded' : '✗ Disabled'}</div></div>
                <div class="info-item"><div class="info-label">MIB Dirs</div><div class="info-value">${(mibCfg.directories || []).length} directories</div></div>
            </div>`;

            if (trapEl) {
                trapEl.innerHTML = `<div class="info-grid">
                    <div class="info-item"><div class="info-label">Status</div><div class="info-value">${tr.enabled ? '<span style="color:var(--accent-green);">✓ Enabled</span>' : '<span style="color:var(--accent-red);">✗ Disabled</span>'}</div></div>
                    <div class="info-item"><div class="info-label">Listen Address</div><div class="info-value">${esc(tr.listen_address || '—')}</div></div>
                    <div class="info-item"><div class="info-label">SNMPv3 Users</div><div class="info-value">${tr.v3_users_count || 0} configured</div></div>
                </div>`;
            }
        } catch (err) {
            serverEl.innerHTML = `<div class="empty-state"><p>Server config unavailable: ${err.message}</p></div>`;
            if (trapEl) trapEl.innerHTML = `<div class="empty-state"><p>Trap config unavailable</p></div>`;
        }
    }

    // ── Poll Progress ─────────────────────────────────────────────────
    async function loadPollProgress() {
        try {
            const data = await apiCall('GET', '/poller/progress');
            const container = $('#pollProgressContainer');
            if (!container) return;
            const activePolls = Object.values(data.progress || {}).filter(p => p.polling);
            if (!activePolls.length) {
                container.innerHTML = ''; container.style.display = 'none';
                if (progressTimer) { clearInterval(progressTimer); progressTimer = null; }
                return;
            }
            container.style.display = 'block';
            if (!progressTimer) progressTimer = setInterval(loadPollProgress, 2000);
            container.innerHTML = activePolls.map(p => {
                const pct = Math.min(p.percent || 0, 100).toFixed(1);
                return `<div class="poll-progress-card"><div class="poll-progress-header"><div class="poll-progress-device"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg><strong>${esc(p.device)}</strong><span class="poll-progress-badge">Polling...</span></div><div class="poll-progress-stats"><span>${p.progress}/${p.total} OIDs</span><span class="poll-progress-elapsed">${p.elapsed||'...'}</span></div></div><div class="poll-progress-bar-track"><div class="poll-progress-bar-fill" style="width:${pct}%"></div></div><div class="poll-progress-footer"><span class="poll-progress-oid" title="${esc(p.current_oid||'')}">${esc(p.current_oid||'...')}</span><span class="poll-progress-pdus">${formatNumber(p.pdus_found||0)} PDUs</span></div></div>`;
            }).join('');
        } catch (err) { console.error('Poll progress error:', err); }
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
            $$('#oidGroupCheckboxes input').forEach(cb => { cb.checked = (device.oid_groups || []).includes(cb.value); });
            const intervalSec = (device.poll_interval || 60000000000) / 1e9;
            const matchVal = `${intervalSec}s`;
            const opts = ['15s','30s','60s','120s','300s','600s'];
            $('#devPollInterval').value = opts.includes(matchVal) ? matchVal : '60s';
            $('#devName').disabled = true;
            updateVersionFields();
            showModal('deviceModal');
        } catch (err) { showToast(`Failed to load device: ${err.message}`, 'error'); }
    }

    function updateVersionFields() {
        const v = $('#devVersion').value;
        if (v === 'v3') { $('#communityGroup').classList.add('hidden'); $('#v3CredentialsGroup').classList.remove('hidden'); }
        else { $('#communityGroup').classList.remove('hidden'); $('#v3CredentialsGroup').classList.add('hidden'); }
    }

    async function handleDeviceSubmit(e) {
        e.preventDefault();
        const version = $('#devVersion').value;
        const oidGroups = []; $$('#oidGroupCheckboxes input:checked').forEach(cb => oidGroups.push(cb.value));
        const tags = {}; const loc = $('#devTagLocation').value.trim(); const crit = $('#devTagCriticality').value;
        if (loc) tags.location = loc; if (crit) tags.criticality = crit;
        const body = { name:$('#devName').value.trim(), ip:$('#devIP').value.trim(), port:parseInt($('#devPort').value)||161, snmp_version:version, poll_interval:$('#devPollInterval').value, oid_groups:oidGroups.length?oidGroups:['system'], tags:Object.keys(tags).length?tags:undefined, enabled:$('#devEnabled').checked };
        if (version==='v1'||version==='v2c') { body.community=$('#devCommunity').value.trim(); if(!body.community){showToast('Community string is required','error');return;} }
        else if (version==='v3') { body.credentials={username:$('#devV3User').value.trim(),auth_protocol:$('#devV3AuthProto').value,auth_passphrase:$('#devV3AuthPass').value,priv_protocol:$('#devV3PrivProto').value,priv_passphrase:$('#devV3PrivPass').value}; if(!body.credentials.username){showToast('SNMPv3 username is required','error');return;} }
        try {
            if (currentEditDevice) { await apiCall('PUT', `/devices/${currentEditDevice}`, body); showToast(`Device "${currentEditDevice}" updated`, 'success'); }
            else { await apiCall('POST', '/devices', body); showToast(`Device "${body.name}" added`, 'success'); }
            hideModal('deviceModal'); $('#devName').disabled = false; refreshCurrentPage();
        } catch (err) { showToast(err.message, 'error'); }
    }

    // ── Delete ────────────────────────────────────────────────────────
    let deviceToDelete = null;
    function confirmDelete(name) { deviceToDelete = name; $('#deleteDeviceName').textContent = name; showModal('deleteModal'); }
    async function deleteDevice() {
        if (!deviceToDelete) return;
        try { await apiCall('DELETE', `/devices/${deviceToDelete}`); showToast(`Device "${deviceToDelete}" deleted`, 'success'); hideModal('deleteModal'); deviceToDelete=null; refreshCurrentPage(); }
        catch (err) { showToast(err.message, 'error'); }
    }

    async function pollDevice(name) {
        try { const data = await apiCall('POST', `/devices/${name}/poll`); showToast(`Polled "${name}": ${data.events||0} events`, 'success'); refreshCurrentPage(); }
        catch (err) { showToast(`Poll failed: ${err.message}`, 'error'); }
    }

    // ── Export Devices ────────────────────────────────────────────────
    async function exportDevices() {
        try {
            const data = await apiCall('GET', '/devices');
            const blob = new Blob([JSON.stringify(data.devices || [], null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = 'snmp-devices.json'; a.click();
            URL.revokeObjectURL(url);
            showToast('Devices exported', 'success');
        } catch (err) { showToast('Export failed: ' + err.message, 'error'); }
    }

    // ── Modal Helpers ─────────────────────────────────────────────────
    function showModal(id) { $(`#${id}`).classList.add('active'); document.body.style.overflow = 'hidden'; }
    function hideModal(id) { $(`#${id}`).classList.remove('active'); document.body.style.overflow = ''; }

    // ── Server Status ─────────────────────────────────────────────────
    function updateServerStatus(online) {
        const el = $('#serverStatus'); if (!el) return;
        const dot = el.querySelector('.status-dot'); const text = el.querySelector('span');
        dot.className = `status-dot ${online ? 'status-online' : 'status-offline'}`;
        text.textContent = online ? 'Connected' : 'Disconnected';
    }

    // ── API Key ───────────────────────────────────────────────────────
    function openApiKeyModal() { $('#apiKeyInput').value = apiKey; showModal('apiKeyModal'); }
    function saveApiKey() { const key=$('#apiKeyInput').value.trim(); if(key){apiKey=key;localStorage.setItem('snmp_api_key',key);showToast('API key saved','success');hideModal('apiKeyModal');refreshCurrentPage();} }

    // ── Countdown ─────────────────────────────────────────────────────
    function startCountdown() {
        countdownValue = REFRESH_INTERVAL / 1000;
        if (countdownTimer) clearInterval(countdownTimer);
        countdownTimer = setInterval(() => {
            countdownValue--;
            const el = $('#countdownText');
            if (el) el.textContent = `${countdownValue}s`;
            if (countdownValue <= 0) countdownValue = REFRESH_INTERVAL / 1000;
        }, 1000);
    }

    // ── Utility ───────────────────────────────────────────────────────
    function esc(str) { if (typeof str !== 'string') return str; return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
    function formatNumber(n) { if (n >= 1_000_000) return (n/1_000_000).toFixed(1)+'M'; if (n >= 1_000) return (n/1_000).toFixed(1)+'K'; return String(n); }
    function formatUptime(s) {
        let totalSeconds = 0;
        const h = s.match(/(\d+)h/), m = s.match(/(\d+)m/), sec = s.match(/([\d.]+)s/);
        if (h) totalSeconds += parseInt(h[1]) * 3600; if (m) totalSeconds += parseInt(m[1]) * 60; if (sec) totalSeconds += parseFloat(sec[1]);
        if (totalSeconds <= 0) return '0s';
        const days = Math.floor(totalSeconds/86400), hours = Math.floor((totalSeconds%86400)/3600), mins = Math.floor((totalSeconds%3600)/60), secs = Math.floor(totalSeconds%60);
        if (days > 0) return `${days}d ${hours}h`; if (hours > 0) return `${hours}h ${mins}m`; if (mins > 0) return `${mins}m ${secs}s`; return `${secs}s`;
    }
    function formatTime(isoStr) {
        if (!isoStr || isoStr === '0001-01-01T00:00:00Z') return '—';
        const d = new Date(isoStr); const now = new Date(); const diffSec = (now - d) / 1000;
        if (diffSec < 60) return 'just now'; if (diffSec < 3600) return `${Math.floor(diffSec/60)}m ago`; if (diffSec < 86400) return `${Math.floor(diffSec/3600)}h ago`; return d.toLocaleDateString();
    }
    function truncate(val, maxLen) { if (!val || val.length <= maxLen) return val; return val.substring(0, maxLen) + '…'; }

    function refreshCurrentPage() {
        const active = document.querySelector('.nav-item.active');
        const page = active?.dataset.page || 'dashboard';
        switch (page) { case 'dashboard':loadDashboard();break; case 'devices':loadDevices();break; case 'traps':loadTraps();break; case 'mibs':loadMIBs();break; case 'settings':loadSettings();break; }
        countdownValue = REFRESH_INTERVAL / 1000;
    }

    // ── Login / Logout ────────────────────────────────────────────────
    async function doLogin() {
        const username=$('#loginUsername').value.trim(), password=$('#loginPassword').value.trim(), errorEl=$('#loginError');
        errorEl.textContent = '';
        if (!username||!password) { errorEl.textContent='Username and password are required'; return; }
        try {
            const res = await fetch(`${API_BASE}/auth/login`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username,password}) });
            const data = await res.json();
            if (!res.ok) { errorEl.textContent = data.error||'Login failed'; return; }
            if (data.mode==='api_key') { errorEl.textContent='Enter API key directly'; return; }
            apiKey=data.token; isLoggedIn=true; localStorage.setItem('snmp_api_key', apiKey);
            $('#loginOverlay').classList.remove('active');
            showToast('Login successful','success');
            startApp();
        } catch (err) { errorEl.textContent='Connection error'; }
    }
    function doLogout() {
        apiKey=''; isLoggedIn=false; localStorage.removeItem('snmp_api_key');
        if (refreshTimer) clearInterval(refreshTimer);
        if (countdownTimer) clearInterval(countdownTimer);
        if (progressTimer) clearInterval(progressTimer);
        $('#loginOverlay').classList.add('active');
        $('#loginUsername').value=''; $('#loginPassword').value='';
        showToast('Logged out','info');
    }

    // Globals for inline onclick
    window._editDevice = openEditModal;
    window._confirmDelete = confirmDelete;
    window._pollDevice = pollDevice;

    function startApp() {
        loadDashboard();
        refreshTimer = setInterval(refreshCurrentPage, REFRESH_INTERVAL);
        progressTimer = setInterval(loadPollProgress, 3000);
        startCountdown();
    }

    // ── Init ──────────────────────────────────────────────────────────
    function init() {
        // Login
        $('#loginBtn')?.addEventListener('click', doLogin);
        $('#loginPassword')?.addEventListener('keydown', e => { if (e.key==='Enter') doLogin(); });
        $('#logoutBtn')?.addEventListener('click', doLogout);

        if (!isLoggedIn) $('#loginOverlay').classList.add('active');

        // Navigation
        $$('.nav-item').forEach(item => item.addEventListener('click', e => { e.preventDefault(); navigateTo(item.dataset.page); }));
        $('#menuToggle').addEventListener('click', () => $('#sidebar').classList.toggle('open'));

        // Hash routing
        const hash = window.location.hash.replace('#','');
        if (hash && ['dashboard','devices','traps','mibs','settings'].includes(hash)) {
            setTimeout(() => navigateTo(hash), 100);
        }

        // Add device buttons
        $('#addDeviceBtn')?.addEventListener('click', openAddModal);
        $('#dashAddDeviceBtn')?.addEventListener('click', openAddModal);
        $('#exportDevicesBtn')?.addEventListener('click', exportDevices);

        // Device form
        $('#deviceForm').addEventListener('submit', handleDeviceSubmit);
        $('#devVersion').addEventListener('change', updateVersionFields);

        // Modal close buttons
        const closeAndReset = () => { hideModal('deviceModal'); $('#devName').disabled = false; };
        $('#modalClose').addEventListener('click', closeAndReset);
        $('#modalCancelBtn').addEventListener('click', closeAndReset);

        // Delete modal
        $('#deleteModalClose').addEventListener('click', () => hideModal('deleteModal'));
        $('#deleteCancelBtn').addEventListener('click', () => hideModal('deleteModal'));
        $('#deleteConfirmBtn').addEventListener('click', deleteDevice);

        // API Key modal
        $('#apiKeyIndicator').addEventListener('click', openApiKeyModal);
        $('#apiKeyModalClose').addEventListener('click', () => hideModal('apiKeyModal'));
        $('#apiKeyCancelBtn').addEventListener('click', () => hideModal('apiKeyModal'));
        $('#apiKeySaveBtn').addEventListener('click', saveApiKey);

        // Output modal
        $('#addOutputBtn')?.addEventListener('click', openAddOutputModal);
        $('#outputForm')?.addEventListener('submit', handleOutputSubmit);
        $('#outType')?.addEventListener('change', updateOutputTypeFields);
        const closeOutput = () => { hideModal('outputModal'); $('#outType').disabled = false; };
        $('#outputModalClose')?.addEventListener('click', closeOutput);
        $('#outputCancelBtn')?.addEventListener('click', closeOutput);

        // Delete output modal
        $('#deleteOutputModalClose')?.addEventListener('click', () => hideModal('deleteOutputModal'));
        $('#deleteOutputCancelBtn')?.addEventListener('click', () => hideModal('deleteOutputModal'));
        $('#deleteOutputConfirmBtn')?.addEventListener('click', deleteOutputConfirm);

        // Refresh button
        $('#refreshBtn').addEventListener('click', () => {
            $('#refreshBtn').classList.add('spinning');
            refreshCurrentPage();
            setTimeout(() => $('#refreshBtn').classList.remove('spinning'), 800);
        });

        // OID lookup
        $('#oidLookupBtn')?.addEventListener('click', resolveOID);
        $('#oidLookupInput')?.addEventListener('keydown', e => { if (e.key==='Enter') resolveOID(); });

        // Device search
        $('#deviceSearch')?.addEventListener('input', e => {
            const q = e.target.value.toLowerCase();
            $$('#devicesTableContainer tbody tr').forEach(row => { row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none'; });
        });

        // Log search
        $('#logSearchInput')?.addEventListener('input', () => renderLogs());

        // Log filter chips
        $$('#logFilterBar .filter-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                $$('#logFilterBar .filter-chip').forEach(c => c.classList.remove('active','active-red','active-green','active-orange'));
                chip.classList.add('active');
                currentLogFilter = chip.dataset.filter;
                renderLogs();
            });
        });

        // Settings tabs
        $$('#settingsTabNav .tab-item').forEach(tab => {
            tab.addEventListener('click', () => {
                $$('#settingsTabNav .tab-item').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                ['outputs','system','server'].forEach(t => {
                    const el = $(`#settingsTab-${t}`);
                    if (el) el.style.display = tab.dataset.tab === t ? 'block' : 'none';
                });
                if (tab.dataset.tab === 'system') loadSystemInfo();
                if (tab.dataset.tab === 'server') loadServerConfig();
            });
        });

        // System info refresh button
        $('#refreshSysInfoBtn')?.addEventListener('click', loadSystemInfo);

        // Close modals on overlay click
        $$('.modal-overlay').forEach(overlay => {
            overlay.addEventListener('click', e => { if (e.target === overlay) { hideModal(overlay.id); $('#devName').disabled = false; } });
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') $$('.modal-overlay.active').forEach(m => { hideModal(m.id); $('#devName').disabled = false; });
            if (e.key === 'r' && !e.ctrlKey && !e.metaKey && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
                e.preventDefault(); refreshCurrentPage();
            }
        });

        // Start app if logged in
        if (isLoggedIn) startApp();
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
