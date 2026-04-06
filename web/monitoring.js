// =============================================================================
// monitoring.js  —  SNMP Manager Monitoring Panel
// Foydalanadi: /api/v1/monitoring/* endpointlari
// Chart.js 4.x CDN orqali yuklangan bo'lishi kerak
// =============================================================================

(function () {
  'use strict';

  // ── Helpers ──────────────────────────────────────────────────────────────────
  const $ = id => document.getElementById(id);
  const API = window.snmpAPI || { get: (p, k) => fetch(p, { headers: { 'X-API-Key': k || '' } }).then(r => r.json()) };

  function apiKey() {
    return localStorage.getItem('snmp_api_key') || '';
  }

  async function apiFetch(path) {
    const key = apiKey();
    const headers = key ? { 'X-API-Key': key } : {};
    const res = await fetch(path, { headers });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  function fmtTime(iso) {
    const d = new Date(iso);
    return d.toLocaleTimeString('uz', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function fmtDateTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleDateString('uz', { month: 'short', day: 'numeric' }) + ' ' +
      d.toLocaleTimeString('uz', { hour: '2-digit', minute: '2-digit' });
  }

  function sevColor(s) {
    const map = { critical: '#f43f5e', high: '#f97316', medium: '#facc15', low: '#22d3ee', info: '#64748b' };
    return map[s] || '#64748b';
  }

  function sevBg(s) {
    const map = { critical: 'rgba(244,63,94,.15)', high: 'rgba(249,115,22,.15)', medium: 'rgba(250,204,21,.12)', low: 'rgba(34,211,238,.12)', info: 'rgba(100,116,139,.1)' };
    return map[s] || 'rgba(100,116,139,.1)';
  }

  function catIcon(c) {
    const map = { availability: '🟢', network: '🌐', performance: '⚡', environment: '🌡️', security: '🔒', system: '🖥️', storage: '💾', voip: '📞', wireless: '📶', vpn: '🔐', bgp: '🔀', ospf: '📡', vlan: '🏷️', trap: '🔔' };
    return map[c] || '📌';
  }

  // ── Chart instances ───────────────────────────────────────────────────────────
  const chartRegistry = {};

  function destroyChart(id) {
    if (chartRegistry[id]) { chartRegistry[id].destroy(); delete chartRegistry[id]; }
  }

  function makeChart(id, config) {
    destroyChart(id);
    const ctx = $(id);
    if (!ctx) return null;
    const ch = new Chart(ctx, config);
    chartRegistry[id] = ch;
    return ch;
  }

  // ── Palette ───────────────────────────────────────────────────────────────────
  const PALETTE = [
    '#6366f1', '#22d3ee', '#f43f5e', '#f97316', '#a3e635',
    '#facc15', '#c084fc', '#fb7185', '#34d399', '#60a5fa'
  ];

  // ─────────────────────────────────────────────────────────────────────────────
  // STATE
  // ─────────────────────────────────────────────────────────────────────────────
  const state = {
    summary: null,
    selectedIP: null,
    activeMonTab: 'charts',
    deviceCharts: {}, // oid → Chart
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // LOAD SUMMARY
  // ─────────────────────────────────────────────────────────────────────────────
  async function loadSummary() {
    try {
      const data = await apiFetch('/api/v1/monitoring/summary');
      state.summary = data;
      renderSummaryCards(data);
      renderSeverityChart(data.severity_distribution || {});
      renderCategoryChart(data.category_distribution || {});
      renderTopOIDsChart(data.top_oids || []);
      renderDeviceGrid(data.devices || []);
    } catch (e) {
      console.error('Monitoring summary error:', e);
    }
  }

  function renderSummaryCards(data) {
    setText('monTotalDevices', data.total_devices ?? '—');
    setText('monDevicesUp', data.devices_up ?? '—');
    setText('monCritical', data.critical_events_1h ?? '—');
    setText('monTotalEvents', data.total_events_1h ?? '—');

    // Alert badge in nav
    const badge = $('alertBadge');
    if (badge && data.critical_events_1h > 0) {
      badge.textContent = data.critical_events_1h;
      badge.style.display = 'inline-block';
    } else if (badge) {
      badge.style.display = 'none';
    }
  }

  function setText(id, val) {
    const el = $(id);
    if (el) el.textContent = val;
  }

  function renderSeverityChart(dist) {
    const labels = Object.keys(dist);
    const values = Object.values(dist);
    const colors = labels.map(sevColor);

    makeChart('chartMonSeverity', {
      type: 'doughnut',
      data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 2, borderColor: '#0f172a' }] },
      options: {
        responsive: true, maintainAspectRatio: true,
        plugins: {
          legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 11 }, boxWidth: 12, padding: 10 } },
          tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed}` } }
        },
        cutout: '62%'
      }
    });
  }

  function renderCategoryChart(dist) {
    const labels = Object.keys(dist).map(k => catIcon(k) + ' ' + k);
    const values = Object.values(dist);

    makeChart('chartMonCategory', {
      type: 'doughnut',
      data: { labels, datasets: [{ data: values, backgroundColor: PALETTE.slice(0, values.length), borderWidth: 2, borderColor: '#0f172a' }] },
      options: {
        responsive: true, maintainAspectRatio: true,
        plugins: {
          legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 10 }, boxWidth: 10, padding: 8 } },
        },
        cutout: '62%'
      }
    });
  }

  function renderTopOIDsChart(oids) {
    const labels = oids.map(o => o.oid_name.length > 20 ? o.oid_name.slice(0, 20) + '…' : o.oid_name);
    const values = oids.map(o => o.count);

    makeChart('chartMonTopOIDs', {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Event Count',
          data: values,
          backgroundColor: PALETTE.map(c => c + 'cc'),
          borderColor: PALETTE,
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,.04)' } },
          y: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { display: false } }
        }
      }
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // DEVICE GRID
  // ─────────────────────────────────────────────────────────────────────────────
  function renderDeviceGrid(devices) {
    const container = $('monDeviceGrid');
    if (!container) return;

    const search = ($('monDeviceSearch')?.value || '').toLowerCase();
    const filtered = devices.filter(d =>
      d.ip.includes(search) || (d.name || '').toLowerCase().includes(search)
    );

    if (!filtered.length) {
      container.innerHTML = `<div class="empty-state" style="grid-column:1/-1;padding:32px;text-align:center;color:var(--text-muted);">No devices found</div>`;
      return;
    }

    container.innerHTML = filtered.map(d => {
      const statusClass = d.status === 'up' ? 'status-up' : d.status === 'down' ? 'status-down' : 'status-unknown';
      const statusColor = d.status === 'up' ? '#22c55e' : d.status === 'down' ? '#f43f5e' : '#94a3b8';
      const critStyle = d.critical_count > 0 ? 'color:var(--accent-red);font-weight:700;' : '';
      const avgSev = d.avg_severity ? d.avg_severity.toFixed(1) : '0.0';
      const logKB = d.log_bytes > 0 ? (d.log_bytes / 1024).toFixed(0) + ' KB' : '—';
      const lastEvt = d.last_event ? fmtDateTime(d.last_event) : 'No events';

      return `
<div class="mon-device-card" data-ip="${d.ip}" onclick="window.MonitoringModule.openDevice('${d.ip}', '${d.name || d.ip}')">
  <div class="mon-card-header">
    <div style="display:flex;align-items:center;gap:8px;">
      <div style="width:8px;height:8px;border-radius:50%;background:${statusColor};flex-shrink:0;box-shadow:0 0 6px ${statusColor}77;"></div>
      <span style="font-weight:600;font-size:0.88rem;color:var(--text-primary);">${d.name || d.ip}</span>
    </div>
    <span style="font-size:0.72rem;color:var(--text-muted);font-family:'JetBrains Mono',monospace;">${d.ip}</span>
  </div>
  <div class="mon-card-metrics">
    <div class="mon-metric">
      <span class="mon-metric-val">${d.event_count_1h}</span>
      <span class="mon-metric-lbl">Events/1h</span>
    </div>
    <div class="mon-metric">
      <span class="mon-metric-val" style="${critStyle}">${d.critical_count}</span>
      <span class="mon-metric-lbl">Critical</span>
    </div>
    <div class="mon-metric">
      <span class="mon-metric-val">${avgSev}</span>
      <span class="mon-metric-lbl">Avg Sev</span>
    </div>
    <div class="mon-metric">
      <span class="mon-metric-val" style="font-size:0.75rem;">${logKB}</span>
      <span class="mon-metric-lbl">Log Size</span>
    </div>
  </div>
  <div style="font-size:0.72rem;color:var(--text-muted);margin-top:8px;border-top:1px solid var(--border-color);padding-top:8px;">
    🕐 Last: ${lastEvt}
    ${d.top_metric ? `<br>📌 ${d.top_metric}` : ''}
  </div>
</div>`;
    }).join('');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ALERTS
  // ─────────────────────────────────────────────────────────────────────────────
  async function loadAlerts() {
    const container = $('monAlertsContainer');
    if (!container) return;

    try {
      const data = await apiFetch('/api/v1/monitoring/alerts?limit=50');
      const alerts = data.alerts || [];

      $('alertCountBadge').textContent = `(${alerts.length} alerts in 3h)`;

      // Sidebar badge
      const nb = $('alertBadge');
      const critAlerts = alerts.filter(a => a.severity_int >= 10).length;
      if (nb) {
        if (critAlerts > 0) { nb.textContent = critAlerts; nb.style.display = 'inline-block'; }
        else nb.style.display = 'none';
      }

      if (!alerts.length) {
        container.innerHTML = `<div style="text-align:center;padding:24px;color:var(--text-muted);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:32px;height:32px;margin-bottom:8px;color:var(--accent-green);display:block;margin:0 auto 8px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> No active alerts — all clear!</div>`;
        return;
      }

      container.innerHTML = `<table class="data-table">
<thead><tr><th>Time</th><th>Device</th><th>OID</th><th>Value</th><th>Severity</th></tr></thead>
<tbody>
${alerts.map(a => `<tr style="cursor:pointer;" onclick="window.MonitoringModule.openDevice('${a.device_ip}','${a.device_name}')">
  <td style="font-size:0.78rem;white-space:nowrap;">${fmtDateTime(a.time)}</td>
  <td><span style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;">${a.device_name || a.device_ip}</span><br><span style="font-size:0.7rem;color:var(--text-muted);">${a.device_ip}</span></td>
  <td style="font-size:0.8rem;">${a.oid_name || '—'}</td>
  <td style="font-size:0.8rem;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${a.value_str || '—'}</td>
  <td><span style="background:${sevBg(a.severity)};color:${sevColor(a.severity)};padding:2px 8px;border-radius:4px;font-size:0.72rem;font-weight:600;text-transform:uppercase;">${a.severity}</span></td>
</tr>`).join('')}
</tbody></table>`;
    } catch (e) {
      container.innerHTML = `<div style="color:var(--text-muted);padding:16px;">Failed to load alerts: ${e.message}</div>`;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // PER-DEVICE DETAIL
  // ─────────────────────────────────────────────────────────────────────────────
  window.MonitoringModule = {
    openDevice(ip, name) {
      state.selectedIP = ip;
      const panel = $('monDeviceDetailPanel');
      const title = $('monDeviceDetailTitle');
      if (panel) { panel.style.display = 'block'; panel.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
      if (title) title.textContent = `📊 ${name || ip}  (${ip})`;
      loadDeviceDetail();
    }
  };

  async function loadDeviceDetail() {
    if (!state.selectedIP) return;
    const ip = state.selectedIP;
    const hours = $('monTimeRange')?.value || '3';

    // Load analytics
    try {
      const data = await apiFetch(`/api/v1/monitoring/device/${ip}?hours=${hours}`);
      if (state.activeMonTab === 'events') renderRecentEvents(data.recent_events || []);
      if (state.activeMonTab === 'hourly') renderHourlyTrend(data.hourly_trend || []);
    } catch (e) { console.warn('Device analytics error:', e); }

    // Load charts
    if (state.activeMonTab === 'charts') await loadDeviceCharts();

    // Load metrics
    if (state.activeMonTab === 'metrics') await loadDeviceMetrics();
  }

  async function loadDeviceCharts() {
    const ip = state.selectedIP;
    if (!ip) return;
    const hours = $('monTimeRange')?.value || '3';
    const oidF = $('monOIDFilter')?.value || '';
    const container = $('monChartsContainer');
    if (container) container.innerHTML = '<div class="loading-state"><div class="spinner"></div><p>Loading charts…</p></div>';

    try {
      const url = `/api/v1/monitoring/device/${ip}/chart?hours=${hours}${oidF ? '&oid=' + encodeURIComponent(oidF) : ''}`;
      const data = await apiFetch(url);
      const series = data.series || [];

      // Populate OID filter dropdown
      const sel = $('monOIDFilter');
      if (sel && series.length > 0 && sel.options.length < 2) {
        sel.innerHTML = '<option value="">All OIDs</option>' +
          series.map(s => `<option value="${s.oid_name}">${s.oid_name}</option>`).join('');
      }

      if (!container) return;
      if (!series.length) {
        container.innerHTML = `<div style="text-align:center;padding:32px;color:var(--text-muted);grid-column:1/-1;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:48px;height:48px;margin-bottom:12px;opacity:.4;display:block;margin:0 auto 12px;"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          <p>No numeric metrics found for this timeframe.</p>
          <p style="font-size:0.8rem;margin-top:6px;">Only OIDs with numeric values appear as charts.<br>String values (sysDescr, etc.) are shown in the OID Metrics tab.</p>
        </div>`;
        return;
      }

      container.innerHTML = series.map((s, i) =>
        `<div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:var(--radius-md);padding:16px;">
          <div style="font-size:0.82rem;font-weight:600;color:var(--text-primary);margin-bottom:10px;">${s.oid_name}${s.unit ? ' <span style="color:var(--text-muted);font-weight:400;font-size:0.74rem;">(${s.unit})</span>' : ''}</div>
          <canvas id="mon_chart_${i}" height="180"></canvas>
        </div>`
      ).join('');

      // Wait a tick for DOM
      setTimeout(() => {
        series.forEach((s, i) => {
          const color = PALETTE[i % PALETTE.length];
          const labels = s.points.map(p => fmtTime(p.t));
          const values = s.points.map(p => p.v);

          makeChart(`mon_chart_${i}`, {
            type: 'line',
            data: {
              labels,
              datasets: [{
                label: s.oid_name,
                data: values,
                borderColor: color,
                backgroundColor: color + '18',
                borderWidth: 2,
                pointRadius: values.length > 100 ? 0 : 3,
                pointHoverRadius: 5,
                tension: 0.3,
                fill: true
              }]
            },
            options: {
              responsive: true,
              animation: { duration: 400 },
              interaction: { mode: 'index', intersect: false },
              plugins: {
                legend: { display: false },
                tooltip: {
                  callbacks: {
                    title: items => items[0]?.label,
                    label: ctx => ` ${ctx.parsed.y}${s.unit ? ' ' + s.unit : ''}`
                  }
                }
              },
              scales: {
                x: {
                  ticks: { color: '#64748b', maxTicksLimit: 8, font: { size: 10 } },
                  grid: { color: 'rgba(255,255,255,.04)' }
                },
                y: {
                  ticks: { color: '#94a3b8', font: { size: 10 } },
                  grid: { color: 'rgba(255,255,255,.06)' }
                }
              }
            }
          });
        });
      }, 50);

    } catch (e) {
      if (container) container.innerHTML = `<div style="color:var(--text-muted);padding:16px;grid-column:1/-1;">Chart load error: ${e.message}</div>`;
    }
  }

  async function loadDeviceMetrics() {
    const ip = state.selectedIP;
    if (!ip) return;
    const container = $('monMetricsTable');
    if (container) container.innerHTML = '<div class="loading-state"><div class="spinner"></div><p>Loading metrics…</p></div>';

    try {
      const data = await apiFetch(`/api/v1/monitoring/device/${ip}/metrics`);
      const metrics = data.metrics || [];

      if (!container) return;
      if (!metrics.length) {
        container.innerHTML = '<div style="text-align:center;padding:24px;color:var(--text-muted);">No metrics recorded yet.</div>';
        return;
      }

      container.innerHTML = `<table class="data-table">
<thead><tr><th>OID Name</th><th>Value</th><th>Type</th><th>Category</th><th>Severity</th><th>Updated</th></tr></thead>
<tbody>
${metrics.map(m => {
  const numVal = m.metric_value != null ? `<br><span style="font-size:0.72rem;color:var(--accent-cyan);">${m.metric_value}${m.unit ? ' ' + m.unit : ''}</span>` : '';
  return `<tr>
  <td><span style="font-weight:500;font-size:0.82rem;">${m.oid_name || m.oid}</span><br><span style="font-size:0.68rem;color:var(--text-muted);font-family:'JetBrains Mono',monospace;">${m.oid}</span></td>
  <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:0.8rem;">${m.value_str || '—'}${numVal}</td>
  <td style="font-size:0.75rem;color:var(--text-muted);">${m.value_type || '—'}</td>
  <td style="font-size:0.75rem;">${catIcon(m.category)} ${m.category || '—'}</td>
  <td><span style="background:${sevBg(m.severity)};color:${sevColor(m.severity)};padding:1px 6px;border-radius:3px;font-size:0.7rem;font-weight:600;">${m.severity}</span></td>
  <td style="font-size:0.72rem;color:var(--text-muted);white-space:nowrap;">${fmtDateTime(m.updated_at)}</td>
</tr>`;
}).join('')}
</tbody></table>`;
    } catch (e) {
      if (container) container.innerHTML = `<div style="color:var(--text-muted);padding:16px;">Error: ${e.message}</div>`;
    }
  }

  function renderRecentEvents(events) {
    const container = $('monEventsTable');
    if (!container) return;
    if (!events.length) {
      container.innerHTML = '<div style="text-align:center;padding:24px;color:var(--text-muted);">No events in this timeframe.</div>';
      return;
    }
    container.innerHTML = `<table class="data-table">
<thead><tr><th>Time</th><th>OID</th><th>Value</th><th>Category</th><th>Severity</th></tr></thead>
<tbody>
${events.map(e => `<tr>
  <td style="font-size:0.75rem;white-space:nowrap;">${fmtDateTime(e.time)}</td>
  <td style="font-size:0.8rem;font-weight:500;">${e.oid_name || '—'}</td>
  <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:0.8rem;">${e.value_str || '—'}</td>
  <td style="font-size:0.75rem;">${catIcon(e.category)} ${e.category || '—'}</td>
  <td><span style="background:${sevBg(e.severity)};color:${sevColor(e.severity)};padding:1px 6px;border-radius:3px;font-size:0.7rem;font-weight:600;">${e.severity}</span></td>
</tr>`).join('')}
</tbody></table>`;
  }

  function renderHourlyTrend(buckets) {
    const labels = buckets.map(b => {
      const d = new Date(b.hour + ':00:00Z');
      return d.toLocaleTimeString('uz', { hour: '2-digit', minute: '2-digit' });
    });

    makeChart('chartMonHourly', {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            label: 'Total Events',
            data: buckets.map(b => b.count),
            backgroundColor: 'rgba(99,102,241,.5)',
            borderColor: '#6366f1',
            borderWidth: 1,
            borderRadius: 3
          },
          {
            label: 'Critical',
            data: buckets.map(b => b.critical),
            backgroundColor: 'rgba(244,63,94,.6)',
            borderColor: '#f43f5e',
            borderWidth: 1,
            borderRadius: 3
          }
        ]
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: '#94a3b8' } } },
        scales: {
          x: { stacked: false, ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,.04)' } },
          y: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,.06)' } }
        }
      }
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // SUB-TAB SWITCHING
  // ─────────────────────────────────────────────────────────────────────────────
  function initSubTabs() {
    const nav = $('monDeviceTabNav');
    if (!nav) return;
    nav.addEventListener('click', e => {
      const item = e.target.closest('[data-montab]');
      if (!item) return;
      const tab = item.dataset.montab;
      state.activeMonTab = tab;

      // Update active class
      nav.querySelectorAll('.tab-item').forEach(el => el.classList.toggle('active', el.dataset.montab === tab));

      // Show/hide tab content
      ['charts', 'metrics', 'events', 'hourly'].forEach(t => {
        const el = $(`monTab-${t}`);
        if (el) el.style.display = t === tab ? '' : 'none';
      });

      // Load data for the opened tab
      if (tab === 'charts') loadDeviceCharts();
      else if (tab === 'metrics') loadDeviceMetrics();
      else if (tab === 'events' || tab === 'hourly') loadDeviceDetail();
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // INIT & EVENT BINDING
  // ─────────────────────────────────────────────────────────────────────────────
  function initMonitoring() {
    // Refresh alerts button
    const refreshAlertsBtn = $('refreshAlertsBtn');
    if (refreshAlertsBtn) refreshAlertsBtn.addEventListener('click', loadAlerts);

    // Close detail panel
    const closeBtn = $('monCloseDetail');
    if (closeBtn) closeBtn.addEventListener('click', () => {
      const panel = $('monDeviceDetailPanel');
      if (panel) panel.style.display = 'none';
      state.selectedIP = null;
    });

    // Refresh current device
    const refreshDevBtn = $('monRefreshDevice');
    if (refreshDevBtn) refreshDevBtn.addEventListener('click', loadDeviceCharts);

    // Time range change
    const timeRange = $('monTimeRange');
    if (timeRange) timeRange.addEventListener('change', loadDeviceDetail);

    // OID filter
    const oidFilter = $('monOIDFilter');
    if (oidFilter) oidFilter.addEventListener('change', loadDeviceCharts);

    // Device search
    const searchInput = $('monDeviceSearch');
    if (searchInput) searchInput.addEventListener('input', () => {
      if (state.summary) renderDeviceGrid(state.summary.devices || []);
    });

    // Sub-tabs
    initSubTabs();
  }

  // ── Public API ────────────────────────────────────────────────────────────────
  window.loadMonitoringPage = async function () {
    await Promise.all([loadSummary(), loadAlerts()]);
  };

  window.MonitoringModule.reload = loadSummary;

  // ── Auto-inject CSS ───────────────────────────────────────────────────────────
  const monCSS = `
.mon-device-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:var(--radius-md);padding:14px;cursor:pointer;transition:border-color .2s,transform .15s,box-shadow .2s;}
.mon-device-card:hover{border-color:var(--accent-cyan);transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.3);}
.mon-card-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;}
.mon-card-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:10px;}
.mon-metric{text-align:center;background:var(--bg-hover);border-radius:6px;padding:6px 4px;}
.mon-metric-val{display:block;font-size:1rem;font-weight:700;color:var(--text-primary);line-height:1;}
.mon-metric-lbl{display:block;font-size:0.62rem;color:var(--text-muted);margin-top:3px;text-transform:uppercase;letter-spacing:.03em;}
`;
  if (!document.getElementById('monStyleTag')) {
    const style = document.createElement('style');
    style.id = 'monStyleTag';
    style.textContent = monCSS;
    document.head.appendChild(style);
  }

  // Init after DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initMonitoring);
  } else {
    initMonitoring();
  }
})();
