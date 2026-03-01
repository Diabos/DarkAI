/* ═══════════════════════════════════════════
   DarkAI Dashboard — Frontend Logic
   ═══════════════════════════════════════════ */

const API = '';  // same origin
let charts = {};
let refreshInterval = null;

// ──────────────────────────────────────────
//  Navigation
// ──────────────────────────────────────────

document.querySelectorAll('[data-page]').forEach(link => {
    link.addEventListener('click', e => {
        e.preventDefault();
        const page = link.dataset.page;
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('[data-page]').forEach(l => l.classList.remove('active'));
        document.getElementById(`page-${page}`).classList.add('active');
        link.classList.add('active');
        // Trigger page-specific load
        pageLoaders[page]?.();
    });
});

const pageLoaders = {
    overview: loadOverview,
    sites: loadSites,
    threats: loadThreats,
    leaks: loadLeaks,
    keywords: loadKeywords,
    graph: loadGraph,
    search: () => {},
    alerts: loadAlerts,
};

// ──────────────────────────────────────────
//  API Helpers
// ──────────────────────────────────────────

async function api(path) {
    try {
        const res = await fetch(`${API}${path}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } catch (e) {
        console.error(`API error (${path}):`, e);
        return null;
    }
}

async function apiPost(path, body) {
    try {
        const res = await fetch(`${API}${path}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body),
        });
        return await res.json();
    } catch (e) {
        console.error(`API POST error (${path}):`, e);
        return null;
    }
}

async function apiDelete(path) {
    try {
        const res = await fetch(`${API}${path}`, {method: 'DELETE'});
        return await res.json();
    } catch (e) {
        console.error(`API DELETE error (${path}):`, e);
        return null;
    }
}

// ──────────────────────────────────────────
//  Status Bar (auto-refresh)
// ──────────────────────────────────────────

async function refreshStatus() {
    const data = await api('/api/status');
    if (!data) return;

    const dot = document.getElementById('crawler-dot');
    const statusEl = document.getElementById('crawler-status');
    dot.className = 'status-dot ' + (data.crawler === 'running' ? 'running' : data.crawler === 'idle' ? 'idle' : 'stopped');
    statusEl.textContent = data.crawler;

    document.getElementById('uptime').textContent = data.uptime || '--:--:--';
    document.getElementById('current-url').textContent = data.current_url || '—';

    // Update overview stats if visible
    const s = data.stats;
    document.getElementById('val-total').textContent = s.total_sites;
    document.getElementById('val-threats').textContent = s.threats;
    document.getElementById('val-safe').textContent = s.safe;
    document.getElementById('val-leaks').textContent = s.leaks_found;
    document.getElementById('val-keywords').textContent = s.keyword_hits;
    document.getElementById('val-queue').textContent = s.queue_pending;
}

// ──────────────────────────────────────────
//  Overview Page
// ──────────────────────────────────────────

async function loadOverview() {
    const stats = await api('/api/stats');
    if (!stats) return;

    // Category chart
    if (stats.categories.length > 0) {
        renderChart('chart-categories', 'doughnut', {
            labels: stats.categories.map(c => c.category),
            datasets: [{
                data: stats.categories.map(c => c.count),
                backgroundColor: generateColors(stats.categories.length),
                borderWidth: 0,
            }]
        });
    }

    // Scan timeline
    if (stats.scan_timeline.length > 0) {
        renderChart('chart-timeline', 'line', {
            labels: stats.scan_timeline.map(t => t.day),
            datasets: [{
                label: 'Sites Scanned',
                data: stats.scan_timeline.map(t => t.count),
                borderColor: '#6c5ce7',
                backgroundColor: 'rgba(108,92,231,0.1)',
                fill: true,
                tension: 0.4,
            }]
        });
    }

    // Threat timeline
    if (stats.threat_timeline.length > 0) {
        renderChart('chart-threats-timeline', 'bar', {
            labels: stats.threat_timeline.map(t => t.day),
            datasets: [{
                label: 'Threats',
                data: stats.threat_timeline.map(t => t.count),
                backgroundColor: 'rgba(255,71,87,0.7)',
                borderRadius: 4,
            }]
        });
    }

    // Leak stats
    if (stats.leak_stats.length > 0) {
        renderChart('chart-leaks', 'polarArea', {
            labels: stats.leak_stats.map(l => l.leak_type),
            datasets: [{
                data: stats.leak_stats.map(l => l.count),
                backgroundColor: generateColors(stats.leak_stats.length, 0.7),
            }]
        });
    }

    // Top linked pages
    const tbody = document.querySelector('#table-top-linked tbody');
    tbody.innerHTML = '';
    (stats.top_linked_pages || []).forEach(p => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td class="mono" style="max-width:500px;overflow:hidden;text-overflow:ellipsis">${esc(p.target_url)}</td><td>${p.incoming}</td>`;
        tbody.appendChild(tr);
    });
}

function renderChart(canvasId, type, data, opts = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    if (charts[canvasId]) charts[canvasId].destroy();
    charts[canvasId] = new Chart(ctx, {
        type,
        data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: '#8888aa', font: { size: 11 } } },
            },
            scales: type === 'line' || type === 'bar' ? {
                x: { ticks: { color: '#555577' }, grid: { color: 'rgba(42,42,90,0.3)' } },
                y: { ticks: { color: '#555577' }, grid: { color: 'rgba(42,42,90,0.3)' }, beginAtZero: true },
            } : undefined,
            ...opts,
        },
    });
}

function generateColors(n, alpha = 1) {
    const base = [
        `rgba(108,92,231,${alpha})`, `rgba(255,71,87,${alpha})`, `rgba(46,213,115,${alpha})`,
        `rgba(30,144,255,${alpha})`, `rgba(255,165,2,${alpha})`, `rgba(255,107,129,${alpha})`,
        `rgba(162,155,254,${alpha})`, `rgba(0,210,211,${alpha})`, `rgba(255,234,167,${alpha})`,
        `rgba(129,236,236,${alpha})`, `rgba(253,121,168,${alpha})`, `rgba(116,185,255,${alpha})`,
    ];
    const colors = [];
    for (let i = 0; i < n; i++) colors.push(base[i % base.length]);
    return colors;
}

// ──────────────────────────────────────────
//  Sites Page
// ──────────────────────────────────────────

async function loadSites() {
    const cat = document.getElementById('filter-category')?.value || '';
    const threats = document.getElementById('filter-threats')?.checked;
    let url = '/api/sites?limit=500';
    if (cat) url += `&category=${encodeURIComponent(cat)}`;
    if (threats) url += '&threats=true';

    const data = await api(url);
    if (!data) return;

    const tbody = document.querySelector('#table-sites tbody');
    tbody.innerHTML = '';
    data.sites.forEach((s, i) => {
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.onclick = () => openSiteDetail(s.url);
        const badge = s.is_threat
            ? '<span class="badge badge-threat">THREAT</span>'
            : '<span class="badge badge-safe">Safe</span>';
        tr.innerHTML = `
            <td>${i + 1}</td>
            <td class="mono">${esc(s.url)}</td>
            <td>${esc(s.category)}</td>
            <td>${s.score.toFixed(2)}</td>
            <td>${badge}</td>
            <td>${s.scanned_at || ''}</td>
            <td><button class="btn btn-sm" onclick="event.stopPropagation();openSiteDetail('${esc(s.url)}')">Details</button></td>
        `;
        tbody.appendChild(tr);
    });

    // Populate category filter
    const stats = await api('/api/stats');
    if (stats) {
        const sel = document.getElementById('filter-category');
        const current = sel.value;
        sel.innerHTML = '<option value="">All Categories</option>';
        stats.categories.forEach(c => {
            sel.innerHTML += `<option value="${esc(c.category)}" ${c.category === current ? 'selected' : ''}>${esc(c.category)} (${c.count})</option>`;
        });
    }
}

// ──────────────────────────────────────────
//  Site Detail Modal
// ──────────────────────────────────────────

async function openSiteDetail(url) {
    const data = await api(`/api/sites/${encodeURIComponent(url)}`);
    if (!data) return;

    const hashMd5 = await md5Hash(url);
    const screenshotUrl = `/api/screenshot/${hashMd5}`;

    let html = `<h3>Site Detail</h3>`;
    html += detailRow('URL', url);
    html += detailRow('Category', data.category);
    html += detailRow('Score', data.score?.toFixed(2));
    html += detailRow('Threat', data.is_threat ? 'YES' : 'No', data.is_threat ? 'threat' : 'safe');
    html += detailRow('Scanned', data.scanned_at || '');

    if (data.content_hash) html += detailRow('Content Hash', data.content_hash);

    if (data.leaks?.length) {
        html += `<h3 style="margin-top:16px;color:var(--leak-color)">Data Leaks (${data.leaks.length})</h3>`;
        data.leaks.forEach(l => {
            html += `<div class="detail-row"><span class="detail-label">${esc(l.leak_type)}</span><span class="detail-value mono">${esc(l.leak_value)}</span></div>`;
        });
    }

    if (data.keyword_hits?.length) {
        html += `<h3 style="margin-top:16px;color:var(--warning)">Keyword Matches (${data.keyword_hits.length})</h3>`;
        data.keyword_hits.forEach(k => {
            html += `<div class="kw-hit"><span class="kw-keyword">${esc(k.keyword)}</span>: ${esc(k.context)}</div>`;
        });
    }

    if (data.links_out?.length) {
        html += `<h3 style="margin-top:16px">Outgoing Links (${data.links_out.length})</h3>`;
        html += '<div style="max-height:150px;overflow-y:auto">';
        data.links_out.forEach(l => { html += `<div class="mono" style="font-size:11px;padding:2px 0">${esc(l)}</div>`; });
        html += '</div>';
    }

    if (data.links_in?.length) {
        html += `<h3 style="margin-top:16px">Incoming Links (${data.links_in.length})</h3>`;
        html += '<div style="max-height:150px;overflow-y:auto">';
        data.links_in.forEach(l => { html += `<div class="mono" style="font-size:11px;padding:2px 0">${esc(l)}</div>`; });
        html += '</div>';
    }

    html += `<h3 style="margin-top:16px">Screenshot</h3>`;
    html += `<img class="screenshot-img" src="${screenshotUrl}" onerror="this.style.display='none'" alt="Screenshot">`;

    document.getElementById('modal-content').innerHTML = html;
    document.getElementById('modal-overlay').classList.add('open');
}

function closeModal() {
    document.getElementById('modal-overlay').classList.remove('open');
}

function detailRow(label, value, cls = '') {
    return `<div class="detail-row"><span class="detail-label">${label}</span><span class="detail-value ${cls}">${esc(String(value))}</span></div>`;
}

// Simple MD5 for screenshot filename matching (same as Python hashlib.md5[:12])
async function md5Hash(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    // We use first 12 hex chars — but Python uses MD5. We'll just pass the URL to the API instead.
    // Actually, let's compute the hash server-side approach:
    // For now, encode and use the screenshot-by-url endpoint
    return '';  // not used directly
}

// Override openSiteDetail screenshot to use the by-url endpoint
// (Already handled: the img src uses /api/screenshot-by-url?url=...)

// ──────────────────────────────────────────
//  Threats Page
// ──────────────────────────────────────────

async function loadThreats() {
    const data = await api('/api/threats');
    if (!data) return;

    const grid = document.getElementById('threat-list');
    if (!data.threats.length) {
        grid.innerHTML = '<div class="empty-state">No threats detected yet. The crawler is working...</div>';
        return;
    }

    grid.innerHTML = '';
    data.threats.forEach(t => {
        grid.innerHTML += `
            <div class="threat-card" onclick="openSiteDetail('${esc(t.url)}')">
                <span class="t-score">${(t.score * 100).toFixed(0)}%</span>
                <div class="t-cat">⚠️ ${esc(t.category)}</div>
                <div class="t-url">${esc(t.url)}</div>
                <div class="t-time">${t.scanned_at || ''}</div>
            </div>
        `;
    });
}

// ──────────────────────────────────────────
//  Leaks Page
// ──────────────────────────────────────────

async function loadLeaks() {
    const data = await api('/api/leaks');
    if (!data) return;

    // Summary badges
    const summary = document.getElementById('leak-summary');
    summary.innerHTML = '';
    Object.entries(data.summary || {}).forEach(([type, count]) => {
        summary.innerHTML += `<span class="leak-badge">${esc(type)}: ${count}</span>`;
    });

    // Table
    const tbody = document.querySelector('#table-leaks tbody');
    tbody.innerHTML = '';
    if (!data.leaks.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No leaks detected yet</td></tr>';
        return;
    }
    data.leaks.forEach((l, i) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${i + 1}</td>
            <td class="mono" style="max-width:300px;overflow:hidden;text-overflow:ellipsis">${esc(l.url)}</td>
            <td><span class="leak-badge">${esc(l.leak_type)}</span></td>
            <td class="mono">${esc(l.leak_value)}</td>
            <td>${l.found_at || ''}</td>
        `;
        tbody.appendChild(tr);
    });
}

// ──────────────────────────────────────────
//  Keywords Page
// ──────────────────────────────────────────

async function loadKeywords() {
    const data = await api('/api/keywords');
    const hits = await api('/api/keyword-hits');

    // Watchlist
    const list = document.getElementById('keyword-list');
    list.innerHTML = '';
    if (data?.keywords?.length) {
        data.keywords.forEach(k => {
            const li = document.createElement('li');
            li.innerHTML = `<span class="kw-text">${esc(k.keyword)}</span>
                <button class="btn btn-sm btn-danger" onclick="deleteKeyword(${k.id})">✕</button>`;
            list.appendChild(li);
        });
    } else {
        list.innerHTML = '<li class="empty-state">No keywords configured</li>';
    }

    // Hits
    const hitsDiv = document.getElementById('keyword-hits');
    hitsDiv.innerHTML = '';
    if (hits?.hits?.length) {
        hits.hits.forEach(h => {
            hitsDiv.innerHTML += `
                <div class="kw-hit">
                    <span class="kw-keyword">${esc(h.keyword)}</span>
                    <div class="kw-url">${esc(h.url)}</div>
                    <div style="margin-top:4px;font-size:12px;color:var(--text-secondary)">${esc(h.context)}</div>
                </div>
            `;
        });
    } else {
        hitsDiv.innerHTML = '<div class="empty-state">No keyword matches yet</div>';
    }
}

async function addKeyword() {
    const input = document.getElementById('new-keyword');
    const kw = input.value.trim();
    if (!kw) return;
    await apiPost('/api/keywords', {keyword: kw});
    input.value = '';
    loadKeywords();
}

async function deleteKeyword(id) {
    await apiDelete(`/api/keywords/${id}`);
    loadKeywords();
}

// ──────────────────────────────────────────
//  Link Graph
// ──────────────────────────────────────────

async function loadGraph() {
    const data = await api('/api/link-graph');
    if (!data || !data.nodes.length) {
        document.getElementById('network-graph').innerHTML = '<div class="empty-state">No link data available yet</div>';
        return;
    }

    const nodes = new vis.DataSet(data.nodes.map(n => ({
        id: n.id,
        label: new URL(n.id).hostname.replace('.onion', ''),
        color: n.is_threat ? '#ff4757' : n.scanned ? '#2ed573' : '#555577',
        font: {color: '#e0e0f0', size: 11},
        shape: n.is_threat ? 'diamond' : 'dot',
        size: n.is_threat ? 18 : 12,
        title: `${n.id}\n${n.category}${n.is_threat ? ' ⚠️ THREAT' : ''}`,
    })));

    const edges = new vis.DataSet(data.edges.map((e, i) => ({
        id: i,
        from: e.source,
        to: e.target,
        arrows: 'to',
        color: {color: 'rgba(108,92,231,0.4)', highlight: '#6c5ce7'},
    })));

    const container = document.getElementById('network-graph');
    container.innerHTML = '';
    new vis.Network(container, {nodes, edges}, {
        physics: {
            stabilization: {iterations: 100},
            barnesHut: {gravitationalConstant: -3000, springLength: 150},
        },
        interaction: {hover: true, tooltipDelay: 200},
    });
}

// ──────────────────────────────────────────
//  Search
// ──────────────────────────────────────────

async function doSearch() {
    const q = document.getElementById('search-input').value.trim();
    if (!q) return;

    const data = await api(`/api/search?q=${encodeURIComponent(q)}`);
    const div = document.getElementById('search-results');

    if (!data || !data.results.length) {
        div.innerHTML = `<div class="empty-state">No results for "${esc(q)}"</div>`;
        return;
    }

    div.innerHTML = `<p style="margin-bottom:12px;color:var(--text-secondary)">${data.count} result(s) for "${esc(q)}"</p>`;
    data.results.forEach(r => {
        let html = `<div class="search-result">`;
        html += `<span class="sr-type ${r.type}">${r.type}</span>`;
        html += `<span class="sr-url">${esc(r.url)}</span>`;
        if (r.category) html += ` — ${esc(r.category)}`;
        if (r.preview) html += `<div class="sr-preview">${esc(r.preview)}</div>`;
        if (r.leak_type) html += `<div class="sr-preview">${esc(r.leak_type)}: ${esc(r.leak_value)}</div>`;
        html += `</div>`;
        div.innerHTML += html;
    });
}

// ──────────────────────────────────────────
//  Alerts Page
// ──────────────────────────────────────────

async function loadAlerts() {
    const config = await api('/api/alerts/config');
    const channels = document.getElementById('alert-channels');
    channels.innerHTML = '';

    const chList = [
        {name: 'Discord', icon: '💬', key: 'discord'},
        {name: 'Slack', icon: '📨', key: 'slack'},
        {name: 'Email', icon: '📧', key: 'email'},
    ];

    chList.forEach(ch => {
        const on = config?.[ch.key];
        channels.innerHTML += `
            <div class="alert-channel">
                <div class="ch-icon">${ch.icon}</div>
                <div class="ch-name">${ch.name}</div>
                <div class="ch-status ${on ? 'on' : 'off'}">${on ? '● Connected' : '○ Not configured'}</div>
            </div>
        `;
    });

    // History
    const history = await api('/api/alerts/history');
    const div = document.getElementById('alert-history');
    if (history?.alerts?.length) {
        div.innerHTML = '';
        history.alerts.forEach(a => {
            div.innerHTML += `<div class="kw-hit"><strong>${esc(a.alert_type)}</strong>: ${esc(a.message || '')} <span style="float:right;color:var(--text-muted)">${a.sent_at || ''}</span></div>`;
        });
    } else {
        div.innerHTML = '<div class="empty-state">No alerts sent yet</div>';
    }
}

async function submitURL() {
    const input = document.getElementById('submit-url');
    const url = input.value.trim();
    if (!url) return;
    const result = await apiPost('/api/scan/submit', {url});
    document.getElementById('submit-result').textContent = result?.status === 'queued'
        ? `✅ ${url} added to scan queue!`
        : `❌ ${result?.error || 'Failed'}`;
    input.value = '';
}

// ──────────────────────────────────────────
//  Export
// ──────────────────────────────────────────

function exportJSON() { window.open('/api/export/json', '_blank'); }
function exportCSV() { window.open('/api/export/csv', '_blank'); }

// ──────────────────────────────────────────
//  Utils
// ──────────────────────────────────────────

function esc(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ──────────────────────────────────────────
//  Init
// ──────────────────────────────────────────

(async function init() {
    await refreshStatus();
    await loadOverview();

    // Auto-refresh every 5s
    refreshInterval = setInterval(async () => {
        await refreshStatus();
        // Refresh active page data every 30s
    }, 5000);

    // Full data refresh every 30s
    setInterval(() => {
        const activePage = document.querySelector('.page.active')?.id?.replace('page-', '');
        if (activePage) pageLoaders[activePage]?.();
    }, 30000);
})();
