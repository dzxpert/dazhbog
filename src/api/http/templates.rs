//! Embedded HTML templates for the web dashboard.

/// Main dashboard HTML template.
pub const HOME: &str = r#"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dazhbog // Function Index</title>
    <style>
        :root {
            --bg-app: #09090b;
            --bg-panel: #121214;
            --bg-element: #1c1c1f;
            --border-subtle: #27272a;
            --border-focus: #3f3f46;
            --text-primary: #ededed;
            --text-secondary: #a1a1aa;
            --text-tertiary: #71717a;
            --text-mono: #d4d4d8;
            --accent-primary: #fafafa;
            --accent-glow: rgba(255, 255, 255, 0.08);
            --state-success: #10b981;
            --state-warning: #f59e0b;
            --state-error: #ef4444;
            --state-info: #3b82f6;
            --font-sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            --font-mono: "JetBrains Mono", "SF Mono", Consolas, monospace;
            --radius-md: 6px;
            --radius-sm: 4px;
            --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            background: var(--bg-app);
            color: var(--text-primary);
            font-family: var(--font-sans);
            -webkit-font-smoothing: antialiased;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            overflow-y: scroll;
        }
        .app-container {
            width: 100%;
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px 24px;
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 48px;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border-subtle);
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 600;
            letter-spacing: -0.02em;
            font-size: 18px;
        }
        .brand-icon {
            width: 20px;
            height: 20px;
            background: var(--accent-primary);
            border-radius: 2px;
        }
        .status-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            font-family: var(--font-mono);
            color: var(--text-secondary);
            background: var(--bg-panel);
            padding: 4px 10px;
            border: 1px solid var(--border-subtle);
            border-radius: 99px;
        }
        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--state-success);
            box-shadow: 0 0 8px rgba(16, 185, 129, 0.4);
        }
        .search-section { display: flex; flex-direction: column; gap: 16px; }
        .input-wrapper { position: relative; }
        .search-input {
            width: 100%;
            background: var(--bg-app);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md);
            padding: 16px 16px 16px 48px;
            font-size: 16px;
            color: var(--text-primary);
            font-family: var(--font-mono);
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }
        .search-input:focus {
            outline: none;
            border-color: var(--text-tertiary);
            box-shadow: 0 0 0 4px var(--accent-glow);
        }
        .search-icon {
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-tertiary);
            pointer-events: none;
        }
        .search-kbd {
            position: absolute;
            right: 16px;
            top: 50%;
            transform: translateY(-50%);
            font-family: var(--font-sans);
            font-size: 11px;
            color: var(--text-tertiary);
            border: 1px solid var(--border-subtle);
            padding: 2px 6px;
            border-radius: 4px;
            pointer-events: none;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            opacity: 1;
            transition: opacity 0.2s var(--ease-out);
        }
        .dashboard.hidden { display: none; opacity: 0; }
        .metric-card {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md);
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .metric-card.danger { border-left: 2px solid var(--state-error); }
        .metric-card.warn { border-left: 2px solid var(--state-warning); }
        .metric-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-tertiary);
            font-weight: 600;
        }
        .metric-value {
            font-family: var(--font-mono);
            font-size: 24px;
            color: var(--text-primary);
            font-weight: 500;
        }
        .metric-sub { font-size: 12px; color: var(--text-secondary); margin-top: 4px; }
        .section-header {
            grid-column: 1 / -1;
            margin-top: 16px;
            margin-bottom: 8px;
            font-size: 12px;
            color: var(--text-tertiary);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .section-header::after { content: ""; flex: 1; height: 1px; background: var(--border-subtle); }
        .results-container { display: none; flex-direction: column; gap: 12px; }
        .results-container.active { display: flex; }
        .results-meta {
            font-size: 13px;
            color: var(--text-secondary);
            display: flex;
            justify-content: space-between;
            padding: 0 4px;
        }
        .result-item {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md);
            padding: 16px;
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 12px;
            transition: transform 0.1s ease, border-color 0.1s ease;
        }
        .result-item:hover { transform: translateY(-1px); border-color: var(--border-focus); }
        .result-main { display: flex; flex-direction: column; gap: 6px; overflow: hidden; }
        .func-name {
            font-family: var(--font-mono);
            font-size: 14px;
            color: var(--text-mono);
            word-break: break-all;
            line-height: 1.4;
        }
        .func-key { font-family: var(--font-mono); font-size: 11px; color: var(--text-tertiary); }
        .result-meta { text-align: right; display: flex; flex-direction: column; align-items: flex-end; gap: 6px; }
        .score-badge {
            font-size: 11px;
            background: var(--bg-element);
            color: var(--text-secondary);
            padding: 2px 6px;
            border-radius: 3px;
        }
        .bin-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
        .bin-tag {
            font-size: 11px;
            color: var(--state-info);
            background: rgba(59, 130, 246, 0.1);
            padding: 2px 6px;
            border-radius: 3px;
            white-space: nowrap;
        }
        .state-msg { text-align: center; padding: 64px 0; color: var(--text-secondary); }
        .state-msg h3 { color: var(--text-primary); margin: 0 0 8px 0; font-size: 16px; }
        .state-msg p { font-size: 13px; margin: 0; }
        @media (max-width: 768px) { .dashboard { grid-template-columns: 1fr 1fr; } }
        @media (max-width: 480px) { .dashboard { grid-template-columns: 1fr; } .app-container { padding: 20px 16px; } }
    </style>
</head>
<body>
    <div class="app-container">
        <header>
            <div class="brand"><div class="brand-icon"></div><span>DAZHBOG</span></div>
            <div class="status-badge">
                <div class="status-dot" id="status-dot"></div>
                <span id="node-status">ONLINE</span>
            </div>
        </header>
        <section class="search-section">
            <div class="input-wrapper">
                <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
                <input type="text" id="q" class="search-input" placeholder="Search functions, binaries, or addresses..." autocomplete="off" spellcheck="false">
                <div class="search-kbd">/</div>
            </div>
        </section>
        <main>
            <div id="dashboard" class="dashboard">
                <div class="section-header">Traffic &amp; Load</div>
                <div class="metric-card"><div class="metric-label">Queries Served</div><div class="metric-value" id="m-queried">0</div><div class="metric-sub">Total Lookups</div></div>
                <div class="metric-card"><div class="metric-label">Active RPC</div><div class="metric-value" id="m-rpc">0</div><div class="metric-sub">Live Connections</div></div>
                <div class="metric-card"><div class="metric-label">Upstream Reqs</div><div class="metric-value" id="m-upstream">0</div><div class="metric-sub">Lumina Relay</div></div>
                <div class="section-header">Index Health</div>
                <div class="metric-card"><div class="metric-label">New Functions</div><div class="metric-value" id="m-new">0</div><div class="metric-sub">Unique Ingested</div></div>
                <div class="metric-card"><div class="metric-label">Pulls</div><div class="metric-value" id="m-pulls">0</div><div class="metric-sub">Metadata Syncs</div></div>
                <div class="metric-card"><div class="metric-label">Pushes</div><div class="metric-value" id="m-pushes">0</div><div class="metric-sub">Submissions</div></div>
                <div class="section-header">Errors &amp; Anomalies</div>
                <div class="metric-card danger"><div class="metric-label">Server Errors</div><div class="metric-value" id="m-errors">0</div></div>
                <div class="metric-card warn"><div class="metric-label">Timeouts</div><div class="metric-value" id="m-timeouts">0</div></div>
                <div class="metric-card warn"><div class="metric-label">Decode Rejects</div><div class="metric-value" id="m-rejects">0</div></div>
                <div class="metric-card danger"><div class="metric-label">Storage Fails</div><div class="metric-value" id="m-append">0</div></div>
            </div>
            <div id="results" class="results-container">
                <div class="results-meta"><span id="results-count">0 results</span><span id="results-latency"></span></div>
                <div id="results-list"></div>
            </div>
        </main>
    </div>
    <script>
        const el={q:document.getElementById('q'),dashboard:document.getElementById('dashboard'),results:document.getElementById('results'),list:document.getElementById('results-list'),count:document.getElementById('results-count'),status:document.getElementById('node-status'),dot:document.getElementById('status-dot'),mQueried:document.getElementById('m-queried'),mRpc:document.getElementById('m-rpc'),mUpstream:document.getElementById('m-upstream'),mNew:document.getElementById('m-new'),mPulls:document.getElementById('m-pulls'),mPushes:document.getElementById('m-pushes'),mErrors:document.getElementById('m-errors'),mTimeouts:document.getElementById('m-timeouts'),mRejects:document.getElementById('m-rejects'),mAppend:document.getElementById('m-append')};
        const fmt=n=>Number(n).toLocaleString();const esc=s=>(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        let metricsTimer=null;
        async function fetchMetrics(){try{const r=await fetch('/api/metrics');if(!r.ok)throw new Error(r.status);const d=await r.json();el.mQueried.textContent=fmt(d.queried_funcs);el.mRpc.textContent=fmt(d.active_connections);el.mUpstream.textContent=fmt(d.upstream_requests);el.mNew.textContent=fmt(d.new_funcs);el.mPulls.textContent=fmt(d.pulls);el.mPushes.textContent=fmt(d.pushes);el.mErrors.textContent=fmt(d.errors);el.mTimeouts.textContent=fmt(d.timeouts);el.mRejects.textContent=fmt(d.decoder_rejects);el.mAppend.textContent=fmt(d.append_failures);el.status.textContent="ONLINE";el.dot.style.background="var(--state-success)";el.dot.style.boxShadow="0 0 8px rgba(16, 185, 129, 0.4)";}catch(e){el.status.textContent="OFFLINE";el.dot.style.background="var(--state-error)";el.dot.style.boxShadow="none";}}
        async function runSearch(){const query=el.q.value.trim();if(!query){el.dashboard.classList.remove('hidden');el.results.classList.remove('active');return;}el.dashboard.classList.add('hidden');el.results.classList.add('active');el.list.innerHTML='<div class="state-msg"><p>Searching index...</p></div>';const t0=performance.now();try{const r=await fetch(`/api/search?q=${encodeURIComponent(query)}`);if(!r.ok)throw new Error('Search failed');const d=await r.json();const t1=performance.now();renderResults(d.results,query,t1-t0);}catch(e){el.list.innerHTML=`<div class="state-msg"><h3>Error</h3><p>${e.message}</p></div>`;}}
        function renderResults(hits,query,latency){if(!hits||hits.length===0){el.list.innerHTML=`<div class="state-msg"><h3>No matches found</h3><p>No functions or binaries matched "${esc(query)}".</p></div>`;el.count.textContent="0 results";return;}el.count.textContent=`${hits.length} result${hits.length===1?'':'s'}`;el.results.querySelector('#results-latency').textContent=`${latency.toFixed(1)}ms`;const html=hits.map(h=>{const bins=(h.binary_names||[]).map(b=>`<span class="bin-tag">${esc(b)}</span>`).join('');return`<div class="result-item"><div class="result-main"><div class="func-name" title="${esc(h.func_name)}">${esc(h.func_name)}</div><div class="func-key">${esc(h.key_hex)}</div><div class="bin-list">${bins}</div></div><div class="result-meta"><span class="score-badge">v${h.version||0}</span><span class="score-badge" style="opacity:0.7">Score ${Number(h.score).toFixed(2)}</span></div></div>`;}).join('');el.list.innerHTML=html;}
        el.q.addEventListener('keydown',e=>{if(e.key==='Enter')runSearch();});
        document.addEventListener('keydown',e=>{if(e.key==='/'&&document.activeElement!==el.q){e.preventDefault();el.q.focus();}});
        fetchMetrics();metricsTimer=setInterval(fetchMetrics,5000);
        el.q.addEventListener('input',()=>{if(el.q.value.trim()===""){el.dashboard.classList.remove('hidden');el.results.classList.remove('active');}});
    </script>
</body>
</html>
"#;
