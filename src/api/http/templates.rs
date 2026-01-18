//! Embedded HTML templates for the web dashboard.
//! AXIOM Design System - Industrial-Military Visual Language

/// Main dashboard HTML template.
pub const HOME: &str = r#"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>DAZHBOG // FUNCTION INDEX TERMINAL</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* ═══════════════════════════════════════════════════════════════
           AXIOM DESIGN SYSTEM - Industrial Military Visual Language
           Classification: OPERATIONAL // Document: DZB-SYS-001
           ═══════════════════════════════════════════════════════════════ */
        
        :root {
            /* Base Colors - Control Room Atmosphere */
            --bg-void: #050505;
            --bg-base: #0a0a0a;
            --bg-panel: #0f0f0f;
            --bg-element: #141414;
            --bg-elevated: #1a1a1a;
            
            /* Borders & Lines */
            --border-dim: #1f1f1f;
            --border-subtle: #2a2a2a;
            --border-focus: #3a3a3a;
            
            /* Primary Accent - Night Vision / Active Systems */
            --accent: #00ff88;
            --accent-dim: #00cc6a;
            --accent-glow: rgba(0, 255, 136, 0.15);
            --accent-pulse: rgba(0, 255, 136, 0.4);
            
            /* Text Hierarchy */
            --text-bright: #ffffff;
            --text-primary: #e8e8e8;
            --text-secondary: #a0a0a0;
            --text-tertiary: #666666;
            --text-dim: #444444;
            
            /* State Colors - Military Warning Palette */
            --state-nominal: #00ff88;
            --state-caution: #ffaa00;
            --state-warning: #ff6600;
            --state-critical: #ff2244;
            --state-info: #0088ff;
            
            /* Typography */
            --font-display: "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: "JetBrains Mono", "SF Mono", "Consolas", monospace;
            
            /* Spacing Scale */
            --space-xs: 4px;
            --space-sm: 8px;
            --space-md: 16px;
            --space-lg: 24px;
            --space-xl: 32px;
            --space-2xl: 48px;
            
            /* Animation */
            --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
            --ease-in-out: cubic-bezier(0.65, 0, 0.35, 1);
        }
        
        /* ─────────────────────────────────────────────────────────────
           BASE RESET & DOCUMENT
           ───────────────────────────────────────────────────────────── */
        
        *, *::before, *::after { box-sizing: border-box; }
        
        body {
            margin: 0;
            background: var(--bg-void);
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 13px;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Scanline overlay effect */
        body::before {
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: repeating-linear-gradient(
                0deg,
                transparent,
                transparent 2px,
                rgba(0, 0, 0, 0.03) 2px,
                rgba(0, 0, 0, 0.03) 4px
            );
            pointer-events: none;
            z-index: 9999;
        }
        
        /* ─────────────────────────────────────────────────────────────
           DIAGONAL STRIPE PATTERNS
           ───────────────────────────────────────────────────────────── */
        
        .stripe-pattern {
            background: repeating-linear-gradient(
                -45deg,
                transparent,
                transparent 4px,
                var(--border-dim) 4px,
                var(--border-dim) 5px
            );
        }
        
        .stripe-accent {
            background: repeating-linear-gradient(
                -45deg,
                transparent,
                transparent 3px,
                var(--accent) 3px,
                var(--accent) 4px
            );
            opacity: 0.15;
        }
        
        /* ─────────────────────────────────────────────────────────────
           DOT GRID PATTERN
           ───────────────────────────────────────────────────────────── */
        
        .dot-grid {
            background-image: radial-gradient(circle, var(--border-subtle) 1px, transparent 1px);
            background-size: 16px 16px;
        }
        
        /* ─────────────────────────────────────────────────────────────
           MAIN CONTAINER
           ───────────────────────────────────────────────────────────── */
        
        .terminal-frame {
            max-width: 1400px;
            margin: 0 auto;
            padding: var(--space-lg);
            position: relative;
        }
        
        /* Corner registration marks */
        .terminal-frame::before,
        .terminal-frame::after {
            content: "";
            position: absolute;
            width: 24px;
            height: 24px;
            border-color: var(--border-subtle);
            border-style: solid;
        }
        .terminal-frame::before {
            top: 8px;
            left: 8px;
            border-width: 2px 0 0 2px;
        }
        .terminal-frame::after {
            top: 8px;
            right: 8px;
            border-width: 2px 2px 0 0;
        }
        
        /* ─────────────────────────────────────────────────────────────
           HEADER - CLASSIFICATION BANNER
           ───────────────────────────────────────────────────────────── */
        
        .classification-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: var(--space-xs) var(--space-md);
            background: var(--accent);
            color: var(--bg-void);
            font-family: var(--font-mono);
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            margin-bottom: var(--space-md);
        }
        
        .classification-bar .doc-code {
            font-weight: 600;
            letter-spacing: 0.1em;
        }
        
        /* ─────────────────────────────────────────────────────────────
           MAIN HEADER
           ───────────────────────────────────────────────────────────── */
        
        .header-grid {
            display: grid;
            grid-template-columns: 1fr auto 1fr;
            gap: var(--space-lg);
            align-items: start;
            padding: var(--space-lg) 0;
            border-bottom: 1px solid var(--border-subtle);
            margin-bottom: var(--space-xl);
        }
        
        .header-left {
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
        }
        
        .brand-block {
            display: flex;
            align-items: center;
            gap: var(--space-md);
        }
        
        .brand-icon {
            width: 48px;
            height: 48px;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .brand-icon .ring {
            position: absolute;
            border: 2px solid var(--accent);
            border-radius: 50%;
        }
        .brand-icon .ring-outer {
            width: 48px;
            height: 48px;
        }
        .brand-icon .ring-inner {
            width: 32px;
            height: 32px;
        }
        .brand-icon .core {
            width: 12px;
            height: 12px;
            background: var(--accent);
            border-radius: 50%;
            box-shadow: 0 0 20px var(--accent-pulse);
            animation: core-pulse 2s ease-in-out infinite;
        }
        
        @keyframes core-pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(0.9); }
        }
        
        .brand-text {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        
        .brand-name {
            font-family: var(--font-display);
            font-size: 28px;
            font-weight: 900;
            letter-spacing: 0.08em;
            color: var(--text-bright);
            line-height: 1;
        }
        
        .brand-sub {
            font-size: 10px;
            color: var(--text-tertiary);
            letter-spacing: 0.2em;
            text-transform: uppercase;
        }
        
        .serial-block {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        
        .serial-block span {
            display: flex;
            gap: var(--space-sm);
        }
        
        .serial-block .label {
            color: var(--text-tertiary);
            min-width: 60px;
        }
        
        /* Center status ring */
        .header-center {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: var(--space-sm);
        }
        
        .status-ring {
            width: 80px;
            height: 80px;
            border: 3px solid var(--border-subtle);
            border-radius: 50%;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .status-ring::before {
            content: "";
            position: absolute;
            inset: 6px;
            border: 1px solid var(--border-dim);
            border-radius: 50%;
        }
        
        .status-ring .status-core {
            width: 24px;
            height: 24px;
            background: var(--state-nominal);
            border-radius: 50%;
            box-shadow: 0 0 30px var(--accent-pulse), inset 0 0 10px rgba(255,255,255,0.3);
            animation: status-pulse 1.5s ease-in-out infinite;
        }
        
        .status-ring.offline .status-core {
            background: var(--state-critical);
            box-shadow: 0 0 30px rgba(255, 34, 68, 0.4);
            animation: none;
        }
        
        @keyframes status-pulse {
            0%, 100% { box-shadow: 0 0 30px var(--accent-pulse), inset 0 0 10px rgba(255,255,255,0.3); }
            50% { box-shadow: 0 0 50px var(--accent-pulse), inset 0 0 15px rgba(255,255,255,0.5); }
        }
        
        .status-label {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.2em;
            color: var(--accent);
            text-transform: uppercase;
            display: flex;
            align-items: center;
            gap: var(--space-sm);
        }
        
        .status-label::before,
        .status-label::after {
            content: "//";
            color: var(--text-dim);
        }
        
        .status-label.offline {
            color: var(--state-critical);
        }
        
        /* Right side - coordinates and timestamp */
        .header-right {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: var(--space-sm);
            text-align: right;
        }
        
        .coord-block {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        
        .timestamp-block {
            font-size: 18px;
            font-weight: 600;
            color: var(--text-secondary);
            font-variant-numeric: tabular-nums;
        }
        
        .uptime-block {
            font-size: 10px;
            color: var(--text-tertiary);
            letter-spacing: 0.1em;
        }
        
        /* ─────────────────────────────────────────────────────────────
           SEARCH TERMINAL
           ───────────────────────────────────────────────────────────── */
        
        .search-terminal {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            padding: var(--space-lg);
            margin-bottom: var(--space-xl);
            position: relative;
        }
        
        .search-terminal::before {
            content: "QUERY INTERFACE";
            position: absolute;
            top: -8px;
            left: var(--space-md);
            background: var(--bg-panel);
            padding: 0 var(--space-sm);
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-tertiary);
        }
        
        .search-row {
            display: flex;
            gap: var(--space-md);
            align-items: center;
        }
        
        .search-prompt {
            font-size: 14px;
            font-weight: 700;
            color: var(--accent);
            white-space: nowrap;
        }
        
        .search-input-wrap {
            flex: 1;
            position: relative;
        }
        
        .search-input {
            width: 100%;
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            padding: var(--space-md) var(--space-lg);
            font-family: var(--font-mono);
            font-size: 14px;
            color: var(--text-primary);
            outline: none;
            transition: border-color 0.15s, box-shadow 0.15s;
        }
        
        .search-input::placeholder {
            color: var(--text-dim);
        }
        
        .search-input:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow), inset 0 0 20px rgba(0, 255, 136, 0.03);
        }
        
        .search-kbd {
            position: absolute;
            right: var(--space-md);
            top: 50%;
            transform: translateY(-50%);
            font-size: 10px;
            font-weight: 600;
            color: var(--text-dim);
            border: 1px solid var(--border-dim);
            padding: 2px 8px;
            letter-spacing: 0.1em;
        }
        
        .search-meta {
            display: flex;
            gap: var(--space-lg);
            margin-top: var(--space-md);
            padding-top: var(--space-md);
            border-top: 1px dashed var(--border-dim);
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
        }
        
        .search-meta span {
            display: flex;
            align-items: center;
            gap: var(--space-xs);
        }
        
        .search-meta .accent {
            color: var(--accent);
        }
        
        /* ─────────────────────────────────────────────────────────────
           METRICS GRID - OPERATIONAL DASHBOARD
           ───────────────────────────────────────────────────────────── */
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
            margin-bottom: var(--space-xl);
        }
        
        .dashboard-grid.hidden { display: none; }
        
        .metric-section-header {
            grid-column: 1 / -1;
            background: var(--bg-element);
            padding: var(--space-sm) var(--space-md);
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.2em;
            color: var(--text-tertiary);
            text-transform: uppercase;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .metric-section-header .section-code {
            color: var(--text-dim);
            font-weight: 400;
        }
        
        .metric-card {
            background: var(--bg-panel);
            padding: var(--space-lg);
            display: flex;
            flex-direction: column;
            gap: var(--space-xs);
            position: relative;
        }
        
        .metric-card::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 3px;
            height: 100%;
            background: var(--border-subtle);
        }
        
        .metric-card.nominal::before { background: var(--state-nominal); }
        .metric-card.caution::before { background: var(--state-caution); }
        .metric-card.warning::before { background: var(--state-warning); }
        .metric-card.critical::before { background: var(--state-critical); }
        
        .metric-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }
        
        .metric-label {
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-tertiary);
            text-transform: uppercase;
        }
        
        .metric-code {
            font-size: 9px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
        }
        
        .metric-value {
            font-size: 32px;
            font-weight: 700;
            color: var(--text-bright);
            font-variant-numeric: tabular-nums;
            line-height: 1;
            margin: var(--space-sm) 0;
        }
        
        .metric-card.nominal .metric-value { color: var(--state-nominal); }
        .metric-card.critical .metric-value { color: var(--state-critical); }
        .metric-card.warning .metric-value { color: var(--state-warning); }
        
        .metric-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-top: var(--space-sm);
            border-top: 1px dashed var(--border-dim);
        }
        
        .metric-sub {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.05em;
        }
        
        .metric-indicator {
            display: flex;
            gap: 2px;
        }
        
        .metric-indicator .bar {
            width: 3px;
            height: 12px;
            background: var(--border-dim);
        }
        
        .metric-indicator .bar.active { background: var(--accent); }
        .metric-indicator .bar.warn { background: var(--state-warning); }
        .metric-indicator .bar.crit { background: var(--state-critical); }
        
        /* Span two columns */
        .metric-wide {
            grid-column: span 2;
        }
        
        /* ─────────────────────────────────────────────────────────────
           SECONDARY METRICS ROW
           ───────────────────────────────────────────────────────────── */
        
        .metrics-secondary {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
            margin-bottom: var(--space-xl);
        }
        
        .metrics-secondary.hidden { display: none; }
        
        .metric-mini {
            background: var(--bg-panel);
            padding: var(--space-md);
            text-align: center;
        }
        
        .metric-mini .label {
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-dim);
            text-transform: uppercase;
            margin-bottom: var(--space-xs);
        }
        
        .metric-mini .value {
            font-size: 18px;
            font-weight: 700;
            color: var(--text-secondary);
            font-variant-numeric: tabular-nums;
        }
        
        .metric-mini.error .value { color: var(--state-critical); }
        .metric-mini.warn .value { color: var(--state-warning); }
        
        /* ─────────────────────────────────────────────────────────────
           RESULTS CONTAINER
           ───────────────────────────────────────────────────────────── */
        
        .results-container {
            display: none;
        }
        
        .results-container.active {
            display: block;
        }
        
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: var(--space-md);
            background: var(--bg-element);
            border: 1px solid var(--border-subtle);
            border-bottom: none;
        }
        
        .results-title {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.2em;
            color: var(--text-tertiary);
            text-transform: uppercase;
            display: flex;
            align-items: center;
            gap: var(--space-md);
        }
        
        .results-count {
            background: var(--accent);
            color: var(--bg-void);
            padding: 2px 8px;
            font-size: 10px;
            font-weight: 700;
        }
        
        .results-meta {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            display: flex;
            gap: var(--space-lg);
        }
        
        .results-list {
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
        }
        
        .result-item {
            display: grid;
            grid-template-columns: auto 1fr auto;
            gap: var(--space-lg);
            padding: var(--space-lg);
            border-bottom: 1px solid var(--border-dim);
            transition: background 0.1s;
        }
        
        .result-item:last-child {
            border-bottom: none;
        }
        
        .result-item:hover {
            background: var(--bg-element);
        }
        
        .result-index {
            font-size: 10px;
            font-weight: 700;
            color: var(--text-dim);
            padding: var(--space-xs) var(--space-sm);
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            height: fit-content;
            min-width: 36px;
            text-align: center;
        }
        
        .result-main {
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
            min-width: 0;
        }
        
        .result-func {
            font-size: 14px;
            font-weight: 600;
            color: var(--accent);
            word-break: break-all;
            line-height: 1.4;
        }
        
        .result-key {
            font-size: 11px;
            color: var(--text-dim);
            font-family: var(--font-mono);
            display: flex;
            align-items: center;
            gap: var(--space-sm);
        }
        
        .result-mangled {
            font-size: 10px;
            color: var(--text-tertiary);
            font-family: var(--font-mono);
            word-break: break-all;
            line-height: 1.3;
            margin-top: 2px;
            padding: 4px 6px;
            background: rgba(0, 0, 0, 0.3);
            border-left: 2px solid var(--text-tertiary);
            max-height: 40px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .result-mangled:hover {
            max-height: none;
            background: rgba(0, 0, 0, 0.5);
        }
        
        .lang-badge {
            font-size: 9px;
            font-weight: 700;
            color: var(--bg-void);
            background: var(--state-info);
            padding: 2px 6px;
            letter-spacing: 0.1em;
        }
        
        .result-bins {
            display: flex;
            flex-wrap: wrap;
            gap: var(--space-xs);
            margin-top: var(--space-xs);
        }
        
        .bin-tag {
            font-size: 10px;
            color: var(--state-info);
            background: rgba(0, 136, 255, 0.1);
            border: 1px solid rgba(0, 136, 255, 0.2);
            padding: 2px 8px;
            letter-spacing: 0.05em;
        }
        
        .result-meta {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: var(--space-xs);
            text-align: right;
        }
        
        .version-badge {
            font-size: 10px;
            font-weight: 700;
            color: var(--bg-void);
            background: var(--accent);
            padding: 2px 8px;
            letter-spacing: 0.1em;
        }
        
        .score-badge {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.05em;
        }
        
        /* ─────────────────────────────────────────────────────────────
           EMPTY / LOADING STATES
           ───────────────────────────────────────────────────────────── */
        
        .state-message {
            text-align: center;
            padding: var(--space-2xl);
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
        }
        
        .state-message .icon {
            font-size: 32px;
            color: var(--text-dim);
            margin-bottom: var(--space-md);
        }
        
        .state-message h3 {
            font-family: var(--font-display);
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 0.1em;
            color: var(--text-secondary);
            text-transform: uppercase;
            margin: 0 0 var(--space-sm) 0;
        }
        
        .state-message p {
            font-size: 12px;
            color: var(--text-dim);
            margin: 0;
        }
        
        /* ─────────────────────────────────────────────────────────────
           FOOTER - SYSTEM TELEMETRY BAR
           ───────────────────────────────────────────────────────────── */
        
        .telemetry-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: var(--space-md);
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            margin-top: var(--space-xl);
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
        }
        
        .telemetry-left,
        .telemetry-right {
            display: flex;
            gap: var(--space-lg);
        }
        
        .telemetry-item {
            display: flex;
            align-items: center;
            gap: var(--space-xs);
        }
        
        .telemetry-item .dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--text-dim);
        }
        
        .telemetry-item .dot.active { background: var(--state-nominal); }
        .telemetry-item .dot.warn { background: var(--state-warning); }
        .telemetry-item .dot.error { background: var(--state-critical); }
        
        .telemetry-center {
            color: var(--text-tertiary);
        }
        
        /* ─────────────────────────────────────────────────────────────
           DECORATIVE ELEMENTS
           ───────────────────────────────────────────────────────────── */
        
        .bracket-wrap {
            display: inline-flex;
            align-items: center;
            gap: var(--space-xs);
        }
        
        .bracket-wrap::before { content: "["; color: var(--text-dim); }
        .bracket-wrap::after { content: "]"; color: var(--text-dim); }
        
        .direction-indicator {
            color: var(--text-dim);
            letter-spacing: -2px;
        }
        
        .divider-line {
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--border-subtle), transparent);
            margin: var(--space-lg) 0;
        }
        
        .dot-sequence {
            display: flex;
            gap: 4px;
        }
        
        .dot-sequence .dot {
            width: 4px;
            height: 4px;
            border-radius: 50%;
            background: var(--border-subtle);
        }
        
        .dot-sequence .dot.active {
            background: var(--accent);
        }
        
        /* ─────────────────────────────────────────────────────────────
           RESPONSIVE ADJUSTMENTS
           ───────────────────────────────────────────────────────────── */
        
        @media (max-width: 1200px) {
            .dashboard-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .metric-wide {
                grid-column: span 1;
            }
            .metrics-secondary {
                grid-template-columns: repeat(3, 1fr);
            }
        }
        
        @media (max-width: 768px) {
            .header-grid {
                grid-template-columns: 1fr;
                gap: var(--space-lg);
                text-align: center;
            }
            .header-left, .header-right {
                align-items: center;
                text-align: center;
            }
            .dashboard-grid,
            .metrics-secondary {
                grid-template-columns: 1fr;
            }
            .metric-wide {
                grid-column: span 1;
            }
            .telemetry-bar {
                flex-direction: column;
                gap: var(--space-md);
            }
            .terminal-frame {
                padding: var(--space-md);
            }
        }
        
        @media (max-width: 480px) {
            .result-item {
                grid-template-columns: 1fr;
                gap: var(--space-md);
            }
            .result-index {
                width: fit-content;
            }
            .result-meta {
                flex-direction: row;
                align-items: center;
            }
        }
    </style>
</head>
<body>
    <div class="terminal-frame">
        <!-- Classification Banner -->
        <div class="classification-bar">
            <span>DAZHBOG FUNCTION INDEX TERMINAL</span>
            <span class="doc-code">DOC: DZB-SYS-001-R4 // OPERATIONAL</span>
        </div>
        
        <!-- Main Header Grid -->
        <header class="header-grid">
            <div class="header-left">
                <div class="brand-block">
                    <div class="brand-icon">
                        <div class="ring ring-outer"></div>
                        <div class="ring ring-inner"></div>
                        <div class="core"></div>
                    </div>
                    <div class="brand-text">
                        <div class="brand-name">DAZHBOG</div>
                        <div class="brand-sub">Function Metadata Server</div>
                    </div>
                </div>
                <div class="serial-block">
                    <span><span class="label">NODE ID</span><span id="node-id">DZB-001-ALPHA</span></span>
                    <span><span class="label">VERSION</span><span id="sys-version">v1.0.0</span></span>
                    <span><span class="label">PROTOCOL</span><span>LUMINA/TCP</span></span>
                </div>
            </div>
            
            <div class="header-center">
                <div class="status-ring" id="status-ring">
                    <div class="status-core"></div>
                </div>
                <div class="status-label" id="status-label">OPERATIONAL</div>
            </div>
            
            <div class="header-right">
                <div class="timestamp-block" id="timestamp">00:00:00</div>
                <div class="uptime-block">UPTIME <span id="uptime">0d 0h 0m</span></div>
                <div class="coord-block">
                    <span>LAT 00.0000 // LON 00.0000</span>
                    <span>SECTOR: PRIMARY</span>
                </div>
            </div>
        </header>
        
        <!-- Search Terminal -->
        <section class="search-terminal">
            <div class="search-row">
                <span class="search-prompt">&gt;&gt;&gt;</span>
                <div class="search-input-wrap">
                    <input type="text" id="q" class="search-input" placeholder="ENTER QUERY: function name, binary, or address..." autocomplete="off" spellcheck="false">
                    <span class="search-kbd">ENTER</span>
                </div>
            </div>
            <div class="search-meta">
                <span>MODE: <span class="accent">FULL-TEXT</span></span>
                <span>INDEX: <span class="accent" id="index-status">READY</span></span>
                <span>LIMIT: <span class="accent">25</span></span>
                <span>PRESS <span class="accent">/</span> TO FOCUS</span>
            </div>
        </section>
        
        <!-- Main Content -->
        <main>
            <!-- Primary Metrics Dashboard -->
            <div id="dashboard" class="dashboard-grid">
                <div class="metric-section-header">
                    <span>DATABASE STATUS</span>
                    <span class="section-code">SEC-000</span>
                </div>
                
                <div class="metric-card nominal">
                    <div class="metric-header">
                        <span class="metric-label">Indexed Functions</span>
                        <span class="metric-code">IDX</span>
                    </div>
                    <div class="metric-value" id="m-indexed">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Unique Keys</span>
                        <div class="metric-indicator">
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Storage Used</span>
                        <span class="metric-code">STO</span>
                    </div>
                    <div class="metric-value" id="m-storage">0 B</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Segment Data</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Search Docs</span>
                        <span class="metric-code">DOC</span>
                    </div>
                    <div class="metric-value" id="m-searchdocs">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Searchable</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Unique Binaries</span>
                        <span class="metric-code">BIN</span>
                    </div>
                    <div class="metric-value" id="m-binaries">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Observed</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-section-header">
                    <span>TRAFFIC ANALYSIS</span>
                    <span class="section-code">SEC-001</span>
                </div>
                
                <div class="metric-card nominal">
                    <div class="metric-header">
                        <span class="metric-label">Queries Processed</span>
                        <span class="metric-code">QRY</span>
                    </div>
                    <div class="metric-value" id="m-queried">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Total Lookups</span>
                        <div class="metric-indicator">
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Active RPC</span>
                        <span class="metric-code">RPC</span>
                    </div>
                    <div class="metric-value" id="m-rpc">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Live Connections</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Upstream Relay</span>
                        <span class="metric-code">UPS</span>
                    </div>
                    <div class="metric-value" id="m-upstream">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Lumina Requests</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Upstream Fetched</span>
                        <span class="metric-code">FTC</span>
                    </div>
                    <div class="metric-value" id="m-fetched">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">From Origin</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-section-header">
                    <span>INDEX OPERATIONS</span>
                    <span class="section-code">SEC-002</span>
                </div>
                
                <div class="metric-card nominal">
                    <div class="metric-header">
                        <span class="metric-label">New Functions</span>
                        <span class="metric-code">NEW</span>
                    </div>
                    <div class="metric-value" id="m-new">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Unique Indexed</span>
                        <div class="metric-indicator">
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Pull Operations</span>
                        <span class="metric-code">PUL</span>
                    </div>
                    <div class="metric-value" id="m-pulls">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Metadata Syncs</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Push Operations</span>
                        <span class="metric-code">PSH</span>
                    </div>
                    <div class="metric-value" id="m-pushes">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Submissions</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Scoring Batches</span>
                        <span class="metric-code">SCR</span>
                    </div>
                    <div class="metric-value" id="m-scoring">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Version Selection</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Secondary Metrics Row -->
            <div id="metrics-secondary" class="metrics-secondary">
                <div class="metric-mini error">
                    <div class="label">Errors</div>
                    <div class="value" id="m-errors">0</div>
                </div>
                <div class="metric-mini warn">
                    <div class="label">Timeouts</div>
                    <div class="value" id="m-timeouts">0</div>
                </div>
                <div class="metric-mini warn">
                    <div class="label">Decode Rejects</div>
                    <div class="value" id="m-rejects">0</div>
                </div>
                <div class="metric-mini error">
                    <div class="label">Storage Fails</div>
                    <div class="value" id="m-append">0</div>
                </div>
                <div class="metric-mini warn">
                    <div class="label">Index Overflow</div>
                    <div class="value" id="m-overflow">0</div>
                </div>
                <div class="metric-mini error">
                    <div class="label">Upstream Errors</div>
                    <div class="value" id="m-uperr">0</div>
                </div>
            </div>
            
            <!-- Search Results Container -->
            <div id="results" class="results-container">
                <div class="results-header">
                    <div class="results-title">
                        <span>QUERY RESULTS</span>
                        <span class="results-count" id="results-count">0</span>
                    </div>
                    <div class="results-meta">
                        <span>LATENCY: <span id="results-latency">0ms</span></span>
                        <span>QUERY: "<span id="results-query"></span>"</span>
                    </div>
                </div>
                <div class="results-list" id="results-list"></div>
            </div>
        </main>
        
        <!-- Telemetry Footer -->
        <footer class="telemetry-bar">
            <div class="telemetry-left">
                <div class="telemetry-item">
                    <span class="dot active" id="tel-storage"></span>
                    <span>STORAGE</span>
                </div>
                <div class="telemetry-item">
                    <span class="dot active" id="tel-index"></span>
                    <span>INDEX</span>
                </div>
                <div class="telemetry-item">
                    <span class="dot active" id="tel-network"></span>
                    <span>NETWORK</span>
                </div>
                <div class="telemetry-item">
                    <span class="dot" id="tel-upstream"></span>
                    <span>UPSTREAM</span>
                </div>
            </div>
            <div class="telemetry-center">
                <span id="sys-time"></span>
            </div>
            <div class="telemetry-right">
                <span>PROTOCOL V5+ CLIENTS: <span id="proto-v5">0</span></span>
                <span>LEGACY CLIENTS: <span id="proto-v0">0</span></span>
            </div>
        </footer>
    </div>
    
    <script>
        /* ═══════════════════════════════════════════════════════════════
           DAZHBOG TERMINAL INTERFACE - AXIOM CONTROL SYSTEM
           Document: DZB-JS-001 // Classification: OPERATIONAL
           ═══════════════════════════════════════════════════════════════ */
        
        const el = {
            // Search
            q: document.getElementById('q'),
            indexStatus: document.getElementById('index-status'),
            
            // Dashboard
            dashboard: document.getElementById('dashboard'),
            secondary: document.getElementById('metrics-secondary'),
            results: document.getElementById('results'),
            resultsList: document.getElementById('results-list'),
            resultsCount: document.getElementById('results-count'),
            resultsLatency: document.getElementById('results-latency'),
            resultsQuery: document.getElementById('results-query'),
            
            // Status
            statusRing: document.getElementById('status-ring'),
            statusLabel: document.getElementById('status-label'),
            timestamp: document.getElementById('timestamp'),
            uptime: document.getElementById('uptime'),
            sysTime: document.getElementById('sys-time'),
            
            // Database Stats
            mIndexed: document.getElementById('m-indexed'),
            mStorage: document.getElementById('m-storage'),
            mSearchDocs: document.getElementById('m-searchdocs'),
            mBinaries: document.getElementById('m-binaries'),
            
            // Traffic Metrics
            mQueried: document.getElementById('m-queried'),
            mRpc: document.getElementById('m-rpc'),
            mUpstream: document.getElementById('m-upstream'),
            mFetched: document.getElementById('m-fetched'),
            mNew: document.getElementById('m-new'),
            mPulls: document.getElementById('m-pulls'),
            mPushes: document.getElementById('m-pushes'),
            mScoring: document.getElementById('m-scoring'),
            
            // Error Metrics
            mErrors: document.getElementById('m-errors'),
            mTimeouts: document.getElementById('m-timeouts'),
            mRejects: document.getElementById('m-rejects'),
            mAppend: document.getElementById('m-append'),
            mOverflow: document.getElementById('m-overflow'),
            mUpErr: document.getElementById('m-uperr'),
            
            // Telemetry
            telStorage: document.getElementById('tel-storage'),
            telIndex: document.getElementById('tel-index'),
            telNetwork: document.getElementById('tel-network'),
            telUpstream: document.getElementById('tel-upstream'),
            protoV5: document.getElementById('proto-v5'),
            protoV0: document.getElementById('proto-v0'),
        };
        
        // Format number with commas
        const fmt = n => Number(n).toLocaleString();
        
        // Format bytes to human readable
        const fmtBytes = b => {
            if (b === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(b) / Math.log(k));
            return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        };
        
        // Format uptime from seconds
        const fmtUptime = secs => {
            const days = Math.floor(secs / 86400);
            const hours = Math.floor((secs % 86400) / 3600);
            const mins = Math.floor((secs % 3600) / 60);
            return `${days}d ${hours}h ${mins}m`;
        };
        
        // Escape HTML
        const esc = s => (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        
        // Update system time
        function updateTime() {
            const now = new Date();
            const time = now.toTimeString().split(' ')[0];
            const date = now.toISOString().split('T')[0];
            el.timestamp.textContent = time;
            el.sysTime.textContent = `${date} ${time} UTC`;
        }
        
        // Fetch and update metrics
        let metricsTimer = null;
        
        async function fetchMetrics() {
            try {
                const r = await fetch('/api/metrics');
                if (!r.ok) throw new Error(r.status);
                const d = await r.json();
                
                // Update database stats
                el.mIndexed.textContent = fmt(d.indexed_funcs || 0);
                el.mStorage.textContent = fmtBytes(d.storage_bytes || 0);
                el.mSearchDocs.textContent = fmt(d.search_docs || 0);
                el.mBinaries.textContent = fmt(d.unique_binaries || 0);
                
                // Update traffic metrics
                el.mQueried.textContent = fmt(d.queried_funcs || 0);
                el.mRpc.textContent = fmt(d.active_connections || 0);
                el.mUpstream.textContent = fmt(d.upstream_requests || 0);
                el.mFetched.textContent = fmt(d.upstream_fetched || 0);
                el.mNew.textContent = fmt(d.new_funcs || 0);
                el.mPulls.textContent = fmt(d.pulls || 0);
                el.mPushes.textContent = fmt(d.pushes || 0);
                el.mScoring.textContent = fmt(d.scoring_batches || 0);
                
                // Update error metrics
                el.mErrors.textContent = fmt(d.errors || 0);
                el.mTimeouts.textContent = fmt(d.timeouts || 0);
                el.mRejects.textContent = fmt(d.decoder_rejects || 0);
                el.mAppend.textContent = fmt(d.append_failures || 0);
                el.mOverflow.textContent = fmt(d.index_overflows || 0);
                el.mUpErr.textContent = fmt(d.upstream_errors || 0);
                
                // Update protocol counters
                el.protoV5.textContent = fmt(d.lumina_v5p || 0);
                el.protoV0.textContent = fmt(d.lumina_v0_4 || 0);
                
                // Update status
                el.statusRing.classList.remove('offline');
                el.statusLabel.classList.remove('offline');
                el.statusLabel.textContent = 'OPERATIONAL';
                el.indexStatus.textContent = 'READY';
                
                // Update telemetry dots
                el.telStorage.className = 'dot ' + ((d.append_failures || 0) > 0 ? 'error' : 'active');
                el.telIndex.className = 'dot ' + ((d.index_overflows || 0) > 0 ? 'warn' : 'active');
                el.telNetwork.className = 'dot ' + ((d.errors || 0) > 0 ? 'warn' : 'active');
                el.telUpstream.className = 'dot ' + ((d.upstream_requests || 0) > 0 ? 'active' : '');
                
                // Update uptime from server
                el.uptime.textContent = fmtUptime(d.uptime_secs || 0);
                
            } catch (e) {
                el.statusRing.classList.add('offline');
                el.statusLabel.classList.add('offline');
                el.statusLabel.textContent = 'OFFLINE';
                el.indexStatus.textContent = 'ERROR';
            }
        }
        
        // Run search
        async function runSearch() {
            const query = el.q.value.trim();
            if (!query) {
                el.dashboard.classList.remove('hidden');
                el.secondary.classList.remove('hidden');
                el.results.classList.remove('active');
                return;
            }
            
            el.dashboard.classList.add('hidden');
            el.secondary.classList.add('hidden');
            el.results.classList.add('active');
            el.resultsQuery.textContent = query;
            el.resultsList.innerHTML = `
                <div class="state-message">
                    <div class="icon">&gt;&gt;&gt;</div>
                    <h3>QUERYING INDEX</h3>
                    <p>Processing request...</p>
                </div>
            `;
            
            const t0 = performance.now();
            try {
                const r = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
                if (!r.ok) throw new Error('Query failed: ' + r.status);
                const d = await r.json();
                const t1 = performance.now();
                renderResults(d.results, query, t1 - t0);
            } catch (e) {
                el.resultsList.innerHTML = `
                    <div class="state-message">
                        <div class="icon">!</div>
                        <h3>QUERY ERROR</h3>
                        <p>${esc(e.message)}</p>
                    </div>
                `;
                el.resultsCount.textContent = '0';
            }
        }
        
        // Render search results
        function renderResults(hits, query, latency) {
            el.resultsLatency.textContent = latency.toFixed(1) + 'ms';
            
            if (!hits || hits.length === 0) {
                el.resultsCount.textContent = '0';
                el.resultsList.innerHTML = `
                    <div class="state-message">
                        <div class="icon">[ ]</div>
                        <h3>NO MATCHES FOUND</h3>
                        <p>Query "${esc(query)}" returned no results.</p>
                    </div>
                `;
                return;
            }
            
            el.resultsCount.textContent = hits.length;
            
            const html = hits.map((h, i) => {
                const bins = (h.binary_names || []).map(b => 
                    `<span class="bin-tag">${esc(b)}</span>`
                ).join('');
                
                const idx = String(i + 1).padStart(2, '0');
                
                // Show demangled name if available, with language badge
                const displayName = h.func_name_demangled || h.func_name;
                const langBadge = h.lang ? `<span class="lang-badge">${esc(h.lang.toUpperCase())}</span>` : '';
                const mangledHint = h.func_name_demangled ? 
                    `<div class="result-mangled" title="Mangled name">${esc(h.func_name)}</div>` : '';
                
                return `
                    <div class="result-item">
                        <div class="result-index">${idx}</div>
                        <div class="result-main">
                            <div class="result-func">${esc(displayName)}</div>
                            ${mangledHint}
                            <div class="result-key">KEY ${esc(h.key_hex)}</div>
                            <div class="result-bins">${bins}</div>
                        </div>
                        <div class="result-meta">
                            ${langBadge}
                            <span class="version-badge">V${h.version || 0}</span>
                            <span class="score-badge">SCORE ${Number(h.score).toFixed(2)}</span>
                        </div>
                    </div>
                `;
            }).join('');
            
            el.resultsList.innerHTML = html;
        }
        
        // Event listeners
        el.q.addEventListener('keydown', e => {
            if (e.key === 'Enter') runSearch();
        });
        
        el.q.addEventListener('input', () => {
            if (el.q.value.trim() === '') {
                el.dashboard.classList.remove('hidden');
                el.secondary.classList.remove('hidden');
                el.results.classList.remove('active');
            }
        });
        
        document.addEventListener('keydown', e => {
            if (e.key === '/' && document.activeElement !== el.q) {
                e.preventDefault();
                el.q.focus();
            }
        });
        
        // Initialize
        updateTime();
        setInterval(updateTime, 1000);
        fetchMetrics();
        metricsTimer = setInterval(fetchMetrics, 5000);
    </script>
</body>
</html>
"#;
