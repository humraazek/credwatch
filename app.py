#!/usr/bin/env python3
"""
Credential Detector - Interactive Web GUI (v2.0)
Evidence-Based Detection, Separated Severity & Confidence,
Context-Aware Classification, and Cross-File Deduplication.

Zero external dependencies - Uses Python standard library only.
"""

import base64
import json
import os
import sys
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from detector import scan_text, scan_zip_bytes, group_findings_by_secret

PORT = 5050

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Credential & Secret Leak Detector v2.0</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #0B0F17;
      --bg-surface: #121824;
      --bg-surface-elevated: #1B2433;
      --border: #233044;
      --border-focus: #3B82F6;
      --text-main: #F3F4F6;
      --text-muted: #94A3B8;
      --accent: #3B82F6;
      --accent-hover: #2563EB;
      --critical: #EF4444;
      --critical-bg: rgba(239, 68, 68, 0.12);
      --high: #F97316;
      --high-bg: rgba(249, 115, 22, 0.12);
      --medium: #F59E0B;
      --medium-bg: rgba(245, 158, 11, 0.12);
      --low: #10B981;
      --low-bg: rgba(16, 185, 129, 0.12);
      --radius: 12px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    header {
      background: rgba(18, 24, 36, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .brand-icon {
      width: 38px;
      height: 38px;
      background: linear-gradient(135deg, #3B82F6, #8B5CF6);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.3rem;
      box-shadow: 0 0 15px rgba(59, 130, 246, 0.4);
    }

    .brand h1 {
      font-size: 1.15rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }

    .brand-sub {
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-top: 1px;
    }

    .badge-status {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      font-size: 0.8rem;
      color: var(--low);
      background: var(--low-bg);
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 0.25rem 0.65rem;
      border-radius: 9999px;
      font-weight: 600;
    }

    .pulse {
      width: 7px;
      height: 7px;
      background-color: var(--low);
      border-radius: 50%;
      animation: pulse 1.8s infinite;
    }

    @keyframes pulse {
      0% { transform: scale(0.95); opacity: 0.8; }
      50% { transform: scale(1.3); opacity: 1; }
      100% { transform: scale(0.95); opacity: 0.8; }
    }

    main {
      flex: 1;
      max-width: 1250px;
      width: 100%;
      margin: 0 auto;
      padding: 2rem;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }

    .card {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.5rem;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
    }

    .tabs {
      display: flex;
      gap: 0.5rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1rem;
      margin-bottom: 1.25rem;
    }

    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: inherit;
      font-weight: 600;
      font-size: 0.95rem;
      padding: 0.5rem 1rem;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .tab-btn:hover {
      color: var(--text-main);
      background: var(--bg-surface-elevated);
    }

    .tab-btn.active {
      color: white;
      background: var(--accent);
    }

    .dropzone {
      border: 2px dashed var(--border);
      border-radius: var(--radius);
      padding: 3rem 1.5rem;
      text-align: center;
      cursor: pointer;
      transition: all 0.2s;
      background: rgba(18, 24, 36, 0.4);
    }

    .dropzone:hover, .dropzone.dragover {
      border-color: var(--accent);
      background: rgba(59, 130, 246, 0.05);
    }

    .dropzone-icon {
      font-size: 2.5rem;
      margin-bottom: 0.75rem;
      display: inline-block;
    }

    .dropzone p {
      color: var(--text-muted);
      font-size: 0.95rem;
    }

    .dropzone strong {
      color: var(--text-main);
    }

    textarea {
      width: 100%;
      min-height: 220px;
      background: var(--bg-base);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text-main);
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.9rem;
      padding: 1rem;
      resize: vertical;
      line-height: 1.5;
    }

    textarea:focus {
      outline: none;
      border-color: var(--border-focus);
    }

    .controls {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 1.25rem;
      flex-wrap: wrap;
      gap: 1rem;
    }

    .samples-bar {
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }

    .sample-chip {
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.82rem;
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 500;
      transition: all 0.15s;
    }

    .sample-chip:hover {
      color: var(--text-main);
      border-color: var(--accent);
      background: rgba(59, 130, 246, 0.1);
    }

    .btn-scan {
      background: var(--accent);
      color: white;
      border: none;
      border-radius: 8px;
      padding: 0.7rem 1.75rem;
      font-family: inherit;
      font-size: 0.95rem;
      font-weight: 700;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      box-shadow: 0 0 15px rgba(59, 130, 246, 0.3);
      transition: all 0.2s;
    }

    .btn-scan:hover {
      background: var(--accent-hover);
      transform: translateY(-1px);
    }

    /* Results section */
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 0.85rem;
      margin-bottom: 1.5rem;
    }

    .metric-card {
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.1rem;
    }

    .metric-title {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.35rem;
    }

    .metric-value {
      font-size: 1.7rem;
      font-weight: 800;
      font-family: 'JetBrains Mono', monospace;
    }

    .metric-critical { color: var(--critical); }
    .metric-high { color: var(--high); }
    .metric-medium { color: var(--medium); }
    .metric-low { color: var(--low); }
    .metric-total { color: var(--text-main); }

    .view-toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 1rem;
      flex-wrap: wrap;
      gap: 0.75rem;
    }

    .view-toggle {
      display: flex;
      gap: 0.3rem;
      background: var(--bg-surface-elevated);
      padding: 0.25rem;
      border-radius: 8px;
      border: 1px solid var(--border);
    }

    .toggle-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 0.35rem 0.85rem;
      border-radius: 6px;
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
    }

    .toggle-btn.active {
      background: var(--accent);
      color: white;
    }

    .btn-export {
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 0.4rem 0.85rem;
      border-radius: 6px;
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
    }

    .btn-export:hover {
      border-color: var(--accent);
    }

    .results-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 0.5rem;
    }

    .results-table th {
      text-align: left;
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--text-muted);
      padding: 0.8rem 1rem;
      border-bottom: 1px solid var(--border);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .results-table td {
      padding: 1rem;
      border-bottom: 1px solid rgba(35, 48, 68, 0.5);
      font-size: 0.88rem;
      vertical-align: top;
    }

    .severity-badge {
      display: inline-block;
      padding: 0.25rem 0.6rem;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .badge-Critical { background: var(--critical-bg); color: var(--critical); border: 1px solid rgba(239,68,68,0.3); }
    .badge-High { background: var(--high-bg); color: var(--high); border: 1px solid rgba(249,115,22,0.3); }
    .badge-Medium { background: var(--medium-bg); color: var(--medium); border: 1px solid rgba(245,158,11,0.3); }
    .badge-Low { background: var(--low-bg); color: var(--low); border: 1px solid rgba(16,185,129,0.3); }

    .confidence-tag {
      display: inline-block;
      font-size: 0.75rem;
      font-weight: 600;
      color: #93C5FD;
      background: rgba(59, 130, 246, 0.1);
      border: 1px solid rgba(59, 130, 246, 0.25);
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      margin-top: 0.35rem;
    }

    .context-tag {
      display: inline-block;
      font-size: 0.72rem;
      font-weight: 500;
      color: var(--text-muted);
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border);
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
    }

    .secret-box {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.82rem;
      background: var(--bg-base);
      border: 1px solid var(--border);
      padding: 0.35rem 0.65rem;
      border-radius: 6px;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      max-width: 280px;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .btn-toggle-mask {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 0.85rem;
      padding: 0.1rem 0.3rem;
      border-radius: 4px;
    }

    .btn-toggle-mask:hover {
      color: var(--text-main);
      background: var(--bg-surface-elevated);
    }

    .code-snippet {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.82rem;
      color: #CBD5E1;
      max-width: 380px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .safe-state {
      text-align: center;
      padding: 2.5rem 1rem;
      color: var(--low);
      background: var(--low-bg);
      border: 1px dashed rgba(16, 185, 129, 0.4);
      border-radius: var(--radius);
      margin-top: 1rem;
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <div class="brand-icon">🛡️</div>
      <div>
        <h1>Credential & Secret Leak Detector <span style="font-size:0.75rem; color:var(--accent);">v2.0</span></h1>
        <div class="brand-sub">Evidence-based severity &bull; Context classification &bull; Cross-file deduplication</div>
      </div>
    </div>
    <div class="badge-status">
      <div class="pulse"></div>
      Engine Active
    </div>
  </header>

  <main>
    <div class="card">
      <div class="tabs">
        <button class="tab-btn active" id="tab-paste-btn" onclick="switchTab('paste')">✏️ Paste Content</button>
        <button class="tab-btn" id="tab-file-btn" onclick="switchTab('file')">📁 Upload File or .ZIP Archive</button>
      </div>

      <!-- Paste Tab -->
      <div id="tab-paste">
        <textarea id="scan-input" placeholder="Paste your AI conversation logs, .env files, code, or configuration here..."></textarea>
      </div>

      <!-- File Tab -->
      <div id="tab-file" style="display: none;">
        <div class="dropzone" id="dropzone" onclick="document.getElementById('file-input').click()">
          <span class="dropzone-icon">📥</span>
          <p><strong>Click to browse</strong> or drag & drop any file or <strong>.zip archive</strong> here</p>
          <p style="font-size: 0.8rem; margin-top: 0.4rem;">Supports .zip repos, .env, .txt, .json, .log, .py, .js, .yaml, .toml, .properties, Dockerfiles</p>
          <input type="file" id="file-input" style="display: none;" onchange="handleFileSelect(event)">
        </div>
        <div id="file-info" style="margin-top: 0.75rem; font-size: 0.85rem; color: var(--accent); display: none;"></div>
      </div>

      <!-- Controls & Test Presets -->
      <div class="controls">
        <div class="samples-bar">
          <span style="font-size: 0.82rem; color: var(--text-muted);">Try a Test Sample:</span>
          <button class="sample-chip" onclick="loadSample('chat')">🤖 AI Chat Leak</button>
          <button class="sample-chip" onclick="loadSample('env')">⚙️ .env File</button>
          <button class="sample-chip" onclick="loadSample('safe')">🛡️ Safe Placeholder Code</button>
        </div>
        <button class="btn-scan" onclick="runScan()">
          <span>🔍</span> Scan for Leaks
        </button>
      </div>
    </div>

    <!-- Results Section -->
    <div class="card" id="results-card" style="display: none;">
      <div class="metrics">
        <div class="metric-card">
          <div class="metric-title">Total Findings</div>
          <div class="metric-value metric-total" id="count-total">0</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Unique Secrets</div>
          <div class="metric-value metric-total" id="count-unique">0</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Critical</div>
          <div class="metric-value metric-critical" id="count-critical">0</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">High</div>
          <div class="metric-value metric-high" id="count-high">0</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Medium</div>
          <div class="metric-value metric-medium" id="count-medium">0</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Low / Info</div>
          <div class="metric-value metric-low" id="count-low">0</div>
        </div>
      </div>

      <div class="view-toolbar">
        <div class="view-toggle">
          <button class="toggle-btn active" id="btn-view-grouped" onclick="setViewMode('grouped')">📦 Group by Secret (Duplicates Merged)</button>
          <button class="toggle-btn" id="btn-view-flat" onclick="setViewMode('flat')">📋 All Occurrences</button>
        </div>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn-export" onclick="exportReport('json')">💾 Export JSON</button>
          <button class="btn-export" onclick="exportReport('txt')">📄 Export TXT</button>
        </div>
      </div>

      <div id="results-body"></div>
    </div>
  </main>

  <script>
    let activeTab = 'paste';
    let fileContent = '';
    let currentFileName = 'Pasted Text';
    let isZip = false;
    let latestFindings = [];
    let latestGrouped = [];
    let currentViewMode = 'grouped';

    const SAMPLES = {
      chat: `User: hey can you help me fix my connection?
Assistant: Sure, what are you trying to connect to?
User: my gmail password is MySecureGmailPass2026!
User: and connect to SSH with ssh password: server_root_pass_99
User: here is my token sk-proj-sampleOpenAiKey1234567890abcdefghij
User: also user login: admin@company.com:SuperSecretPass!`,

      env: `PORT=3000
DATABASE_URL=postgresql://dbuser:ProductionDbSecret99@postgres.cluster.local:5432/main
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AUTH_TOKEN=jwtSecretTokenForProduction123456`,

      safe: `// Example placeholder code
const dbUser = "admin";
const dbPass = "your_password_here"; // Placeholder - should NOT be flagged
const sampleKey = "<api_key>";       // Placeholder - should NOT be flagged
function login() {
  console.log("Welcome!");
}`
    };

    function switchTab(tab) {
      activeTab = tab;
      document.getElementById('tab-paste').style.display = tab === 'paste' ? 'block' : 'none';
      document.getElementById('tab-file').style.display = tab === 'file' ? 'block' : 'none';
      document.getElementById('tab-paste-btn').className = 'tab-btn' + (tab === 'paste' ? ' active' : '');
      document.getElementById('tab-file-btn').className = 'tab-btn' + (tab === 'file' ? ' active' : '');
    }

    function loadSample(key) {
      switchTab('paste');
      document.getElementById('scan-input').value = SAMPLES[key];
      currentFileName = 'Sample ' + key.toUpperCase();
      isZip = false;
      runScan();
    }

    function handleFileSelect(evt) {
      const file = evt.target.files[0];
      if (!file) return;
      currentFileName = file.name;
      isZip = file.name.toLowerCase().endsWith('.zip');
      const reader = new FileReader();

      if (isZip) {
        reader.onload = (e) => {
          const dataUrl = e.target.result;
          fileContent = dataUrl.split(',')[1];
          document.getElementById('file-info').innerHTML = '📦 Selected ZIP Archive: <strong>' + file.name + '</strong> (' + Math.round(file.size / 1024) + ' KB) &mdash; <span style="color:#10B981; font-weight:600;">Will extract & scan all files inside archive</span>';
          document.getElementById('file-info').style.display = 'block';
        };
        reader.readAsDataURL(file);
      } else {
        reader.onload = (e) => {
          fileContent = e.target.result;
          document.getElementById('file-info').innerHTML = '📄 Selected File: <strong>' + file.name + '</strong> (' + Math.round(file.size / 1024) + ' KB)';
          document.getElementById('file-info').style.display = 'block';
        };
        reader.readAsText(file);
      }
    }

    // Drag and drop listeners
    const dropzone = document.getElementById('dropzone');
    dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone.addEventListener('dragleave', () => { dropzone.classList.remove('dragover'); });
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length) {
        handleFileSelect({ target: { files: e.dataTransfer.files } });
      }
    });

    async function runScan() {
      const content = activeTab === 'paste' 
        ? document.getElementById('scan-input').value 
        : fileContent;

      if (!content || !content.trim()) {
        alert('Please paste some text or upload a file first.');
        return;
      }

      const scanBtn = document.querySelector('.btn-scan');
      scanBtn.innerHTML = '<span>⏳</span> Scanning...';
      scanBtn.disabled = true;

      try {
        const isZipScan = (activeTab === 'file' && isZip);
        const resp = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            content: content, 
            source: currentFileName,
            is_zip: isZipScan
          })
        });
        const data = await resp.json();
        latestFindings = data.findings || [];
        latestGrouped = data.grouped || [];
        renderDashboard();
      } catch (err) {
        alert('Scan error: ' + err.message);
      } finally {
        scanBtn.innerHTML = '<span>🔍</span> Scan for Leaks';
        scanBtn.disabled = false;
      }
    }

    function setViewMode(mode) {
      currentViewMode = mode;
      document.getElementById('btn-view-grouped').className = 'toggle-btn' + (mode === 'grouped' ? ' active' : '');
      document.getElementById('btn-view-flat').className = 'toggle-btn' + (mode === 'flat' ? ' active' : '');
      renderResultsTable();
    }

    function renderDashboard() {
      const card = document.getElementById('results-card');
      card.style.display = 'block';

      let critical = 0, high = 0, medium = 0, low = 0;
      latestFindings.forEach(f => {
        if (f.severity === 'Critical') critical++;
        else if (f.severity === 'High') high++;
        else if (f.severity === 'Medium') medium++;
        else low++;
      });

      document.getElementById('count-total').innerText = latestFindings.length;
      document.getElementById('count-unique').innerText = latestGrouped.length;
      document.getElementById('count-critical').innerText = critical;
      document.getElementById('count-high').innerText = high;
      document.getElementById('count-medium').innerText = medium;
      document.getElementById('count-low').innerText = low;

      renderResultsTable();
    }

    function renderResultsTable() {
      const body = document.getElementById('results-body');

      if (latestFindings.length === 0) {
        body.innerHTML = `
          <div class="safe-state">
            <h3>✅ No Leaked Credentials Detected</h3>
            <p style="margin-top: 0.5rem; font-size: 0.9rem;">
              No passwords, API keys, private keys, or exposed credentials were found.
            </p>
          </div>
        `;
        return;
      }

      if (currentViewMode === 'grouped') {
        let html = `
          <table class="results-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Detection Rule</th>
                <th>Masked Secret</th>
                <th>Occurrences Across Files</th>
              </tr>
            </thead>
            <tbody>
        `;

        latestGrouped.forEach((g, idx) => {
          const occHtml = g.occurrences.map(o => `
            <div style="margin-bottom:0.4rem;">
              <span class="context-tag">${o.context_type}</span>
              <strong style="color:#CBD5E1; font-family:'JetBrains Mono',monospace; font-size:0.83rem;">${o.source}:${o.line}</strong>
              <div class="code-snippet">${o.snippet}</div>
            </div>
          `).join('');

          html += `
            <tr>
              <td><span class="severity-badge badge-${g.severity}">${g.severity}</span></td>
              <td>
                <span class="confidence-tag">${g.confidence} Confidence</span>
                <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.3rem;">${g.confidence_reason}</div>
              </td>
              <td>
                <strong>${g.label}</strong>
                <div style="font-size:0.75rem; color:var(--text-muted); margin-top:2px;">${g.category}</div>
                <div style="font-size:0.72rem; color:#94A3B8; margin-top:0.3rem; max-width:250px;">${g.evidence}</div>
              </td>
              <td>
                <span class="secret-box">
                  <span id="secret-grp-${idx}">${g.redacted_secret}</span>
                  <button class="btn-toggle-mask" onclick="toggleSecretGroup(${idx})" title="Toggle Reveal">👁️</button>
                </span>
                <div style="font-size:0.72rem; color:var(--text-muted); margin-top:0.25rem;">Entropy: ${g.entropy}</div>
              </td>
              <td>${occHtml}</td>
            </tr>
          `;
        });

        html += '</tbody></table>';
        body.innerHTML = html;

      } else {
        // Flat view
        let html = `
          <table class="results-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Detection Rule</th>
                <th>Location & Context</th>
                <th>Masked Secret</th>
                <th>Snippet</th>
              </tr>
            </thead>
            <tbody>
        `;

        latestFindings.forEach((f, idx) => {
          html += `
            <tr>
              <td><span class="severity-badge badge-${f.severity}">${f.severity}</span></td>
              <td>
                <span class="confidence-tag">${f.confidence}</span>
                <div style="font-size:0.72rem; color:var(--text-muted); margin-top:2px;">${f.confidence_reason}</div>
              </td>
              <td>
                <strong>${f.label}</strong>
                <div style="font-size:0.75rem; color:var(--text-muted);">${f.category}</div>
              </td>
              <td>
                <span class="context-tag">${f.context_type}</span>
                <div style="font-family:'JetBrains Mono',monospace; font-size:0.83rem; margin-top:3px;">${f.source}:${f.line}</div>
              </td>
              <td>
                <span class="secret-box">
                  <span id="secret-flat-${idx}">${f.redacted_secret}</span>
                  <button class="btn-toggle-mask" onclick="toggleSecretFlat(${idx})" title="Toggle Reveal">👁️</button>
                </span>
              </td>
              <td><div class="code-snippet" title="${f.snippet.replace(/"/g, '&quot;')}">${f.snippet}</div></td>
            </tr>
          `;
        });

        html += '</tbody></table>';
        body.innerHTML = html;
      }
    }

    function toggleSecretGroup(idx) {
      const g = latestGrouped[idx];
      const el = document.getElementById('secret-grp-' + idx);
      if (el.innerText === g.redacted_secret) {
        el.innerText = g.raw_secret;
        el.style.color = '#EF4444';
      } else {
        el.innerText = g.redacted_secret;
        el.style.color = 'inherit';
      }
    }

    function toggleSecretFlat(idx) {
      const f = latestFindings[idx];
      const el = document.getElementById('secret-flat-' + idx);
      if (el.innerText === f.redacted_secret) {
        el.innerText = f.raw_secret;
        el.style.color = '#EF4444';
      } else {
        el.innerText = f.redacted_secret;
        el.style.color = 'inherit';
      }
    }

    function exportReport(format) {
      if (latestFindings.length === 0) {
        alert('No findings to export.');
        return;
      }
      let content = '', filename = '', mime = '';
      if (format === 'json') {
        content = JSON.stringify({ findings: latestFindings, grouped: latestGrouped }, null, 2);
        filename = 'credential_audit_report.json';
        mime = 'application/json';
      } else {
        let lines = [
          '===========================================================================',
          ' CREDENTIAL & SECRET AUDIT REPORT',
          '===========================================================================',
          ` Total Findings: ${latestFindings.length} | Unique Secrets: ${latestGrouped.length}`,
          '===========================================================================',
          ''
        ];
        latestGrouped.forEach((g, i) => {
          lines.push(`[${i+1}] ${g.label} (${g.category})`);
          lines.push(`    Severity: ${g.severity} | Confidence: ${g.confidence}`);
          lines.push(`    Reason: ${g.confidence_reason}`);
          lines.push(`    Evidence: ${g.evidence}`);
          lines.push(`    Secret: ${g.redacted_secret} (Entropy: ${g.entropy})`);
          lines.push(`    Occurrences (${g.occurrences.length}):`);
          g.occurrences.forEach(o => {
            lines.push(`      - ${o.source}:${o.line} [${o.context_type}]`);
            lines.push(`        Snippet: ${o.snippet}`);
          });
          lines.push('---------------------------------------------------------------------------');
        });
        content = lines.join('\\n');
        filename = 'credential_audit_report.txt';
        mime = 'text/plain';
      }

      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  </script>
</body>
</html>
"""


class LeakScanHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        url = urlparse(self.path)
        if url.path == "/api/scan":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(body)
                content = data.get("content", "")
                source = data.get("source", "Input")
                is_zip = data.get("is_zip", False)

                if is_zip:
                    zip_bytes = base64.b64decode(content)
                    findings = scan_zip_bytes(zip_bytes, zip_name=source)
                else:
                    findings = scan_text(content, source_name=source)

                grouped = group_findings_by_secret(findings)
                response = {
                    "status": "success",
                    "total_findings": len(findings),
                    "unique_secrets": len(grouped),
                    "findings": findings,
                    "grouped": grouped,
                }
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Silence default request logging to keep terminal clean
        pass


def main():
    server_address = ("127.0.0.1", PORT)
    httpd = HTTPServer(server_address, LeakScanHandler)
    url = f"http://127.0.0.1:{PORT}"
    print()
    print("=" * 65)
    print(" [*] Credential & Secret Leak Detector GUI v2.0")
    print("=" * 65)
    print(f"  URL: {url}")
    print("  Status: Running locally on your machine (zero external calls)")
    print("  Press Ctrl+C to stop the server.")
    print("=" * 65)
    print()

    # Open browser automatically
    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Server stopped.")
        httpd.server_close()


if __name__ == "__main__":
    main()
