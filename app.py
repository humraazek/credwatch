#!/usr/bin/env python3
"""
Credential Detector - Minimalist Black & White GUI (Mistral style)
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
  <title>Credential Detector</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Geist+Mono:wght@400;500;600&family=Geist:wght@300;400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-black: #000000;
      --bg-card: #0A0A0A;
      --bg-card-hover: #121212;
      --border-subtle: #222222;
      --border-strong: #333333;
      --text-primary: #FFFFFF;
      --text-secondary: #999999;
      --text-tertiary: #555555;
      --accent-white: #FFFFFF;
      --crit-red: #FF453A;
      --high-orange: #FF9F0A;
      --med-amber: #FFD60A;
      --low-green: #30D158;
      --font-sans: 'Geist', -apple-system, sans-serif;
      --font-mono: 'Geist Mono', monospace;
      --font-heading: 'Space Grotesk', sans-serif;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background-color: var(--bg-black);
      color: var(--text-primary);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-font-smoothing: antialiased;
      line-height: 1.5;
    }

    header {
      background-color: var(--bg-black);
      border-bottom: 1px solid var(--border-subtle);
      padding: 0.9rem 2rem;
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
      gap: 0.85rem;
    }

    .brand-mark {
      width: 16px;
      height: 16px;
      background-color: #FFFFFF;
      border-radius: 2px;
      display: inline-block;
    }

    .brand-title {
      font-family: var(--font-heading);
      font-weight: 700;
      font-size: 0.95rem;
      letter-spacing: -0.01em;
      color: #FFFFFF;
    }

    .brand-version {
      font-family: var(--font-mono);
      font-size: 0.72rem;
      color: var(--text-tertiary);
      border: 1px solid var(--border-subtle);
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
    }

    .status-dot {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--text-secondary);
    }

    .dot {
      width: 6px;
      height: 6px;
      background-color: var(--low-green);
      border-radius: 50%;
    }

    main {
      flex: 1;
      max-width: 1100px;
      width: 100%;
      margin: 0 auto;
      padding: 2.5rem 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }

    .panel {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 1.5rem;
    }

    .tabs {
      display: flex;
      gap: 1.5rem;
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: 0.75rem;
      margin-bottom: 1.25rem;
    }

    .tab-btn {
      background: none;
      border: none;
      color: var(--text-secondary);
      font-family: var(--font-sans);
      font-size: 0.85rem;
      font-weight: 500;
      cursor: pointer;
      padding-bottom: 0.75rem;
      margin-bottom: -0.75rem;
      border-bottom: 2px solid transparent;
      transition: color 0.15s, border-color 0.15s;
    }

    .tab-btn:hover {
      color: var(--text-primary);
    }

    .tab-btn.active {
      color: #FFFFFF;
      border-bottom: 2px solid #FFFFFF;
    }

    textarea {
      width: 100%;
      min-height: 180px;
      background: var(--bg-black);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      color: var(--text-primary);
      font-family: var(--font-mono);
      font-size: 0.82rem;
      padding: 0.85rem;
      resize: vertical;
      line-height: 1.6;
    }

    textarea:focus {
      outline: none;
      border-color: var(--border-strong);
    }

    .dropzone {
      border: 1px dashed var(--border-strong);
      border-radius: 6px;
      padding: 2.5rem 1.5rem;
      text-align: center;
      cursor: pointer;
      background: var(--bg-black);
      transition: border-color 0.15s;
    }

    .dropzone:hover, .dropzone.dragover {
      border-color: #FFFFFF;
    }

    .dropzone p {
      font-size: 0.85rem;
      color: var(--text-secondary);
    }

    .dropzone strong {
      color: var(--text-primary);
      font-weight: 500;
    }

    .sub-drop {
      font-family: var(--font-mono);
      font-size: 0.72rem;
      color: var(--text-tertiary);
      margin-top: 0.35rem;
    }

    .action-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 1.25rem;
      flex-wrap: wrap;
      gap: 0.85rem;
    }

    .samples-row {
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }

    .sample-label {
      font-family: var(--font-mono);
      font-size: 0.72rem;
      color: var(--text-tertiary);
      margin-right: 0.3rem;
    }

    .sample-btn {
      background: var(--bg-black);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      font-family: var(--font-mono);
      font-size: 0.72rem;
      padding: 0.25rem 0.55rem;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.15s;
    }

    .sample-btn:hover {
      color: var(--text-primary);
      border-color: var(--border-strong);
      background: var(--bg-card-hover);
    }

    .btn-run {
      background: #FFFFFF;
      color: #000000;
      border: none;
      border-radius: 4px;
      padding: 0.55rem 1.4rem;
      font-family: var(--font-sans);
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      transition: opacity 0.15s, background-color 0.15s;
    }

    .btn-run:hover {
      opacity: 0.9;
      background-color: #EDEDED;
    }

    /* Results section */
    .summary-strip {
      display: flex;
      gap: 2rem;
      padding-bottom: 1.25rem;
      border-bottom: 1px solid var(--border-subtle);
      margin-bottom: 1.25rem;
      flex-wrap: wrap;
    }

    .summary-item {
      display: flex;
      flex-direction: column;
    }

    .summary-label {
      font-family: var(--font-mono);
      font-size: 0.68rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-tertiary);
    }

    .summary-count {
      font-family: var(--font-mono);
      font-size: 1.35rem;
      font-weight: 600;
      margin-top: 0.1rem;
    }

    .color-crit { color: var(--crit-red); }
    .color-high { color: var(--high-orange); }
    .color-med { color: var(--med-amber); }
    .color-low { color: var(--low-green); }

    .sub-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      flex-wrap: wrap;
      gap: 0.5rem;
    }

    .toggle-group {
      display: flex;
      gap: 0.2rem;
      background: var(--bg-black);
      border: 1px solid var(--border-subtle);
      border-radius: 4px;
      padding: 2px;
    }

    .toggle-option {
      background: transparent;
      border: none;
      color: var(--text-secondary);
      font-family: var(--font-mono);
      font-size: 0.72rem;
      padding: 0.25rem 0.65rem;
      border-radius: 3px;
      cursor: pointer;
    }

    .toggle-option.active {
      background: var(--border-subtle);
      color: #FFFFFF;
    }

    .btn-sub-action {
      background: var(--bg-black);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      font-family: var(--font-mono);
      font-size: 0.72rem;
      padding: 0.25rem 0.6rem;
      border-radius: 4px;
      cursor: pointer;
    }

    .btn-sub-action:hover {
      color: var(--text-primary);
      border-color: var(--border-strong);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }

    th {
      text-align: left;
      font-family: var(--font-mono);
      font-size: 0.68rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-tertiary);
      padding: 0.6rem 0.8rem;
      border-bottom: 1px solid var(--border-subtle);
    }

    td {
      padding: 0.9rem 0.8rem;
      border-bottom: 1px solid var(--border-subtle);
      vertical-align: top;
    }

    .tag-severity {
      font-family: var(--font-mono);
      font-size: 0.68rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .sev-Critical { color: var(--crit-red); }
    .sev-High { color: var(--high-orange); }
    .sev-Medium { color: var(--med-amber); }
    .sev-Low { color: var(--low-green); }

    .tag-context {
      font-family: var(--font-mono);
      font-size: 0.68rem;
      color: var(--text-tertiary);
      border: 1px solid var(--border-subtle);
      padding: 0.05rem 0.35rem;
      border-radius: 3px;
    }

    .secret-pill {
      font-family: var(--font-mono);
      font-size: 0.78rem;
      background: var(--bg-black);
      border: 1px solid var(--border-subtle);
      padding: 0.25rem 0.55rem;
      border-radius: 4px;
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
    }

    .btn-reveal {
      background: none;
      border: none;
      color: var(--text-tertiary);
      cursor: pointer;
      font-size: 0.75rem;
      padding: 0;
    }

    .btn-reveal:hover {
      color: var(--text-primary);
    }

    .snippet-text {
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: #999999;
      max-width: 320px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .clean-state {
      text-align: center;
      padding: 2.5rem 1rem;
      color: var(--low-green);
      font-family: var(--font-mono);
      font-size: 0.85rem;
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <div class="brand-mark"></div>
      <div class="brand-title">credential-detector</div>
      <div class="brand-version">v2.0</div>
    </div>
    <div class="status-dot">
      <div class="dot"></div>
      <span>local</span>
    </div>
  </header>

  <main>
    <div class="panel">
      <div class="tabs">
        <button class="tab-btn active" id="tab-paste-btn" onclick="switchTab('paste')">Paste Text</button>
        <button class="tab-btn" id="tab-file-btn" onclick="switchTab('file')">File / Archive (.zip)</button>
      </div>

      <!-- Paste Tab -->
      <div id="tab-paste">
        <textarea id="scan-input" placeholder="Paste conversation log, .env file, or code here..."></textarea>
      </div>

      <!-- File Tab -->
      <div id="tab-file" style="display: none;">
        <div class="dropzone" id="dropzone" onclick="triggerFileInput()">
          <p><strong>Click to browse</strong> or drag and drop a file</p>
          <div class="sub-drop">Supports .zip archives, .env, .json, .log, .py, .js, .yaml, .toml, Dockerfiles</div>
        </div>
        <input type="file" id="file-input" style="display: none;" onchange="handleFileSelect(event)">
        <div id="file-info" style="margin-top: 0.6rem; font-family: var(--font-mono); font-size: 0.75rem; color: #FFFFFF; display: none;"></div>
      </div>

      <!-- Actions -->
      <div class="action-bar">
        <div class="samples-row">
          <span class="sample-label">sample:</span>
          <button class="sample-btn" onclick="loadSample('chat')">chat_leak</button>
          <button class="sample-btn" onclick="loadSample('env')">env_file</button>
          <button class="sample-btn" onclick="loadSample('safe')">safe_code</button>
        </div>
        <button class="btn-run" onclick="runScan()">Scan Target</button>
      </div>
    </div>

    <!-- Results Panel -->
    <div class="panel" id="results-card" style="display: none;">
      <div class="summary-strip">
        <div class="summary-item">
          <span class="summary-label">Findings</span>
          <span class="summary-count" id="count-total">0</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Unique</span>
          <span class="summary-count" id="count-unique">0</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Critical</span>
          <span class="summary-count color-crit" id="count-critical">0</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">High</span>
          <span class="summary-count color-high" id="count-high">0</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Medium</span>
          <span class="summary-count color-med" id="count-medium">0</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Low</span>
          <span class="summary-count color-low" id="count-low">0</span>
        </div>
      </div>

      <div class="sub-bar">
        <div class="toggle-group">
          <button class="toggle-option active" id="btn-view-grouped" onclick="setViewMode('grouped')">grouped</button>
          <button class="toggle-option" id="btn-view-flat" onclick="setViewMode('flat')">all</button>
        </div>
        <div style="display: flex; gap: 0.4rem;">
          <button class="btn-sub-action" onclick="exportReport('json')">export json</button>
          <button class="btn-sub-action" onclick="exportReport('txt')">export txt</button>
        </div>
      </div>

      <div id="results-body"></div>
    </div>
  </main>

  <script>
    let activeTab = 'paste';
    let fileContent = '';
    let currentFileName = 'input';
    let isZip = false;
    let latestFindings = [];
    let latestGrouped = [];
    let currentViewMode = 'grouped';

    const SAMPLES = {
      chat: `User: help me fix my connection
User: my gmail password is MySecureGmailPass2026!
User: connect via ssh password: server_root_pass_99
User: token sk-proj-sampleOpenAiKey1234567890abcdefghij
User: login admin@company.com:SuperSecretPass!`,

      env: `PORT=3000
DATABASE_URL=postgresql://dbuser:ProductionDbSecret99@postgres.cluster.local:5432/main
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AUTH_TOKEN=jwtSecretTokenForProduction123456`,

      safe: `// Example placeholder code
const dbUser = "admin";
const dbPass = "your_password_here"; // Placeholder
const sampleKey = "<api_key>";       // Placeholder`
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
      currentFileName = key;
      isZip = false;
      runScan();
    }

    function triggerFileInput() {
      const fi = document.getElementById('file-input');
      fi.value = '';
      fi.click();
    }

    function handleFileSelect(evt) {
      const file = evt.target.files ? evt.target.files[0] : null;
      if (!file) return;

      currentFileName = file.name;
      isZip = file.name.toLowerCase().endsWith('.zip');

      const infoEl = document.getElementById('file-info');
      infoEl.style.display = 'block';
      infoEl.innerText = 'reading ' + file.name + '...';

      const reader = new FileReader();

      if (isZip) {
        reader.onload = (e) => {
          const res = e.target.result;
          const commaIdx = res.indexOf(',');
          fileContent = commaIdx !== -1 ? res.substring(commaIdx + 1) : res;
          infoEl.innerHTML = 'archive: <strong>' + file.name + '</strong> (' + Math.round(file.size / 1024) + ' KB) &mdash; <span style="color:#30D158;">analyzing archive...</span>';
          runScan();
        };
        reader.onerror = () => {
          infoEl.innerText = 'error reading zip file';
        };
        reader.readAsDataURL(file);
      } else {
        reader.onload = (e) => {
          fileContent = e.target.result;
          infoEl.innerHTML = 'file: <strong>' + file.name + '</strong> (' + Math.round(file.size / 1024) + ' KB) &mdash; <span style="color:#30D158;">analyzing file...</span>';
          runScan();
        };
        reader.onerror = () => {
          infoEl.innerText = 'error reading file';
        };
        reader.readAsText(file);
      }
    }

    const dropzone = document.getElementById('dropzone');
    dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone.addEventListener('dragleave', () => { dropzone.classList.remove('dragover'); });
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
        handleFileSelect({ target: { files: e.dataTransfer.files } });
      }
    });

    async function runScan() {
      const isFileMode = (activeTab === 'file');
      const content = isFileMode ? fileContent : document.getElementById('scan-input').value;

      if (!content || !content.trim()) {
        alert(isFileMode ? 'Please select or drop a file first.' : 'Please enter text to scan.');
        return;
      }

      const btn = document.querySelector('.btn-run');
      btn.innerText = 'Scanning...';
      btn.disabled = true;

      try {
        const resp = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            content: content, 
            source: currentFileName,
            is_zip: (isFileMode && isZip)
          })
        });

        if (!resp.ok) {
          const errData = await resp.json().catch(() => ({ error: 'Server error ' + resp.status }));
          throw new Error(errData.error || ('Server returned HTTP ' + resp.status));
        }

        const data = await resp.json();
        latestFindings = data.findings || [];
        latestGrouped = data.grouped || [];
        renderDashboard();
      } catch (err) {
        alert('Scan error: ' + err.message);
      } finally {
        btn.innerText = 'Scan Target';
        btn.disabled = false;
      }
    }

    function setViewMode(mode) {
      currentViewMode = mode;
      document.getElementById('btn-view-grouped').className = 'toggle-option' + (mode === 'grouped' ? ' active' : '');
      document.getElementById('btn-view-flat').className = 'toggle-option' + (mode === 'flat' ? ' active' : '');
      renderTable();
    }

    function renderDashboard() {
      document.getElementById('results-card').style.display = 'block';

      let crit = 0, high = 0, med = 0, low = 0;
      latestFindings.forEach(f => {
        if (f.severity === 'Critical') crit++;
        else if (f.severity === 'High') high++;
        else if (f.severity === 'Medium') med++;
        else low++;
      });

      document.getElementById('count-total').innerText = latestFindings.length;
      document.getElementById('count-unique').innerText = latestGrouped.length;
      document.getElementById('count-critical').innerText = crit;
      document.getElementById('count-high').innerText = high;
      document.getElementById('count-medium').innerText = med;
      document.getElementById('count-low').innerText = low;

      renderTable();
    }

    function renderTable() {
      const body = document.getElementById('results-body');

      if (latestFindings.length === 0) {
        body.innerHTML = '<div class="clean-state">0 findings. Target is clean.</div>';
        return;
      }

      if (currentViewMode === 'grouped') {
        let html = `
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Rule</th>
                <th>Secret</th>
                <th>Occurrences</th>
              </tr>
            </thead>
            <tbody>
        `;

        latestGrouped.forEach((g, idx) => {
          const occHtml = g.occurrences.map(o => `
            <div style="margin-bottom:0.35rem;">
              <span class="tag-context">${o.context_type}</span>
              <span style="font-family:var(--font-mono); color:#CBD5E1; font-size:0.75rem;">${o.source}:${o.line}</span>
              <div class="snippet-text">${o.snippet}</div>
            </div>
          `).join('');

          html += `
            <tr>
              <td><span class="tag-severity sev-${g.severity}">${g.severity}</span></td>
              <td>
                <div style="font-family:var(--font-mono); font-size:0.75rem; color:#FFFFFF;">${g.confidence}</div>
                <div style="font-size:0.68rem; color:var(--text-tertiary); max-width:200px;">${g.confidence_reason}</div>
              </td>
              <td>
                <div style="font-weight:500; color:#FFFFFF;">${g.label}</div>
                <div style="font-size:0.68rem; color:var(--text-tertiary);">${g.category}</div>
              </td>
              <td>
                <span class="secret-pill">
                  <span id="grp-${idx}">${g.redacted_secret}</span>
                  <button class="btn-reveal" onclick="toggleSecretGroup(${idx})">&#x25C9;</button>
                </span>
                <div style="font-family:var(--font-mono); font-size:0.68rem; color:var(--text-tertiary); margin-top:2px;">H: ${g.entropy}</div>
              </td>
              <td>${occHtml}</td>
            </tr>
          `;
        });

        html += '</tbody></table>';
        body.innerHTML = html;

      } else {
        let html = `
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Rule</th>
                <th>Target</th>
                <th>Secret</th>
                <th>Snippet</th>
              </tr>
            </thead>
            <tbody>
        `;

        latestFindings.forEach((f, idx) => {
          html += `
            <tr>
              <td><span class="tag-severity sev-${f.severity}">${f.severity}</span></td>
              <td>
                <div style="font-family:var(--font-mono); font-size:0.75rem;">${f.confidence}</div>
              </td>
              <td>
                <div style="font-weight:500;">${f.label}</div>
                <div style="font-size:0.68rem; color:var(--text-tertiary);">${f.category}</div>
              </td>
              <td>
                <span class="tag-context">${f.context_type}</span>
                <div style="font-family:var(--font-mono); font-size:0.72rem; margin-top:2px;">${f.source}:${f.line}</div>
              </td>
              <td>
                <span class="secret-pill">
                  <span id="flt-${idx}">${f.redacted_secret}</span>
                  <button class="btn-reveal" onclick="toggleSecretFlat(${idx})">&#x25C9;</button>
                </span>
              </td>
              <td><div class="snippet-text">${f.snippet}</div></td>
            </tr>
          `;
        });

        html += '</tbody></table>';
        body.innerHTML = html;
      }
    }

    function toggleSecretGroup(idx) {
      const g = latestGrouped[idx];
      const el = document.getElementById('grp-' + idx);
      if (el.innerText === g.redacted_secret) {
        el.innerText = g.raw_secret;
        el.style.color = '#FFFFFF';
        el.style.fontWeight = 'bold';
      } else {
        el.innerText = g.redacted_secret;
        el.style.color = 'inherit';
        el.style.fontWeight = 'normal';
      }
    }

    function toggleSecretFlat(idx) {
      const f = latestFindings[idx];
      const el = document.getElementById('flt-' + idx);
      if (el.innerText === f.redacted_secret) {
        el.innerText = f.raw_secret;
        el.style.color = '#FFFFFF';
        el.style.fontWeight = 'bold';
      } else {
        el.innerText = f.redacted_secret;
        el.style.color = 'inherit';
        el.style.fontWeight = 'normal';
      }
    }

    function exportReport(format) {
      if (latestFindings.length === 0) return;
      let content = '', filename = '', mime = '';
      if (format === 'json') {
        content = JSON.stringify({ findings: latestFindings, grouped: latestGrouped }, null, 2);
        filename = 'credentials_report.json';
        mime = 'application/json';
      } else {
        let lines = [
          'AUDIT REPORT',
          `Findings: ${latestFindings.length} | Unique: ${latestGrouped.length}`,
          '-------------------------------------------------------'
        ];
        latestGrouped.forEach((g, i) => {
          lines.push(`[${i+1}] ${g.label} [${g.severity}] (${g.confidence} confidence)`);
          lines.push(`    Secret: ${g.redacted_secret} (Entropy: ${g.entropy})`);
          g.occurrences.forEach(o => {
            lines.push(`    - ${o.source}:${o.line} [${o.context_type}]`);
            lines.push(`      ${o.snippet}`);
          });
        });
        content = lines.join('\\n');
        filename = 'credentials_report.txt';
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
            resp_bytes = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.end_headers()
            self.wfile.write(resp_bytes)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        url = urlparse(self.path)
        if url.path == "/api/scan":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(content_length)
                body = raw_body.decode("utf-8", errors="replace")
                data = json.loads(body)
                content = data.get("content", "")
                source = data.get("source", "input")
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
                resp_bytes = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)
            except Exception as e:
                err_bytes = json.dumps({"error": str(e)}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(err_bytes)))
                self.end_headers()
                self.wfile.write(err_bytes)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def main():
    server_address = ("127.0.0.1", PORT)
    httpd = HTTPServer(server_address, LeakScanHandler)
    url = f"http://127.0.0.1:{PORT}"
    print()
    print("=" * 60)
    print(" [*] credential-detector - Minimalist Web GUI")
    print("=" * 60)
    print(f"  URL: {url}")
    print("  Status: Running locally on your machine")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)
    print()

    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Stopped.")
        httpd.server_close()


if __name__ == "__main__":
    main()
