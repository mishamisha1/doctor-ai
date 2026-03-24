package main

const htmlPage = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Doctor-AI — Anti-Malware Engine</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg-dark: #0d1117;
  --bg-card: #161b22;
  --bg-sidebar: #0d1117;
  --border: #30363d;
  --accent: #58a6ff;
  --accent-dim: #388bfd;
  --success: #3fb950;
  --warning: #d29922;
  --danger: #f85149;
  --text: #e6edf3;
  --text-muted: #8b949e;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Inter', -apple-system, sans-serif; background: var(--bg-dark); color: var(--text); min-height: 100vh; overflow-x: hidden; }
.layout { display: flex; flex-direction: column; min-height: 100vh; }

/* Header */
.header {
  background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%);
  border-bottom: 1px solid var(--border);
  padding: 12px 24px;
  display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;
}
.header h1 { font-size: 1.4rem; font-weight: 700; background: linear-gradient(90deg, #58a6ff, #a371f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.badges { display: flex; gap: 8px; flex-wrap: wrap; }
.badge { font-size: 11px; padding: 4px 10px; border-radius: 20px; font-weight: 600; }
.badge-go { background: #238636; color: #fff; }
.badge-ver { background: #1f6feb; color: #fff; }
.badge-safe { background: var(--success); color: #000; display: flex; align-items: center; gap: 4px; }
.badge-safe::before { content: '✓'; font-weight: bold; }

/* Main content */
.main { display: flex; flex: 1; min-height: 0; }
.sidebar {
  width: 220px; background: var(--bg-sidebar); border-right: 1px solid var(--border);
  padding: 20px 0; display: flex; flex-direction: column; gap: 8px;
}
.sidebar .logo { padding: 0 20px 16px; font-size: 24px; }
.sidebar .greeting { padding: 0 20px 12px; font-size: 13px; color: var(--text-muted); }
.nav-item {
  padding: 10px 20px; cursor: pointer; border-left: 3px solid transparent; color: var(--text-muted);
  font-size: 14px; display: flex; align-items: center; gap: 10px; transition: all 0.2s;
}
.nav-item:hover { color: var(--accent); background: rgba(88,166,255,0.08); }
.nav-item.active { color: var(--accent); border-left-color: var(--accent); background: rgba(88,166,255,0.1); }
.nav-item .icon { font-size: 16px; opacity: 0.8; }

.content { flex: 1; padding: 24px; overflow: auto; display: flex; gap: 24px; }
.center { flex: 1; display: flex; flex-direction: column; gap: 20px; min-width: 0; }
.right { width: 260px; flex-shrink: 0; }

/* Progress circle */
.progress-box {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px;
  padding: 32px; display: flex; flex-direction: column; align-items: center; gap: 16px;
}
.progress-ring {
  width: 140px; height: 140px; border-radius: 50%;
  background: conic-gradient(var(--accent) calc(var(--p)*1%), var(--border) 0);
  display: flex; align-items: center; justify-content: center;
}
.progress-ring-inner {
  width: 110px; height: 110px; border-radius: 50%; background: var(--bg-card);
  display: flex; align-items: center; justify-content: center; font-size: 28px; font-weight: 700;
}
.controls { display: flex; gap: 12px; }
.ctrl-btn { width: 40px; height: 40px; border-radius: 50%; border: 1px solid var(--border); background: var(--bg-dark); color: var(--text); cursor: pointer; font-size: 16px; }
.ctrl-btn:hover { background: var(--border); }
.threats { display: flex; align-items: center; gap: 8px; color: var(--warning); font-weight: 600; }
.threats .warn-icon { font-size: 20px; }

/* Log / Output */
.log-box {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
  padding: 16px; font-family: 'JetBrains Mono', monospace; font-size: 12px;
  white-space: pre-wrap; word-break: break-all; overflow: auto; max-height: 280px; min-height: 120px;
}
.log-box::-webkit-scrollbar { width: 8px; }
.log-box::-webkit-scrollbar-track { background: var(--bg-dark); border-radius: 4px; }
.log-box::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }

.activity-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; }
.activity-box h4 { margin-bottom: 10px; font-size: 12px; color: var(--text-muted); }
.activity-list { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-muted); max-height: 80px; overflow: auto; }
.activity-list div { padding: 4px 0; border-bottom: 1px solid var(--border); }
.activity-list div:last-child { border-bottom: none; }
.tip-box { background: rgba(88,166,255,0.1); border: 1px solid rgba(88,166,255,0.3); border-radius: 10px; padding: 12px; font-size: 13px; }

/* Scan history */
.history-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; }
.history-box h4 { margin-bottom: 12px; font-size: 12px; color: var(--text-muted); text-transform: uppercase; }
.history-dates { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.hist-date { padding: 8px 14px; border-radius: 8px; background: var(--bg-dark); color: var(--text-muted); font-size: 12px; cursor: pointer; }
.hist-date:hover { color: var(--accent); }
.hist-date.active { background: rgba(88,166,255,0.2); color: var(--accent); }
.hist-nav { color: var(--text-muted); cursor: pointer; padding: 4px; }
.hist-nav:hover { color: var(--accent); }

/* Right panel - Protection */
.protection-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 20px; }
.protection-box h4 { margin-bottom: 16px; font-size: 13px; display: flex; align-items: center; gap: 8px; }
.protection-item { margin-bottom: 16px; }
.protection-item:last-child { margin-bottom: 0; }
.protection-item label { font-size: 12px; color: var(--text-muted); display: block; margin-bottom: 6px; }
.slider-wrap { display: flex; align-items: center; gap: 10px; }
.slider { flex: 1; height: 6px; -webkit-appearance: none; background: var(--border); border-radius: 3px; }
.slider::-webkit-slider-thumb { -webkit-appearance: none; width: 16px; height: 16px; border-radius: 50%; background: var(--accent); cursor: pointer; }

/* Action buttons grid */
.actions { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 8px; }
.btn { padding: 10px 14px; border-radius: 10px; border: 1px solid var(--border); background: var(--bg-card); color: var(--text); cursor: pointer; font-size: 13px; font-weight: 500; transition: all 0.2s; }
.btn:hover { background: var(--accent); color: #000; border-color: var(--accent); }
.btn-primary { background: var(--accent); color: #000; border-color: var(--accent); }
.btn-primary:hover { background: var(--accent-dim); }
.btn-danger:hover { background: var(--danger); border-color: var(--danger); color: #fff; }

/* Settings / API Key */
.settings-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin-top: 16px; }
.settings-card input { width: 100%; padding: 10px; background: var(--bg-dark); border: 1px solid var(--border); border-radius: 8px; color: var(--text); margin-top: 8px; }
.log-health { display:grid; grid-template-columns: repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin-top:10px; }
.log-health .metric { background: var(--bg-dark); border:1px solid var(--border); border-radius:10px; padding:10px; }
.metric .k { color: var(--text-muted); font-size:11px; }
.metric .v { margin-top:4px; font-family:'JetBrains Mono', monospace; font-size:12px; }
.section-panel { display: none; }
.section-panel.active { display: flex; flex-direction: column; gap: 20px; }
.modal-overlay { display: none; position: fixed; top:0; left:0; right:0; bottom:0; background: rgba(0,0,0,0.8); z-index: 9999; align-items: center; justify-content: center; }
.modal-overlay.visible { display: flex; }
.modal-box { background: var(--bg-card); border: 1px solid var(--accent); border-radius: 16px; padding: 32px; text-align: center; max-width: 400px; }
.modal-box h3 { margin-bottom: 12px; color: var(--accent); }
.modal-box p { color: var(--text-muted); font-size: 14px; }
.spinner { width: 40px; height: 40px; border: 3px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 16px; }
@keyframes spin { to { transform: rotate(360deg); } }
.btn.working { background: var(--accent); color: #000; }
</style>
</head>
<body>
<div class="layout">
<header class="header">
  <h1>Doctor-AI — Anti-Malware Engine</h1>
  <div class="badges">
    <span class="badge badge-go">Go 1.25</span>
    <span class="badge badge-ver">v1.0</span>
    <span class="badge badge-safe" id="statusBadge">Загрузка...</span>
  </div>
</header>

<div class="main">
<aside class="sidebar">
  <div class="logo">🩺</div>
  <div class="greeting" id="greeting">Привет!</div>
  <div class="nav-item active" data-section="scan"><span class="icon">🔍</span> Scan</div>
  <div class="nav-item" data-section="protect"><span class="icon">🛡</span> Protect</div>
  <div class="nav-item" data-section="lab"><span class="icon">🧪</span> Lab</div>
  <div class="nav-item" data-section="quarantine"><span class="icon">🔒</span> Quarantine</div>
  <div class="nav-item" data-section="update"><span class="icon">🔄</span> Update</div>
  <div class="nav-item" data-section="settings"><span class="icon">⚙</span> Settings</div>
</aside>

<div class="content">
<div class="center" style="flex:1;flex-direction:column">

<!-- SCAN -->
<div id="panel-scan" class="section-panel active">
  <div class="progress-box">
    <div class="progress-ring" id="progressRing" style="--p: 0">
      <div class="progress-ring-inner" id="progressPercent">0%</div>
    </div>
    <div class="threats" id="threatsBox">
      <span class="warn-icon">⚠</span>
      <span id="threatsCount">— угроз</span>
    </div>
  </div>
  <div class="actions">
    <button class="btn" data-cmd="scan" onclick="run('scan',this)">Scan</button>
    <button class="btn" data-cmd="plan" onclick="run('plan',this)">Plan</button>
    <button class="btn" data-cmd="fix" onclick="run('fix',this)">Fix</button>
    <button class="btn" data-cmd="fix-auto" onclick="run('fix',this,1)">Fix -Auto</button>
    <button class="btn btn-danger" data-cmd="rollback" onclick="run('rollback',this)">Rollback</button>
    <button class="btn" data-cmd="avscan" onclick="run('avscan',this)">AV Scan</button>
    <button class="btn" data-cmd="analyze" onclick="analyze(this)">Analyze AI</button>
    <button class="btn" onclick="humanReport(this)">Human Report</button>
    <button class="btn btn-primary" data-cmd="smart-scan" onclick="customScan(this)">Smart Scan</button>
    <button class="btn" data-cmd="knight-preview" onclick="knightPreview(this)">Knight Preview</button>
    <button class="btn btn-danger" data-cmd="knight-mode" onclick="knightMode(this)">Knight Mode</button>
    <button class="btn" data-cmd="agent" onclick="agentRun(this)">Agent</button>
    <button class="btn" data-cmd="latestScan" onclick="latestScan(this)">Latest Scan</button>
  </div>
  <div class="settings-card" style="margin-top:10px">
    <h4>Knight Policy Profile</h4>
    <p style="font-size:12px;color:var(--text-muted)">Monitor = только наблюдение, Soft Block = аккуратная блокировка, Aggressive = максимальная проактивность.</p>
    <select id="knightProfile" style="margin-top:8px;padding:10px;background:var(--bg-dark);border:1px solid var(--border);border-radius:8px;color:var(--text)">
      <option value="monitor">Monitor</option>
      <option value="soft-block">Soft Block</option>
      <option value="aggressive">Aggressive</option>
    </select>
  </div>
  <div class="log-box" id="out">Scan: телеметрия. Plan: план. Fix: применить. Analyze: EDR+AI.</div>

  <div class="settings-card">
    <h4>Quick Protect (3 шага)</h4>
    <p style="font-size:12px;color:var(--text-muted)">Для обычного пользователя: 1) Agent, 2) Analyze, 3) Knight Mode.</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn" onclick="quickProtect('1',this)">Шаг 1: Start Agent</button>
      <button class="btn" onclick="quickProtect('2',this)">Шаг 2: Analyze</button>
      <button class="btn btn-danger" onclick="quickProtect('3',this)">Шаг 3: Knight Mode</button>
    </div>
    <div id="quickProtectOut" class="log-box" style="min-height:80px;margin-top:10px">Готово к запуску шагов.</div>
  </div>
  <div class="activity-box">
    <h4>📡 Активность</h4>
    <div id="activityList" class="activity-list"></div>
    <button class="btn" style="margin-top:8px" onclick="refreshActivity()">Обновить</button>
  </div>
  <div class="history-box">
    <h4>📅 История сканов</h4>
    <div class="history-dates" id="historyDates"></div>
  </div>
</div>


<!-- LAB -->
<div id="panel-lab" class="section-panel">
  <div class="settings-card">
    <h4>Lab / Simulation</h4>
    <p style="font-size:12px;color:var(--text-muted)">Сгенерируйте синтетический поток EDR-событий, запустите корреляцию и посмотрите timeline инцидентов без консоли.</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
      <select id="labScenario" style="padding:10px;background:var(--bg-dark);border:1px solid var(--border);border-radius:8px;color:var(--text)">
        <option value="mixed">mixed</option>
        <option value="malicious">malicious</option>
        <option value="benign">benign</option>
      </select>
      <input id="labCount" type="number" min="1" max="500" value="30" style="width:110px;padding:10px;background:var(--bg-dark);border:1px solid var(--border);border-radius:8px;color:var(--text)">
      <button class="btn btn-primary" onclick="labGenerate(this)">Generate stream</button>
      <button class="btn" onclick="labAnalyze(this)">Run Analyze</button>
      <button class="btn" onclick="labTimeline(this)">Show timeline</button>
    </div>
  </div>
  <div class="log-box" id="labOut" style="min-height:120px">Lab output...</div>
  <div class="settings-card">
    <h4>Incidents timeline</h4>
    <div id="labTimelineBox" class="log-box" style="min-height:160px">Нет данных.</div>
  </div>
</div>

<!-- PROTECT -->
<div id="panel-protect" class="section-panel">
  <div class="settings-card">
    <h4>Загрузить подозрительные файлы или пути</h4>
    <p style="font-size:12px;color:var(--text-muted);margin:8px 0">Пути, которые Defender не отметил, но корреляция/AI выявила</p>
    <input type="file" id="protectFile" style="margin:8px 0">
    <textarea id="protectPaths" placeholder="C:\path\to\file.exe&#10;C:\Users\...\suspicious.dll" style="width:100%;height:100px;background:var(--bg-dark);border:1px solid var(--border);border-radius:8px;color:var(--text);padding:10px;margin:8px 0;font-family:monospace"></textarea>
    <button class="btn" onclick="uploadAnalyze()">Анализировать</button>
    <div id="protectOut" class="log-box" style="margin-top:12px;min-height:60px"></div>
  </div>
  <div class="settings-card">
    <h4>Пути, отмеченные AI/корреляцией</h4>
    <div id="flaggedList" class="activity-list" style="max-height:200px"></div>
    <button class="btn" style="margin-top:8px" onclick="refreshFlagged()">Обновить</button>
  </div>
</div>

<!-- QUARANTINE -->
<div id="panel-quarantine" class="section-panel">
  <div class="settings-card">
    <h4>Проверить файлы на VT (по хэшам)</h4>
    <p style="font-size:12px;color:var(--text-muted)">Выберите файл — из него извлекут хэши, проверят в VirusTotal и добавят в whitelist/blacklist.</p>
    <div style="margin:8px 0">
      <strong>Scan:</strong>
      <div id="vtScanFiles" style="display:flex;flex-wrap:wrap;gap:6px;margin:4px 0"></div>
    </div>
    <div style="margin:8px 0">
      <strong>EDR:</strong>
      <div id="vtEdrFiles" style="display:flex;flex-wrap:wrap;gap:6px;margin:4px 0"></div>
    </div>
    <div id="vtCheckLog" class="log-box" style="min-height:80px;margin-top:8px;font-size:11px"></div>
  </div>
  <div class="settings-card">
    <h4>Whitelist / Blacklist хэшей</h4>
    <p style="font-size:12px;color:var(--text-muted)">Проверенные VT: чисто → whitelist, угроза → blacklist. Повторно не проверяются.</p>
    <div id="hashlistSummary">White: 0 | Black: 0</div>
    <button class="btn" style="margin-top:8px" onclick="refreshHashlist()">Обновить</button>
  </div>
  <div class="settings-card">
    <h4>VirusTotal API</h4>
    <p style="font-size:12px;color:var(--text-muted)">Ключ для проверки хэшей (score &gt; 0)</p>
    <input type="password" id="vtkey" placeholder="VT API key">
    <button class="btn" style="margin-top:8px" onclick="saveVTKey()">Сохранить ключ</button>
    <p style="font-size:11px;margin-top:8px;color:var(--text-muted)">Бесплатно: virustotal.com/gui/my-apikey</p>
  </div>
</div>

<!-- UPDATE -->
<div id="panel-update" class="section-panel">
  <div class="settings-card">
    <h4>Обновления системы и драйверов</h4>
    <div class="actions" style="margin-top:12px">
      <button class="btn" onclick="run('update',this)">Update (winget, Defender)</button>
      <button class="btn" onclick="run('driver-install',this)">Driver Install</button>
      <button class="btn" onclick="run('driver-auto',this)">Driver Auto</button>
      <button class="btn" onclick="refreshDriverReport()">Driver Report</button>
    </div>
    <p style="font-size:12px;color:var(--text-muted);margin-top:12px">Driver Install/Auto — интерактивны, запускаются в отдельном терминале.</p>
  </div>
  <div class="settings-card">
    <h4>AI Driver Assistant</h4>
    <textarea id="driverIssue" placeholder="Опишите проблему: экран мигает, звук не работает, wifi отваливается..." style="width:100%;height:90px;background:var(--bg-dark);border:1px solid var(--border);border-radius:8px;color:var(--text);padding:10px;font-family:inherit"></textarea>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">
      <button class="btn btn-primary" onclick="askDriverAI(this)">AI: подобрать драйвер</button>
      <button class="btn btn-danger" onclick="applyDriverAI(this)">Подтвердить и применить</button>
    </div>
    <div id="driverAIPlan" class="log-box" style="min-height:80px;margin-top:10px">AI план пока не сформирован.</div>
  </div>
  <div class="settings-card">
    <h4>Подробный отчёт по драйверам</h4>
    <div id="driverReport" class="log-box" style="min-height:180px">Нет данных.</div>
  </div>
  <div class="log-box" id="outUpdate" style="min-height:100px">Вывод команд Update...</div>
</div>

<!-- SETTINGS -->
<div id="panel-settings" class="section-panel">

  <div class="settings-card">
    <h4>Startup / Portable Check</h4>
    <p style="font-size:12px;color:var(--text-muted)">Проверка готовности этого ПК: права, ключи, пути, Sysmon assets.</p>
    <div id="startupCheckBox" class="log-box" style="min-height:110px">Проверка...</div>
    <button class="btn" style="margin-top:8px" onclick="refreshStartupCheck()">Обновить проверку</button>
  </div>
  <div class="settings-card">
    <h4>OpenAI API Key</h4>
    <input type="password" id="apikey" placeholder="sk-...">
    <button class="btn" style="margin-top:8px" onclick="setKey()">Сохранить</button>
  </div>
  <div class="settings-card">
    <h4>VirusTotal API Key</h4>
    <input type="password" id="vtkeySettings" placeholder="VT key для Quarantine">
    <button class="btn" style="margin-top:8px" onclick="saveVTKeyFromSettings()">Сохранить</button>
  </div>
  <div class="settings-card">
    <h4>Log Hygiene (EDR)</h4>
    <p style="font-size:12px;color:var(--text-muted)">Контроль размера и "свежести" <code>edr_events.jsonl</code>. Помогает не тянуть старые инциденты.</p>
    <div class="log-health" id="logHealthBox">
      <div class="metric"><div class="k">Lines</div><div class="v" id="logLines">—</div></div>
      <div class="metric"><div class="k">Size</div><div class="v" id="logSize">—</div></div>
      <div class="metric"><div class="k">Oldest</div><div class="v" id="logOldest">—</div></div>
      <div class="metric"><div class="k">Newest</div><div class="v" id="logNewest">—</div></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
      <button class="btn" onclick="refreshLogHealth()">Обновить метрики</button>
      <button class="btn btn-danger" onclick="compactLogsNow(this)">Очистить старые логи сейчас</button>
    </div>
    <div id="logCompactOut" class="log-box" style="min-height:60px;margin-top:10px">Нет данных.</div>
  </div>
</div>

</div>
</div>
</div>
</div>

<div class="modal-overlay" id="modalOverlay">
  <div class="modal-box">
    <div class="spinner"></div>
    <h3 id="modalTitle">Выполняется...</h3>
    <p id="modalMsg">Ориентировочно 30–60 сек. Подождите.</p>
  </div>
</div>

<script>
const out=document.getElementById('out');
const progressRing=document.getElementById('progressRing');
const progressPercent=document.getElementById('progressPercent');
const threatsCount=document.getElementById('threatsCount');
const statusBadge=document.getElementById('statusBadge');
const greeting=document.getElementById('greeting');
const modalOverlay=document.getElementById('modalOverlay');
const modalTitle=document.getElementById('modalTitle');
const modalMsg=document.getElementById('modalMsg');
let driverPlanCommand='';

const cmdTimes = { scan: '30-60 сек', plan: '5-15 сек', fix: '20-40 сек', avscan: '1-5 мин', analyze: '30-90 сек', 'smart-scan':'20-60 сек', 'knight-mode':'30-90 сек', 'lab-generate':'5-10 сек', 'lab-analyze':'10-20 сек', 'lab-timeline':'3-5 сек', 'quick-protect':'10-120 сек', 'driver-install': 'интерактивно', 'driver-auto': 'интерактивно', 'driver-ai':'20-60 сек', update: '1-3 мин' };

function showModal(title, msg) {
  modalTitle.textContent = title || 'Выполняется...';
  modalMsg.textContent = msg || 'Подождите.';
  modalOverlay.classList.add('visible');
}
function hideModal() { modalOverlay.classList.remove('visible'); }
function setProgress(p){ if(progressRing){ progressRing.style.setProperty('--p',p); progressPercent.textContent=p+'%'; }}

function setBtnWorking(btn, working) {
  if (!btn) return;
  document.querySelectorAll('.btn').forEach(b=>b.classList.remove('working'));
  if (working) btn.classList.add('working');
}

document.querySelectorAll('.nav-item').forEach(el=>{
  el.addEventListener('click',()=>{
    const sec=el.getAttribute('data-section');
    document.querySelectorAll('.nav-item').forEach(x=>x.classList.remove('active'));
    document.querySelectorAll('.section-panel').forEach(x=>x.classList.remove('active'));
    el.classList.add('active');
    const panel=document.getElementById('panel-'+sec);
    if(panel) panel.classList.add('active');
    if(sec==='quarantine'){ refreshQuarantine(); refreshHashlist(); refreshVTFileList(); }
    if(sec==='protect') refreshFlagged();
    if(sec==='settings'){ refreshLogHealth(); refreshStartupCheck(); }
    if(sec==='update') refreshDriverReport();
    if(sec==='lab') labTimeline();
  });
});

async function refreshStatus(){
  try{
    const r=await fetch('/api/status');
    const d=await r.json();
    greeting.textContent='Привет, '+(d.host||'User')+'!';
    statusBadge.textContent=d.agent?'Agent ✓':'Stay Safe ✓';
    statusBadge.className='badge badge-safe';
  }catch(e){ statusBadge.textContent='Offline'; statusBadge.className='badge'; }
}

async function refreshThreats(){
  try{
    const r=await fetch('/api/quick-check');
    const d=await r.json();
    const n=d.incidents||0;
    threatsCount.textContent=n+' угроз обнаружено';
    setProgress(Math.min(100, (d.events||0)/10));
  }catch(e){ threatsCount.textContent='—'; }
}

async function refreshHistory(){
  try{
    const r=await fetch('/api/scan-history');
    const arr=await r.json();
    const html=arr.slice(-7).map((x,i)=>'<span class="hist-date'+(i===arr.length-1?' active':'')+'">'+x.date+'</span>').join('');
    document.getElementById('historyDates').innerHTML=html||'<span class="hist-date">Нет сканов</span>';
  }catch(e){ document.getElementById('historyDates').innerHTML='<span class="hist-date">—</span>'; }
}

function getOutput(){
  const p=document.querySelector('.section-panel.active');
  if(p&&p.id==='panel-update') return document.getElementById('outUpdate');
  return out;
}

async function run(cmd, btn, auto){
  const t = cmdTimes[cmd] || 'неизвестно';
  showModal(cmd + ' выполняется...', 'Ориентировочно: ' + t);
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/run?cmd='+encodeURIComponent(cmd)+(auto?'&auto=1':''));
    getOutput().textContent=await r.text();
    setProgress(100);
    refreshThreats(); refreshHistory();
  }catch(e){ getOutput().textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function customScan(btn){
  showModal('Smart Scan...', 'Локальный эвристический скан подозрительных файлов.');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/custom-scan');
    out.textContent=await r.text();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function knightPreview(btn){
  showModal('Knight Preview...', 'Показываем, что будет заблокировано/карантинено до применения.');
  setBtnWorking(btn, true);
  try{
    const profile=(document.getElementById('knightProfile')||{}).value||'monitor';
    const r=await fetch('/api/auto-protect-preview?profile='+encodeURIComponent(profile));
    out.textContent=await r.text();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function knightMode(btn){
  showModal('Knight Mode...', 'Проактивная защита: локальная эвристика + AI verdict + авто-реакция.');
  setBtnWorking(btn, true);
  try{
    const profile=(document.getElementById('knightProfile')||{}).value||'monitor';
    const fd=new FormData(); fd.append('profile', profile);
    const r=await fetch('/api/auto-protect',{method:'POST', body:fd});
    out.textContent=await r.text();
    refreshThreats();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function labGenerate(btn){
  showModal('Lab Generate...', 'Генерация синтетического EDR-потока.');
  setBtnWorking(btn, true);
  try{
    const scenario=document.getElementById('labScenario').value;
    const count=document.getElementById('labCount').value||'30';
    const fd=new FormData();
    fd.append('scenario', scenario);
    fd.append('count', count);
    const r=await fetch('/api/lab-generate',{method:'POST',body:fd});
    const text=await r.text();
    document.getElementById('labOut').textContent=text;
    refreshThreats();
  }catch(e){ document.getElementById('labOut').textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function labAnalyze(btn){
  showModal('Lab Analyze...', 'Запуск корреляции по сгенерированному потоку.');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/lab-analyze',{method:'POST'});
    const text=await r.text();
    document.getElementById('labOut').textContent=text;
    await labTimeline();
    refreshThreats();
  }catch(e){ document.getElementById('labOut').textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function labTimeline(btn){
  if(btn) setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/lab-timeline');
    if(!r.ok) throw new Error(await r.text());
    const arr=await r.json();
    let txt='Incidents: '+arr.length+'\n\n';
    arr.forEach((x,i)=>{
      txt += (i+1)+') ['+(x.severity||'n/a')+'] score='+x.score+'\n';
      txt += '   '+x.start+' -> '+x.end+'\n';
      (x.reasons||[]).slice(0,3).forEach(r=>{ txt += '   - '+r+'\n'; });
      txt += '\n';
    });
    document.getElementById('labTimelineBox').textContent=txt;
  }catch(e){ document.getElementById('labTimelineBox').textContent='Ошибка timeline: '+e.message; }
  if(btn) setBtnWorking(btn, false);
}

async function quickProtect(step, btn){
  showModal('Quick Protect...', 'Выполняем шаг '+step+' из 3');
  setBtnWorking(btn, true);
  try{
    const fd=new FormData(); fd.append('step', step);
    const r=await fetch('/api/quick-protect',{method:'POST',body:fd});
    const text=await r.text();
    document.getElementById('quickProtectOut').textContent=text;
    out.textContent=text;
    refreshStatus(); refreshThreats();
  }catch(e){ document.getElementById('quickProtectOut').textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function humanReport(btn){
  showModal('Human Report...', 'Собираем понятный отчёт по инцидентам.');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/human-report');
    out.textContent=await r.text();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function refreshStartupCheck(){
  try{
    const r=await fetch('/api/startup-check');
    if(!r.ok) throw new Error(await r.text());
    const d=await r.json();
    const yes=v=>v?'OK':'NO';
    let txt='Admin: '+yes(d.admin)+'\n';
    txt+='Logs dir: '+yes(d.logsDir)+'\n';
    txt+='Configs dir: '+yes(d.configDir)+'\n';
    txt+='Sysmon exe: '+yes(d.sysmonExe)+'\n';
    txt+='Sysmon config: '+yes(d.sysmonConfig)+'\n';
    txt+='OpenAI key: '+yes(d.openaiKey)+'\n';
    txt+='VT key: '+yes(d.vtKey)+'\n\n';
    txt+=d.message||'';
    document.getElementById('startupCheckBox').textContent=txt;
  }catch(e){
    document.getElementById('startupCheckBox').textContent='Ошибка проверки: '+e.message;
  }
}

async function analyze(btn){
  showModal('Analyze AI...', 'Корреляция + AI объяснения. Ориентировочно 30-90 сек.');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/analyze');
    out.textContent=await r.text();
    setProgress(100);
    refreshThreats(); refreshHistory();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function agentRun(btn){
  showModal('Agent...', 'Запуск EDR-агента');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/agent');
    out.textContent=await r.text();
    refreshStatus();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function setKey(){
  const key=document.getElementById('apikey').value;
  if(!key){ alert('Введите ключ'); return; }
  showModal('Сохранение...', '');
  try{
    const fd=new FormData(); fd.append('key',key);
    await fetch('/api/ai-key',{method:'POST',body:fd});
    alert('OpenAI ключ сохранён');
  }catch(e){ alert('Ошибка: '+e.message); }
  hideModal();
}

async function latestScan(btn){
  showModal('Latest Scan...', '');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/latest-scan');
    out.textContent=await r.text();
  }catch(e){ out.textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn, false);
}

async function uploadAnalyze(){
  const paths=document.getElementById('protectPaths').value;
  const file=document.getElementById('protectFile').files[0];
  showModal('Анализ...', '');
  try{
    const fd=new FormData();
    if(file) fd.append('file', file);
    fd.append('paths', paths);
    const r=await fetch('/api/upload-analyze', {method:'POST', body:fd});
    document.getElementById('protectOut').textContent=await r.text();
    refreshFlagged();
  }catch(e){ document.getElementById('protectOut').textContent='Ошибка: '+e.message; }
  hideModal();
}

async function refreshFlagged(){
  try{
    const r=await fetch('/api/flagged-paths');
    const arr=await r.json();
    const list=document.getElementById('flaggedList');
    if(list) list.innerHTML=arr.length?arr.map(x=>'<div>'+escapeHtml(x.path)+' ['+x.severity+']</div>').join(''):'<div>Нет данных. Запустите Analyze.</div>';
  }catch(e){}
}

async function refreshHashlist(){
  try{
    const r=await fetch('/api/hashlist');
    const d=await r.json();
    const el=document.getElementById('hashlistSummary');
    if(el) el.textContent='White: '+d.whitelist.length+' | Black: '+d.blacklist.length;
  }catch(e){}
}

async function refreshVTFileList(){
  try{
    const r=await fetch('/api/vt-file-list');
    const d=await r.json();
    const scanEl=document.getElementById('vtScanFiles');
    const edrEl=document.getElementById('vtEdrFiles');
    if(scanEl){
      scanEl.innerHTML=(d.scans||[]).map(x=>'<button class="btn vt-file-btn" data-path="'+escapeAttr(x.path)+'">'+escapeHtml(x.name)+'</button>').join('')||'<span style="color:var(--text-muted)">Нет scan_*.json</span>';
    }
    if(edrEl){
      edrEl.innerHTML=(d.edr||[]).map(x=>'<button class="btn vt-file-btn" data-path="'+escapeAttr(x.path)+'">'+escapeHtml(x.name)+'</button>').join('')||'<span style="color:var(--text-muted)">Нет edr_*.jsonl</span>';
    }
    document.querySelectorAll('.vt-file-btn').forEach(btn=>{
      btn.onclick=function(){ checkFileVT(this.getAttribute('data-path')); };
    });
  }catch(e){}
}

function escapeAttr(s){
  return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

async function checkFileVT(path){
  const logEl=document.getElementById('vtCheckLog');
  if(logEl) logEl.textContent='Проверка...';
  try{
    const fd=new FormData();
    fd.append('path',path);
    const r=await fetch('/api/check-file-vt',{method:'POST',body:fd});
    const text=await r.text();
    if(logEl) logEl.textContent=text;
    refreshHashlist();
  }catch(e){
    if(logEl) logEl.textContent='Ошибка: '+e.message;
  }
}

async function refreshDriverReport(){
  try{
    const r=await fetch('/api/driver-report');
    if(!r.ok) throw new Error(await r.text());
    const d=await r.json();
    let txt='Installed drivers: '+(d.installed||[]).length+'\n';
    txt+='Problematic/unsigned: '+(d.problematic||[]).length+'\n\n';
    (d.problematic||[]).slice(0,20).forEach((x,i)=>{
      txt += (i+1)+') '+(x.deviceName||'unknown')+' | '+(x.provider||'')+' | '+(x.version||'')+' | inf='+ (x.inf||'') +'\n';
    });
    txt += '\nDownloaded/updated packages from logs: '+(d.downloaded||[]).length+'\n';
    (d.downloaded||[]).slice(0,10).forEach((x,i)=>{
      txt += (i+1)+') '+x.folder+'\n';
      if(x.provenance) txt += '   provenance: '+x.provenance.replace(/\n/g,' | ')+'\n';
    });
    document.getElementById('driverReport').textContent=txt;
  }catch(e){
    document.getElementById('driverReport').textContent='Ошибка отчёта: '+e.message;
  }
}

async function askDriverAI(btn){
  const issue=document.getElementById('driverIssue').value.trim();
  if(!issue){ alert('Опишите проблему'); return; }
  showModal('AI Driver Assistant...', 'Анализ симптомов и подбор команды.');
  setBtnWorking(btn,true);
  try{
    const fd=new FormData(); fd.append('issue',issue);
    const r=await fetch('/api/driver-ai-plan',{method:'POST',body:fd});
    const txt=await r.text();
    if(!r.ok) throw new Error(txt);
    const p=JSON.parse(txt);
    driverPlanCommand=p.command||'';
    document.getElementById('driverAIPlan').textContent='Command: '+(p.command||'none')+'\nConfidence: '+(p.confidence||0)+'\nTarget: '+(p.target_hint||'')+'\nReason: '+(p.reason||'');
  }catch(e){
    document.getElementById('driverAIPlan').textContent='AI ошибка: '+e.message;
    driverPlanCommand='';
  }
  hideModal(); setBtnWorking(btn,false);
}

async function applyDriverAI(btn){
  if(!driverPlanCommand || driverPlanCommand==='none'){ alert('Сначала получите AI план'); return; }
  if(!confirm('Применить AI-план и запустить '+driverPlanCommand+' ?')) return;
  showModal('Применение AI плана...', 'Запускаем интерактивную установку драйвера.');
  setBtnWorking(btn,true);
  try{
    const fd=new FormData(); fd.append('command',driverPlanCommand);
    const r=await fetch('/api/driver-ai-apply',{method:'POST',body:fd});
    const text=await r.text();
    document.getElementById('outUpdate').textContent=text;
  }catch(e){ document.getElementById('outUpdate').textContent='Ошибка: '+e.message; }
  hideModal(); setBtnWorking(btn,false);
}

async function refreshQuarantine(){
  try{
    const r=await fetch('/api/quarantine-hashes');
    const arr=await r.json();
    const list=document.getElementById('quarantineList');
    if(list) list.innerHTML=arr.length?arr.map(x=>'<div>'+escapeHtml(x.name)+'</div>').join(''):'<div>Карантин пуст</div>';
  }catch(e){}
}

async function saveVTKey(){
  const key=document.getElementById('vtkey').value;
  if(!key){ alert('Введите VT ключ'); return; }
  const fd=new FormData(); fd.append('key',key);
  await fetch('/api/vt-key',{method:'POST',body:fd});
  alert('VirusTotal ключ сохранён');
}

async function saveVTKeyFromSettings(){
  const key=document.getElementById('vtkeySettings').value;
  if(!key){ alert('Введите VT ключ'); return; }
  const fd=new FormData(); fd.append('key',key);
  await fetch('/api/vt-key',{method:'POST',body:fd});
  alert('Сохранено');
}

function humanBytes(n){
  if(!Number.isFinite(n)) return '—';
  const u=['B','KB','MB','GB']; let i=0; let x=n;
  while(x>=1024 && i<u.length-1){x/=1024;i++;}
  return x.toFixed(i===0?0:1)+' '+u[i];
}

async function refreshLogHealth(){
  try{
    const r=await fetch('/api/log-health');
    if(!r.ok) throw new Error(await r.text()||('HTTP '+r.status));
    const d=await r.json();
    document.getElementById('logLines').textContent=d.exists?String(d.lineCount):'0';
    document.getElementById('logSize').textContent=d.exists?humanBytes(d.sizeBytes):'0 B';
    document.getElementById('logOldest').textContent=d.oldest||'—';
    document.getElementById('logNewest').textContent=d.newest||'—';
  }catch(e){
    document.getElementById('logCompactOut').textContent='Ошибка метрик: '+e.message;
  }
}

async function compactLogsNow(btn){
  showModal('Компакция логов...', 'Удаляем устаревшие события и лишние строки.');
  setBtnWorking(btn, true);
  try{
    const r=await fetch('/api/log-compact',{method:'POST'});
    const text=await r.text();
    document.getElementById('logCompactOut').textContent=r.ok?text:('Ошибка compaction: '+text);
    refreshLogHealth();
  }catch(e){
    document.getElementById('logCompactOut').textContent='Ошибка: '+e.message;
  }
  hideModal();
  setBtnWorking(btn, false);
}

async function refreshActivity(){
  try{
    const r=await fetch('/api/events-tail');
    const arr=await r.json();
    document.getElementById('activityList').innerHTML=arr.map(x=>'<div>'+escapeHtml(x)+'</div>').join('')||'<div>Нет событий</div>';
  }catch(e){ document.getElementById('activityList').innerHTML='<div>—</div>'; }
}
function escapeHtml(s){ const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

refreshStatus(); refreshThreats(); refreshHistory(); refreshActivity(); refreshLogHealth(); refreshDriverReport(); refreshStartupCheck(); labTimeline();
</script>
</body>
</html>
`
