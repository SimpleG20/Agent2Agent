// Mini Agent Economy - Frontend App
const API = {
  registry: 'http://localhost:3000',
  agents: {
    summary: 'http://localhost:3001',
    translation: 'http://localhost:3002',
    research: 'http://localhost:3003'
  }
};

const STATE = {
  agents: [],
  selectedAgent: null,
  walletId: null,
  owner: 'default',
  log: []
};

// --- DOM refs ---
const $ = id => document.getElementById(id);
const balanceEl = $('balance');
const agentList = $('agent-list');
const agentSelect = $('agent-select');
const taskSkill = $('task-skill');
const taskPayload = $('task-payload');
const translationLang = $('translation-lang');
const chkSimulate402 = $('chk-simulate-402');
const tokenRow = $('token-row');
const tokenSelect = $('token-select');
const taskResult = $('task-result');
const transactionLog = $('transaction-log');

// --- Wallet ---
async function loadWallet() {
  try {
    const res = await fetch(`${API.registry}/wallet?owner=${STATE.owner}`);
    const data = await res.json();
    STATE.walletId = data.id;
    balanceEl.textContent = data.balance;
  } catch (e) {
    balanceEl.textContent = 'ERR';
    addLog('Failed to load wallet', 'fail');
  }
}

async function addCredits(amount = 10) {
  try {
    const res = await fetch(`${API.registry}/wallet/transfer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        walletId: STATE.walletId,
        amount: -amount,
        description: 'Credit top-up (negative debit = credit)'
      })
    });
    // Simpler: direct credit via fake endpoint
    // Actually wallet.js has credit(). Let's call it directly through a custom endpoint
    // For simplicity, let's just do a POST to add credits manually
    const creditRes = await fetch(`${API.registry}/wallet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner: STATE.owner, amount })
    });
    if (creditRes.ok) {
      await loadWallet();
      addLog(`Added ${amount} credits`, 'ok');
    }
  } catch (e) {
    addLog('Failed to add credits', 'fail');
  }
}

// --- Agent Discovery ---
async function discoverAgents(skill = '') {
  try {
    const url = skill
      ? `${API.registry}/agents?skill=${encodeURIComponent(skill)}`
      : `${API.registry}/agents`;
    const res = await fetch(url);
    const data = await res.json();
    STATE.agents = data.agents || [];
    renderAgentList(STATE.agents);
    populateAgentSelect(STATE.agents);
    addLog(`Found ${STATE.agents.length} agent(s)${skill ? ` for skill "${skill}"` : ''}`, 'ok');
  } catch (e) {
    agentList.innerHTML = '<div class="agent-card" style="color:#f87171">Error connecting to registry</div>';
    addLog('Registry connection failed', 'fail');
  }
}

function renderAgentList(agents) {
  if (agents.length === 0) {
    agentList.innerHTML = '<div style="color:#888; padding: 0.5rem;">No agents found</div>';
    return;
  }
  agentList.innerHTML = agents.map(a => {
    const hasA2A = a.id === 'research-agent';
    return `
    <div class="agent-card" data-id="${a.id}" onclick="selectAgent('${a.id}')">
      <div class="agent-info">
        <h3>${a.name} ${hasA2A ? '<span class="a2a-badge">A2A</span>' : ''}</h3>
        <p>${a.description || ''}</p>
        <span class="agent-skills">${a.skills.join(', ')}</span>
      </div>
      <div class="agent-meta">
        <div class="agent-price">${a.price} credit(s)</div>
        <div class="agent-status">${a.status}</div>
        <div style="font-size:0.7rem;color:#666;margin-top:2px">${a.endpoint}</div>
      </div>
    </div>
  `}).join('');
}

function populateAgentSelect(agents) {
  agentSelect.innerHTML = '<option value="">-- Select agent --</option>' +
    agents.map(a => `<option value="${a.id}">${a.name} (${a.price} credits)</option>`).join('');
}

function selectAgent(id) {
  // Visual highlight
  document.querySelectorAll('.agent-card').forEach(el => el.classList.remove('selected'));
  const card = document.querySelector(`.agent-card[data-id="${id}"]`);
  if (card) card.classList.add('selected');

  const agent = STATE.agents.find(a => a.id === id);
  STATE.selectedAgent = agent;
  if (agent) {
    agentSelect.value = agent.id;
    taskSkill.value = agent.skills[0] || '';
    // Show translation lang only for translation
    translationLang.closest('.form-row').style.display =
      agent.skills.includes('translation') ? 'flex' : 'none';
    addLog(`Selected agent: ${agent.name}`, 'ok');
  }
}

// --- Task Execution ---
async function sendTask() {
  const agent = STATE.selectedAgent;
  if (!agent) {
    showResult('Select an agent first', 'error');
    return;
  }

  const skill = taskSkill.value.trim();
  const text = taskPayload.value.trim();
  if (!text) {
    showResult('Enter text or query', 'error');
    return;
  }

  const payload = { text };
  if (skill === 'translation') {
    payload.target_lang = translationLang.value;
  }

  const taskId = 'task-' + Date.now();

  if (chkSimulate402.checked) {
    // Step 1: Send WITHOUT token -> expect 402
    addLog(`[${agent.name}] Sending without token (expect 402)...`, 'pending');
    showResult('⏳ Simulating 402 Payment Required...', 'payment');

    try {
      const res1 = await fetch(agent.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ task_id: taskId, skill, payload })
      });

      if (res1.status === 402) {
        const errData = await res1.json();
        showResult(
          `⛔ 402 Payment Required\nPrice: ${errData.price} credit(s)\nMessage: ${errData.message}\nHint: ${errData.hint || ''}`,
          'payment'
        );
        addLog(`[${agent.name}] Got 402 Payment Required (price: ${errData.price})`, 'pending');

        // Step 2: Resend WITH token
        const token = tokenSelect.value;
        addLog(`[${agent.name}] Retrying with token: ${token}...`, 'pending');
        showResult(prev => prev + '\n\n🔄 Retrying with token...');

        const res2 = await fetch(agent.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Agent-Token': token
          },
          body: JSON.stringify({ task_id: taskId, skill, payload })
        });

        if (res2.ok) {
          const data = await res2.json();
          showResult(JSON.stringify(data, null, 2), 'success');
          addLog(`[${agent.name}] Task completed! Cost: ${agent.price} credit(s)`, 'ok');
          await loadWallet(); // Refresh balance
        } else {
          const err2 = await res2.json();
          showResult(JSON.stringify(err2, null, 2), 'error');
          addLog(`[${agent.name}] Task failed after token`, 'fail');
        }
      } else {
        // Unexpected: no 402
        const data = await res1.json();
        showResult(JSON.stringify(data, null, 2), 'success');
        addLog(`[${agent.name}] Task completed (no 402 triggered)`, 'ok');
      }
    } catch (e) {
      showResult(`Error: ${e.message}`, 'error');
      addLog(`[${agent.name}] Connection error: ${e.message}`, 'fail');
    }
  } else {
    // Send directly with token (skip 402 simulation)
    try {
      const res = await fetch(agent.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Agent-Token': tokenSelect.value
        },
        body: JSON.stringify({ task_id: taskId, skill, payload })
      });
      const data = await res.json();
      if (res.ok) {
        showResult(JSON.stringify(data, null, 2), 'success');
        addLog(`[${agent.name}] Task completed!`, 'ok');
      } else {
        showResult(JSON.stringify(data, null, 2), 'error');
        addLog(`[${agent.name}] Task failed`, 'fail');
      }
      await loadWallet();
    } catch (e) {
      showResult(`Error: ${e.message}`, 'error');
      addLog(`[${agent.name}] Connection error: ${e.message}`, 'fail');
    }
  }
}

// --- UI Helpers ---
function showResult(content, type = '') {
  taskResult.className = 'result-box visible ' + type;

  // If showing raw JSON, render with A2A visualization
  if (typeof content === 'string' && content.startsWith('{')) {
    try {
      const data = JSON.parse(content);
      taskResult.innerHTML = formatResultWithA2A(data);
      return;
    } catch { /* fallback to text */ }
  }

  if (typeof content === 'function') {
    taskResult.textContent = content(taskResult.textContent);
  } else {
    taskResult.textContent = content;
  }
}

function formatResultWithA2A(data) {
  const parts = [];

  // A2A Chain visualization
  if (data.result && data.result.a2a_chain) {
    const chain = data.result.a2a_chain;
    parts.push(`<div class="a2a-chain">`);
    parts.push(`<div class="a2a-title">🔗 A2A Communication Chain</div>`);
    parts.push(`<div class="a2a-flow">`);
    chain.forEach((step, i) => {
      const agents = step.split('→').map(s => s.trim());
      agents.forEach((agent, j) => {
        if (j > 0) parts.push(`<span class="a2a-arrow"> → </span>`);
        parts.push(`<span class="a2a-agent">${agent}</span>`);
      });
      if (i < chain.length - 1) parts.push(`<span class="a2a-arrow"> → </span>`);
    });
    parts.push(`</div>`);
    if (data.result.note) {
      parts.push(`<div class="a2a-note">💬 ${data.result.note}</div>`);
    }
    parts.push(`</div>`);
  }

  // Show visual A2A summary if present
  if (data.result && data.result.a2a_summary) {
    const summary = data.result.a2a_summary;
    if (summary.summary) {
      parts.push(`<div class="a2a-summary-box">`);
      parts.push(`<div class="a2a-summary-title">📝 Summary Agent Result (via A2A)</div>`);
      parts.push(`<div class="a2a-summary-text">${escapeHtml(summary.summary)}</div>`);
      parts.push(`</div>`);
    }
  }

  // Show research result
  if (data.result && data.result.research) {
    const r = data.result.research;
    if (r.result) {
      parts.push(`<div class="a2a-summary-box">`);
      parts.push(`<div class="a2a-summary-title">🔍 Research Result</div>`);
      parts.push(`<div><b>${escapeHtml(r.result.title || '')}</b></div>`);
      parts.push(`<div style="margin-top:4px;color:#aaa">${escapeHtml(r.result.snippet || '')}</div>`);
      parts.push(`<div style="margin-top:4px;color:#666;font-size:0.75rem">Sources: ${r.result.sources || 0} | Confidence: ${r.confidence || 'N/A'}</div>`);
      parts.push(`</div>`);
    }
  }

  // Full JSON for detail
  const jsonPretty = JSON.stringify(data, null, 2);
  parts.push(`<details class="a2a-json-detail">`);
  parts.push(`<summary>📄 View full JSON response</summary>`);
  parts.push(`<pre>${escapeHtml(jsonPretty)}</pre>`);
  parts.push(`</details>`);

  return parts.join('\n');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function addLog(msg, status = 'ok') {
  const time = new Date().toLocaleTimeString();
  STATE.log.unshift({ time, msg, status });
  renderLog();
}

function renderLog() {
  transactionLog.innerHTML = STATE.log.slice(0, 50).map(entry => `
    <div class="log-entry">
      <span class="log-time">${entry.time}</span>
      <span class="log-msg">${entry.msg}</span>
      <span class="log-status ${entry.status}">${entry.status}</span>
    </div>
  `).join('');
}

function clearLog() {
  STATE.log = [];
  renderLog();
}

function toggleTokenRow() {
  tokenRow.classList.toggle('visible', !chkSimulate402.checked);
}

// --- Event Bindings ---
$('btn-search').addEventListener('click', () => discoverAgents($('skill-search').value.trim()));
$('btn-list-all').addEventListener('click', () => discoverAgents());
$('btn-refresh-wallet').addEventListener('click', loadWallet);
$('btn-add-credits').addEventListener('click', () => addCredits(10));
$('btn-send-task').addEventListener('click', sendTask);
$('btn-clear-logs').addEventListener('click', clearLog);
chkSimulate402.addEventListener('change', toggleTokenRow);

agentSelect.addEventListener('change', () => {
  const agent = STATE.agents.find(a => a.id === agentSelect.value);
  if (agent) selectAgent(agent.id);
});

// Enter key in search
$('skill-search').addEventListener('keydown', e => {
  if (e.key === 'Enter') discoverAgents(e.target.value.trim());
});

// --- Init ---
async function init() {
  await loadWallet();
  await discoverAgents();
  toggleTokenRow();
  addLog('App initialized. Registry: ' + API.registry, 'ok');
}

init();
