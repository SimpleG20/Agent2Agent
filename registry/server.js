const express = require('express');
const cors = require('cors');
const registry = require('./registry');
const wallet = require('./wallet');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// --- Registry endpoints ---
app.get('/agents', (req, res) => {
  const { skill } = req.query;
  const list = registry.listAgents(skill);
  res.json({ agents: list, count: list.length });
});

app.get('/agents/:id', (req, res) => {
  const agent = registry.getAgent(req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  res.json(agent);
});

app.post('/register', (req, res) => {
  const card = req.body;
  if (!card.name || !card.endpoint || !card.skills) {
    return res.status(400).json({ error: 'Missing required fields: name, endpoint, skills' });
  }
  const agent = registry.registerAgent(card);
  res.status(201).json(agent);
});

// --- Wallet endpoints ---
app.get('/wallet', (req, res) => {
  const w = wallet.getOrCreateWallet(req.query.owner || 'default');
  res.json({ id: w.id, owner: w.owner, balance: w.balance });
});

app.post('/wallet', (req, res) => {
  const { owner, amount } = req.body;
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Positive amount required' });
  }
  const w = wallet.getOrCreateWallet(owner || 'default');
  const result = wallet.credit(w.id, amount, 'Manual credit top-up');
  if (!result.ok) {
    return res.status(500).json({ error: result.error });
  }
  res.json({ id: w.id, owner: w.owner, balance: w.balance, transaction: result.transaction });
});

app.post('/wallet/transfer', (req, res) => {
  const { walletId, amount, agentId, description } = req.body;
  if (!walletId || !amount) {
    return res.status(400).json({ error: 'walletId and amount required' });
  }
  const result = wallet.debit(walletId, amount, description || `Payment to ${agentId || 'agent'}`);
  if (!result.ok) {
    return res.status(402).json({ error: result.error });
  }
  res.json(result.transaction);
});

app.get('/wallet/history', (req, res) => {
  const w = wallet.getWalletByOwner(req.query.owner || 'default');
  if (!w) return res.status(404).json({ error: 'Wallet not found' });
  const history = wallet.getHistory(w.id);
  res.json({ history });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'agent-registry', agents: registry.listAgents().length });
});

app.listen(PORT, () => {
  console.log(`[Registry] Running on http://localhost:${PORT}`);
  console.log(`[Registry] Agents registered: ${registry.listAgents().length}`);
});
