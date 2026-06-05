const express = require('express');
const cors = require('cors');
const { paymentMiddleware } = require('../shared/middleware');
const handler = require('./handler');

const app = express();
const PORT = 3003;
const PRICE = 3;

app.use(cors());
app.use(express.json());

app.post('/task', paymentMiddleware, async (req, res) => {
  const { task_id, payload } = req.body;
  console.log(`[Research] Task received: ${task_id}`);

  try {
    const result = await handler.handleTask(payload || {});
    res.json({
      task_id: task_id || 'unknown',
      status: 'completed',
      agent: 'research-agent',
      price: PRICE,
      result,
      token: req.agentToken
    });
  } catch (err) {
    console.error(`[Research] Error: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', agent: 'research-agent', port: PORT, price: PRICE });
});

app.listen(PORT, () => {
  console.log(`[Research Agent] Running on http://localhost:${PORT}`);
  console.log(`[Research Agent] Price: ${PRICE} credit(s)`);
  console.log(`[Research Agent] A2A enabled → calls Summary Agent`);
});
