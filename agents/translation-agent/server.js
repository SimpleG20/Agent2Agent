const express = require('express');
const cors = require('cors');
const { paymentMiddleware } = require('../shared/middleware');
const handler = require('./handler');

const app = express();
const PORT = 3002;
const PRICE = 2;

app.use(cors());
app.use(express.json());

app.post('/task', paymentMiddleware, (req, res) => {
  const { task_id, payload } = req.body;
  console.log(`[Translation] Task received: ${task_id}`);

  const result = handler.handleTask(payload || {});

  res.json({
    task_id: task_id || 'unknown',
    status: 'completed',
    agent: 'translation-agent',
    price: PRICE,
    result,
    token: req.agentToken
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', agent: 'translation-agent', port: PORT, price: PRICE });
});

app.listen(PORT, () => {
  console.log(`[Translation Agent] Running on http://localhost:${PORT}`);
  console.log(`[Translation Agent] Price: ${PRICE} credit(s)`);
});
