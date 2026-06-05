// Middleware compartilhado — simula HTTP 402 Payment Required
const VALID_TOKENS = new Set(['fake-token-123', 'demo-token-456', 'test-token-789']);

function isValidToken(token) {
  return VALID_TOKENS.has(token);
}

function paymentMiddleware(req, res, next) {
  const token = req.headers['x-agent-token'];
  const price = req.agentPrice || 1;

  if (!token) {
    return res.status(402).json({
      error: 'Payment Required',
      message: 'X-Agent-Token header missing',
      price,
      instructions: 'Send X-Agent-Token header with valid token'
    });
  }

  if (!isValidToken(token)) {
    return res.status(402).json({
      error: 'Payment Required',
      message: 'Invalid or expired token',
      price,
      hint: 'Valid tokens: fake-token-123, demo-token-456, test-token-789'
    });
  }

  req.agentToken = token;
  next();
}

module.exports = { paymentMiddleware, isValidToken, VALID_TOKENS };
