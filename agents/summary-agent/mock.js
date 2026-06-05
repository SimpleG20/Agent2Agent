// Summary Agent - Responde com resumos mockados
function summarize(text) {
  if (!text || text.trim().length === 0) {
    return { summary: '', originalLength: 0, summaryLength: 0 };
  }
  const clean = text.trim();
  const sentences = clean.split(/[.!?]+/).filter(s => s.trim().length > 0);
  const summary = sentences.length <= 2
    ? clean
    : sentences.slice(0, 2).join('. ') + '. [resumo mockado — primeiras frases]';
  return {
    summary,
    originalLength: clean.length,
    summaryLength: summary.length
  };
}

function mockResponse(payload) {
  const text = payload.text || payload.content || '';
  const result = summarize(text);
  return {
    summary: result.summary,
    originalLength: result.originalLength,
    summaryLength: result.summaryLength,
    tokensUsed: Math.ceil(result.originalLength / 4),
    provider: 'mock'
  };
}

module.exports = { summarize, mockResponse };
