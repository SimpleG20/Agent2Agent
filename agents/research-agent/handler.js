const mock = require('./mock');
const { callAgent } = require('../shared/a2a-client');

const SUMMARY_AGENT = 'http://localhost:3001/task';

async function handleTask(payload) {
  // Step 1: Do research
  const researchResult = mock.mockResponse(payload);

  // Step 2: Call Summary Agent (A2A) to summarize findings
  let summaryResult = null;
  try {
    const snippet = researchResult.result?.snippet || JSON.stringify(researchResult);
    const summaryResponse = await callAgent(
      SUMMARY_AGENT,
      'a2a-' + Date.now(),
      'summary',
      { text: snippet }
    );
    summaryResult = summaryResponse.result;
    console.log(`[Research] A2A call to Summary Agent: OK`);
  } catch (err) {
    console.log(`[Research] A2A call failed (Summary may be down): ${err.message}`);
    summaryResult = { error: 'A2A communication failed', detail: err.message };
  }

  return {
    research: researchResult,
    a2a_summary: summaryResult,
    a2a_chain: ['research-agent → summary-agent'],
    note: 'Research Agent called Summary Agent via A2A protocol'
  };
}

module.exports = { handleTask };
