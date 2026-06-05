const { v4: uuidv4 } = require('uuid');

// Em memória — simula registro descentralizado
const agents = new Map();

function registerAgent(card) {
  const agent = {
    ...card,
    id: card.id || uuidv4(),
    registeredAt: new Date().toISOString(),
    status: card.status || 'online'
  };
  agents.set(agent.id, agent);
  return agent;
}

function getAgent(id) {
  return agents.get(id) || null;
}

function listAgents(skill) {
  const all = Array.from(agents.values());
  if (!skill) return all;
  return all.filter(a =>
    a.skills.some(s => s.toLowerCase() === skill.toLowerCase())
  );
}

function unregisterAgent(id) {
  return agents.delete(id);
}

// Seed agents
registerAgent({
  id: 'summary-agent',
  name: 'Summary Agent',
  description: 'Agente que resume textos longos em paragrafos curtos',
  endpoint: 'http://localhost:3001/task',
  skills: ['summary', 'text-processing'],
  price: 1,
  aiProvider: 'mock',
  status: 'online'
});

registerAgent({
  id: 'translation-agent',
  name: 'Translation Agent',
  description: 'Agente que traduz textos entre idiomas',
  endpoint: 'http://localhost:3002/task',
  skills: ['translation', 'text-processing'],
  price: 2,
  aiProvider: 'mock',
  status: 'online'
});

registerAgent({
  id: 'research-agent',
  name: 'Research Agent',
  description: 'Agente que realiza pesquisas simuladas sobre topicos',
  endpoint: 'http://localhost:3003/task',
  skills: ['research', 'knowledge'],
  price: 3,
  aiProvider: 'mock',
  status: 'online'
});

module.exports = { registerAgent, getAgent, listAgents, unregisterAgent };
