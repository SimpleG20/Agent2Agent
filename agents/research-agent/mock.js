// Research Agent - Pesquisa simulada

const fakeResults = {
  climate: {
    title: 'Mudancas Climaticas: Impactos Globais',
    snippet: 'Pesquisas indicam que a temperatura media global aumentou 1.1°C desde a era pre-industrial. ' +
      'O painel IPCC projeta impactos significativos em ecossistemas, agricultura e zonas costeiras ' +
      'nas proximas decadas.',
    sources: 24
  },
  ai: {
    title: 'Inteligencia Artificial: Avancos Recentes',
    snippet: 'Modelos de linguagem large (LLMs) como GPT-4 e Claude demonstraram capacidades ' +
      'avancadas em raciocinio, traducao e geracao de codigo. O campo avanca rapidamente em ' +
      'direcao a sistemas multimodais e autonometos.',
    sources: 42
  },
  space: {
    title: 'Exploracao Espacial: Nova Era',
    snippet: 'Programas Artemis da NASA e Starship da SpaceX prometem retorno a Lua e missoes ' +
      'tripuladas a Marte. Telescopio James Webb revela dados revolucionarios sobre o universo ' +
      'primitivo.',
    sources: 18
  }
};

function research(query) {
  if (!query || query.trim().length === 0) {
    return { query: '', result: null, error: 'Query is required' };
  }

  const lower = query.toLowerCase();
  let data = null;

  if (lower.includes('climate') || lower.includes('clima') || lower.includes('global')) {
    data = fakeResults.climate;
  } else if (lower.includes('ai') || lower.includes('intelligence') || lower.includes('inteligencia') || lower.includes('gpt') || lower.includes('llm')) {
    data = fakeResults.ai;
  } else if (lower.includes('space') || lower.includes('espaco') || lower.includes('nasa') || lower.includes('marte')) {
    data = fakeResults.space;
  }

  if (!data) {
    return {
      query,
      result: {
        title: `Resultados para: ${query}`,
        snippet: `🔍 [Resultado simulado para: "${query}"] — Pesquisa academica simulada. ` +
          `Nao foram encontradas correspondencias nas bases de dados pre-definidas.`,
        sources: 0
      },
      confidence: 'low'
    };
  }

  return {
    query,
    result: data,
    confidence: 'high',
    tokensUsed: Math.ceil(query.length / 2)
  };
}

function mockResponse(payload) {
  const query = payload.query || payload.text || payload.content || '';
  const result = research(query);
  return { ...result, provider: 'mock' };
}

module.exports = { research, mockResponse };
