// Provider abstrato — suporta mock e API real
// Configuravel por agente

class AIProvider {
  constructor(config = {}) {
    this.mode = config.mode || 'mock'; // 'mock' | 'api'
    this.apiKey = config.apiKey || null;
    this.apiUrl = config.apiUrl || null;
  }

  setMode(mode) {
    if (!['mock', 'api'].includes(mode)) {
      throw new Error(`Invalid mode: ${mode}. Use 'mock' or 'api'.`);
    }
    this.mode = mode;
  }

  async process({ skill, payload, mockFn }) {
    if (this.mode === 'api' && this.apiKey) {
      return this._callExternalAPI(skill, payload);
    }
    return mockFn(payload);
  }

  async _callExternalAPI(skill, payload) {
    // Placeholder para integracao real com API de IA
    // Exemplo: OpenAI, Claude, etc.
    console.log(`[AI Provider] Calling external API for skill: ${skill}`);
    // Implementar conforme necessidade
    throw new Error('External API not configured. Set apiKey and apiUrl.');
  }
}

module.exports = AIProvider;
