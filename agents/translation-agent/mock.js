// Translation Agent - Tradução mockada

const targetLangNames = {
  en: 'English',
  pt: 'Portuguese',
  es: 'Spanish',
  fr: 'French',
  de: 'German',
  it: 'Italian',
  ja: 'Japanese',
  zh: 'Chinese'
};

function translate(text, targetLang = 'en') {
  if (!text || text.trim().length === 0) {
    return { translatedText: '', targetLang };
  }

  const langName = targetLangNames[targetLang] || targetLang.toUpperCase();
  const translatedText = `🌐 [MOCK TRANSLATION TO ${langName}]: ${text.trim()}`;

  return {
    translatedText,
    targetLang,
    sourceDetected: text.trim().length > 0 ? 'unknown' : 'none',
    tokensUsed: Math.ceil(text.trim().length / 3)
  };
}

function mockResponse(payload) {
  const text = payload.text || payload.content || '';
  const targetLang = payload.target_lang || payload.targetLang || 'en';
  const result = translate(text, targetLang);
  return {
    ...result,
    provider: 'mock'
  };
}

module.exports = { translate, mockResponse };
