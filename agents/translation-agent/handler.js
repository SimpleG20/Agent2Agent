const mock = require('./mock');

function handleTask(payload) {
  return mock.mockResponse(payload);
}

module.exports = { handleTask };
