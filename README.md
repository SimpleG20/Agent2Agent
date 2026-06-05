# Agent2Agent

Protótipo de uma mini economia de agentes usando comunicação A2A, descoberta de agentes e pagamento simulado por créditos.

O projeto demonstra como diferentes agentes podem se registrar em um serviço de descoberta, anunciar suas habilidades e receber tarefas via HTTP. Cada agente exige um token de pagamento simulado antes de executar a tarefa, retornando `402 Payment Required` quando o token não é enviado ou é inválido.

## Para que serve

Este projeto serve como uma prova de conceito acadêmica para:

- Descobrir agentes por habilidade, como `summary`, `translation` e `research`.
- Enviar tarefas para agentes independentes via HTTP.
- Simular cobrança por uso com créditos e tokens.
- Demonstrar um fluxo A2A, no qual um agente chama outro agente para completar uma tarefa.
- Testar uma interface web simples para descoberta, carteira, envio de tarefas e logs.

## Como funciona

O sistema é composto por quatro serviços Node.js:

| Serviço | Porta | Descrição |
| --- | --- | --- |
| Registry | `3000` | Lista agentes, registra novos agentes e gerencia a carteira simulada. |
| Summary Agent | `3001` | Resume textos usando uma resposta mockada. |
| Translation Agent | `3002` | Traduz textos usando uma resposta mockada. |
| Research Agent | `3003` | Faz uma pesquisa simulada e chama o Summary Agent via A2A. |

Também existe um frontend estático em `frontend/index.html` para interagir com os serviços.

## Requisitos

- Node.js 18 ou superior
- npm

## Instalação

```bash
npm install
```

## Como rodar

Para iniciar o registry e todos os agentes:

```bash
npm run dev
```

Esse comando sobe todos os serviços ao mesmo tempo usando `concurrently`.

Depois, abra o frontend no navegador:

```text
frontend/index.html
```

Se preferir rodar os serviços separadamente:

```bash
npm run start:registry
npm run start:summary
npm run start:translation
npm run start:research
```

## Fluxo de uso

1. Inicie os serviços com `npm run dev`.
2. Abra `frontend/index.html`.
3. Veja o saldo da carteira simulada.
4. Liste ou filtre agentes por habilidade.
5. Selecione um agente.
6. Envie uma tarefa.
7. Observe o retorno `402 Payment Required` quando a opção de simulação estiver ativa.
8. Reenvie a tarefa com um token válido.
9. Veja o resultado e os logs da operação.

Tokens válidos para teste:

```text
fake-token-123
demo-token-456
test-token-789
```

## Exemplos de API

Listar agentes:

```bash
curl http://localhost:3000/agents
```

Filtrar agentes por habilidade:

```bash
curl "http://localhost:3000/agents?skill=summary"
```

Consultar carteira padrão:

```bash
curl http://localhost:3000/wallet
```

Adicionar créditos:

```bash
curl -X POST http://localhost:3000/wallet \
  -H "Content-Type: application/json" \
  -d '{"owner":"default","amount":10}'
```

Enviar tarefa sem token, gerando `402 Payment Required`:

```bash
curl -X POST http://localhost:3001/task \
  -H "Content-Type: application/json" \
  -d '{"task_id":"demo-1","skill":"summary","payload":{"text":"Este é um texto longo para demonstrar o resumo. Ele possui mais de uma frase. O agente deve retornar uma versão menor."}}'
```

Enviar tarefa com token válido:

```bash
curl -X POST http://localhost:3001/task \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: fake-token-123" \
  -d '{"task_id":"demo-2","skill":"summary","payload":{"text":"Este é um texto longo para demonstrar o resumo. Ele possui mais de uma frase. O agente deve retornar uma versão menor."}}'
```

Testar o Research Agent com chamada A2A para o Summary Agent:

```bash
curl -X POST http://localhost:3003/task \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: fake-token-123" \
  -d '{"task_id":"research-1","skill":"research","payload":{"text":"inteligencia artificial e LLMs"}}'
```

## Endpoints principais

### Registry

- `GET /agents`: lista todos os agentes.
- `GET /agents?skill=<skill>`: filtra agentes por habilidade.
- `GET /agents/:id`: busca um agente por ID.
- `POST /register`: registra um novo agente.
- `GET /wallet`: consulta ou cria a carteira do owner informado.
- `POST /wallet`: adiciona créditos à carteira.
- `POST /wallet/transfer`: simula débito de créditos.
- `GET /wallet/history`: lista o histórico da carteira.
- `GET /health`: verifica o status do registry.

### Agentes

Todos os agentes expõem:

- `POST /task`: recebe uma tarefa e executa a habilidade do agente.
- `GET /health`: verifica o status do agente.

Formato básico de tarefa:

```json
{
  "task_id": "task-123",
  "skill": "summary",
  "payload": {
    "text": "Texto ou consulta para o agente"
  }
}
```

## Observações

- O registry, a carteira e o histórico ficam em memória. Ao reiniciar os serviços, os dados voltam ao estado inicial.
- As respostas dos agentes são mockadas; não há chamada real para modelos de IA.
- O pagamento é uma simulação baseada em tokens HTTP, sem integração real com blockchain, gateway de pagamento ou carteira externa.
- O Research Agent demonstra comunicação A2A chamando o Summary Agent internamente.
