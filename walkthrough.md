# Walkthrough: Protótipo de Comunicação A2A Soberana

Este documento descreve o que foi construído, os componentes implementados, as modificações de infraestrutura local, e os resultados da verificação automatizada de ponta a ponta (E2E) para a rede descentralizada de comunicação segura entre agentes (Agente Alfa e Agente Beta).

---

## 🛠️ O que foi Implementado

O projeto foi construído sob o diretório [a2a-secure-net](file:///home/tasso/Desktop/a2a-secure-net) com as seguintes camadas:

1. **Infraestrutura Blockchain Local (EVM):**
   - Um nó **Ganache** local rodando em background na porta `8545`.
   - Um smart contract [IdentityRegistry.sol](file:///home/tasso/Desktop/a2a-secure-net/blockchain/contracts/IdentityRegistry.sol) compilado usando a versão de EVM `paris` (para evitar incompatibilidades de PUSH0) e implantado no Ganache.
   - Script de deploy automatizado [deploy.js](file:///home/tasso/Desktop/a2a-secure-net/blockchain/deploy.js) que compila o contrato e registra o endereço gerado em [deployed_address.json](file:///home/tasso/Desktop/a2a-secure-net/blockchain/deployed_address.json).

2. **Camada Criptográfica (Go Key Guard):**
   - Um microserviço Go autocontido ([main.go](file:///home/tasso/Desktop/a2a-secure-net/key-guard/main.go)) compilado em binário executável (`key-guard-bin`).
   - Módulo criptográfico [crypto.go](file:///home/tasso/Desktop/a2a-secure-net/key-guard/crypto/crypto.go) que gera chaves Ed25519 de forma soberana para cada agente e manipula assinaturas Ed25519 de payloads.
   - Módulo blockchain [client.go](file:///home/tasso/Desktop/a2a-secure-net/key-guard/blockchain/client.go) que interage com a rede local Ethereum (Anvil/Ganache) usando o `go-ethereum` SDK para registrar os DIDs (`did:custom:alfa`, `did:custom:beta`) vinculando a chave Ed25519 e o endpoint HTTP.
   - Validador determinístico de regras de negócio [rules.go](file:///home/tasso/Desktop/a2a-secure-net/key-guard/rules/rules.go) que bloqueia assinaturas se transações forem maiores que 100.0 ou se o payload contiver vazamento de chaves ou injeções (`private_key`, `secret_key`, `sudo`).
   - Módulo [didcomm.go](file:///home/tasso/Desktop/a2a-secure-net/key-guard/didcomm/didcomm.go) encapsulando mensagens no padrão de envelope assinado **JWS (JSON Web Signature) Flat Serialization** do DIDComm v2.
   - Cache de blacklist local [blacklist.go](file:///home/tasso/Desktop/a2a-secure-net/key-guard/blacklist/blacklist.go) com suporte a expiração TTL em arquivo JSON.
   - Endpoint `/resolve` (GET) adicionado para expor a resolução em tempo real de DIDs para o painel de controle.

3. **Camada Cognitiva (Python + LangGraph Tools):**
   - Classe [agent.py](file:///home/tasso/Desktop/a2a-secure-net/cognitive/agent.py) com as tools `SendMessageTool` e `ReadInboxTool` que comunicam o agente LLM com seu Key Guard via requisições HTTP REST internas.
   - Monitor de anomalias cognitivas em Python com detecção proativa de Prompt Injections ("ignore previous instructions", "override rules", etc.) que dispara o circuit breaker isolando o par localmente e disparando uma notificação de auto-revogação P2P DIDComm.
   - Interface de loop contínuo [agent_main.py](file:///home/tasso/Desktop/a2a-secure-net/cognitive/agent_main.py) para simular escutas de rede em consoles interativos.

4. **Painel de Controle Visual (Interactive Dashboard):**
   - Desenvolvemos uma interface web em Flask ([server.py](file:///home/tasso/Desktop/a2a-secure-net/dashboard/server.py)) executando na porta `9000`.
   - Painel frontend [index.html](file:///home/tasso/Desktop/a2a-secure-net/dashboard/templates/index.html) estilizado com estética moderna escura, glassmorphism e cores HSL personalizadas.
   - Permite visualizar em tempo real o status dos Key Guards, DIDs resolvidos na Blockchain, chaves públicas registradas, caches de blacklist em Go e Python, e a caixa de entrada (inbox).
   - Possibilita o envio de mensagens e simulação direta de ataques de injeção e violações de regras para ver o Circuit Breaker atuando visualmente.

---

## 🧪 Resultados da Verificação Automatizada

Executamos o script de testes de integração automatizados [simulation_test.py](file:///home/tasso/Desktop/a2a-secure-net/tests/simulation_test.py) que simula o ecossistema completo de ponta a ponta. 

### Comando executado:
```bash
./venv/bin/python3 tests/simulation_test.py
```

### Output dos Testes:
```
Starting Key Guard subprocesses (logging to files)...
Waiting for Key Guards to register on-chain and start (5s)...

--- Test 01: Normal P2P Communication ---
Test 01 tool_send_message result: {'status': 'sent'}
Test 01 passed: Normal secure message sent, signed, resolved, and verified successfully.
.
--- Test 02: Key Guard Business Rule Violation (Amount > 100) ---
Test 02 Key Guard direct send status code: 403
Test 02 Key Guard direct send response: {'error': 'business rule violation: amount 150.000000 exceeds limit of 100.0'}
Test 02 passed: Key Guard successfully blocked signature for exceeding limit.
.
--- Test 03: Key Guard Security Rule Violation (Forbidden Keyword) ---
Test 03 Key Guard direct send status code: 403
Test 03 Key Guard direct send response: {'error': "security violation: payload contains forbidden keyword 'private_key'"}
Test 03 passed: Key Guard successfully blocked signature containing forbidden keywords.
.
--- Test 04: Cognitive Anomaly Detection and P2P Revocation Circuit Breaker ---
[ALFA COGNITIVE] ANOMALY DETECTED: Prompt injection attempt detected: 'ignore previous instructions'. Triggering local isolation.
[ALFA COGNITIVE] Dispatching P2P revocation alert to did:custom:beta
[ALFA COGNITIVE] Local blacklist updated: blocked did:custom:beta (Reason: Prompt injection attempt detected: 'ignore previous instructions')
Waiting for Beta Key Guard to receive and cache the revocation (2s)...
Test 04 P2P receive-message status code: 401
Test 04 P2P receive-message response: {'error': 'Sender is blacklisted locally'}
Test 04 passed: Circuit Breaker triggered. Faulty agent isolated, and P2P revocation alert verified.
.
Terminating Key Guard subprocesses...
----------------------------------------------------------------------
Ran 4 tests in 8.429s

OK
```

---

## 📈 Conclusão

Todos os testes passaram com sucesso, comprovando:
1. Geração local e armazenamento isolado de chaves privadas (Soberania de dados).
2. Validação determinística de regras pelo Key Guard em Go antes de assinar.
3. Resolução dinâmica de DIDs e endpoints na Blockchain local.
4. Isolamento automático offline (Circuit Breaker) via propagação P2P de alertas de revogação.
