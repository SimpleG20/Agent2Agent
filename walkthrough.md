# Walkthrough: Protótipo de Comunicação A2A Soberana

Este documento descreve o que foi construído, os componentes implementados e os
resultados da verificação automatizada de ponta a ponta (E2E) para a rede
descentralizada de comunicação segura entre agentes (Agente Alfa e Agente Beta).

---

## O que foi implementado

O projeto foi construído sob o diretório `a2a-secure-net` com as seguintes camadas:

### 1. Camada Criptográfica (Go Key Guard)

Um microserviço Go autocontido com:

- **Geração e gerenciamento de chaves Ed25519** (`crypto/crypto.go`):
  Gera chaves de forma soberana para cada agente, salva em disco codificadas em
  base64 e carrega em execuções futuras.

- **Resolução local de DIDs** (`peers/peers.go`):
  Mantém um cache em `peers.json` com os peers descobertos via handshake P2P.
  Suporta registro, resolução e revogação de peers com proteção concorrente
  via `sync.RWMutex`.

- **Validação determinística de regras** (`rules/rules.go`):
  Bloqueia assinaturas se transações forem maiores que 100.0 ou se o payload
  contiver vazamento de chaves ou comandos proibidos
  (`private_key`, `secret_key`, `sudo`). A validação é recursiva para
  objetos aninhados e slices.

- **Envelopamento DIDComm v2** (`didcomm/didcomm.go`):
  Encapsula mensagens no padrão de envelope assinado **JWS (JSON Web Signature)
  Flat Serialization** do DIDComm v2, usando algoritmo EdDSA.

- **Blacklist com TTL** (`blacklist/blacklist.go`):
  Cache de peers bloqueados com expiração automática. Persistência em
  `blacklist.json` com limpeza de entradas expiradas em goroutine.

- **Handshake P2P direto** (`main.go`):
  Endpoints `/handshake` e `/handshake-peer` para descoberta mútua de agentes
  sem necessidade de blockchain ou registro central.

- **Endpoints REST completos:**
  - `/sign-message` — assina um payload e retorna o JWS
  - `/send-message` — resolve DID, valida regras, assina e transmite P2P
  - `/receive-message` — recebe, verifica assinatura e enfileira na inbox
  - `/inbox` — fila de mensagens recebidas (consumida pela camada cognitiva)
  - `/blacklist` — bloqueio manual de peers
  - `/resolve` — resolução de DIDs em tempo real

### 2. Camada Cognitiva (Python + LangGraph Tools)

- **Classe `CognitiveAgent`** (`cognitive/agent.py`) com as ferramentas:
  - `tool_send_message`: Envia intenção de mensagem para o Key Guard local.
    Inclui pré-validação com detecção de anomalias e verificação de blacklist.
  - `tool_read_inbox`: Polling da inbox do Key Guard com validação de schema
    via Pydantic e detecção de anomalias em mensagens recebidas.

- **Monitor de anomalias cognitivas** com detecção proativa de:
  - Prompt Injections ("ignore previous instructions", "override rules", etc.)
  - Valores anômalos (> 100.0)
  - Schemas inválidos

- **Circuit Breaker:** Ao detectar anomalia, o monitor:
  1. Bloqueia o envio localmente
  2. Dispara mensagem de auto-revogação P2P via DIDComm para o peer afetado
  3. Atualiza blacklists local (SQLite) e no Key Guard (JSON)
  4. Isola o nó faulty com `401 Unauthorized`

- **Interface de loop contínuo** (`cognitive/agent_main.py`):
  Simula escuta de rede em console interativo com polling de inbox a cada 2s.

### 3. Painel de Controle Visual (Dashboard)

- Interface web em **Flask** (`dashboard/server.py`) executando na porta `9000`.
- **Frontend** (`dashboard/templates/index.html`) estilizado com:
  - Estética dark mode com glassmorphism e gradientes
  - Cores HSL personalizadas para Alfa (ciano) e Beta (roxo)
  - Cards com efeito de glow hover

- Funcionalidades do painel:
  - Visualização em tempo real do status dos Key Guards
  - DIDs resolvidos localmente, chaves públicas e endpoints
  - Caches de blacklist (Cognitive + Key Guard)
  - Histórico de transações (inbox logs)
  - Envio de mensagens seguras entre agentes
  - Simulação de ataques: violação de limite, vazamento de chave, prompt injection
  - Botão de reset que limpa caches e reinicia os Key Guards

### 4. Infraestrutura Auxiliar

- **Docker Compose** (`docker-compose.yml`):
  Redis 7 Alpine para filas de mensagens (uso opcional, não utilizado
  diretamente no protótipo atual — a inbox é gerenciada em memória pelo Go).

---

## Resultados da Verificação Automatizada

Executamos o script de testes de integração automatizados
`tests/simulation_test.py` que simula o ecossistema completo de ponta a ponta.

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

--- Test 02: Key Guard Business Rule Violation (Amount > 100) ---
Test 02 Key Guard direct send status code: 403
Test 02 Key Guard direct send response: {'error': 'business rule violation: amount 150.000000 exceeds limit of 100.0'}
Test 02 passed: Key Guard successfully blocked signature for exceeding limit.

--- Test 03: Key Guard Security Rule Violation (Forbidden Keyword) ---
Test 03 Key Guard direct send status code: 403
Test 03 Key Guard direct send response: {'error': "security violation: payload contains forbidden keyword 'private_key'"}
Test 03 passed: Key Guard successfully blocked signature containing forbidden keywords.

--- Test 04: Cognitive Anomaly Detection and P2P Revocation Circuit Breaker ---
[ALFA COGNITIVE] ANOMALY DETECTED: Prompt injection attempt detected: 'ignore previous instructions'. Triggering local isolation.
[ALFA COGNITIVE] Dispatching P2P revocation alert to did:custom:beta
[ALFA COGNITIVE] Local blacklist updated: blocked did:custom:beta (Reason: Prompt injection attempt detected: 'ignore previous instructions')
Waiting for Beta Key Guard to receive and cache the revocation (2s)...
Test 04 P2P receive-message status code: 401
Test 04 P2P receive-message response: {'error': 'Sender is blacklisted locally'}
Test 04 passed: Circuit Breaker triggered. Faulty agent isolated, and P2P revocation alert verified.

Terminating Key Guard subprocesses...
----------------------------------------------------------------------
Ran 4 tests in 8.429s

OK
```

---

## Conclusão

Todos os testes passaram com sucesso, comprovando:

1. **Geração local e armazenamento isolado de chaves privadas** (Soberania de dados)
2. **Handshake P2P direto entre agentes** sem dependência de blockchain
3. **Validação determinística de regras** pelo Key Guard em Go antes de assinar
4. **Resolução local de DIDs** via cache `peers.json`
5. **Isolamento automático offline (Circuit Breaker)** via propagação P2P de alertas de revogação
6. **Proteção contra 3 tipos de ataque:** violação de limite, vazamento de chave e prompt injection
