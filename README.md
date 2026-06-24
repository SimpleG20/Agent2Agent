# Agent-to-Agent (A2A) Secure P2P Network Prototype

Este repositório contém o protótipo de uma rede de comunicação Agent-to-Agent (A2A)
descentralizada **Peer-to-Peer**, focada em segurança máxima, soberania absoluta de dados
e mitigação a ataques de engenharia social (Prompt Injection).

O sistema adota o padrão **Identidade Auto-Soberana (SSI)** local utilizando chaves
Ed25519 (`did:key:<multicodec>`) e empacotamento seguro **DIDComm v2 (JWS Flat Serialization)**,
dispensando orquestradores ou blockchains públicas. A resolução de DIDs é feita de forma
**offline via handshake P2P direto** entre os agentes.

---

## Arquitetura de Camadas Isoladas

Para garantir o controle de chaves e proteção contra injeções, a arquitetura de cada nó
de agente soberano é dividida estritamente em duas camadas independentes:

```
                  +-----------------------------------------+
                  |        CAMADA COGNITIVA (Python)        |
                  |   - LLM Engine (LangGraph / Pydantic)   |
                  |   - Monitor de Anomalias (SQLite)       |
                  +--------------------+--------------------+
                                       |
                               HTTP REST (Interno)
                                       |
                  +--------------------v--------------------+
                  |       CAMADA CRIPTOGRÁFICA (Go)         |
                  |   - Key Guard (Ed25519 Sovereign Keys)  |
                  |   - Motor de Regras Determinísticas     |
                  |   - DIDComm v2 Encoder / Decoder        |
                  |   - Tabela de Peers (peers.json)        |
                  |   - Blacklist com TTL (blacklist.json)  |
                  +--------------------+--------------------+
                                       |
                               HTTP P2P (Externo)
                                       |
                                       v
                              (Outros Agentes)
```

1. **Camada Cognitiva (Python):** Executa a lógica de negócios e tomada de decisão.
   Não possui acesso físico às chaves privadas do agente. Comunica-se com a camada
   criptográfica local via APIs HTTP REST internas e gerencia um banco de dados SQLite
   (`cognitive_store.db`) para monitorar injeções de prompt no payload e manter
   blacklist cognitiva local.

2. **Camada Criptográfica (Key Guard em Go):** Um microserviço robusto exclusivo do
   agente que gerencia localmente as chaves Ed25519, mantém um cache de peers
   descobertos via handshake P2P (`peers.json`), valida as regras de negócio de forma
   determinística antes de assinar e realiza o envelopamento de mensagens no padrão
   **DIDComm v2** (JWS Flat Serialization).

---

## Mecanismos de Defesa & Circuit Breaker

- **Isolamento de Chaves:** A chave privada Ed25519 fica isolada no Key Guard (Go) e
  nunca é exposta à camada cognitiva baseada em LLM.

- **Handshake P2P Direto:** Os agentes se descobrem mutuamente através de um handshake
  HTTP direto, trocando DIDs, chaves públicas e endpoints. Não há necessidade de
  blockchain ou registro central.

- **Resolução Local de DIDs:** O Key Guard mantém um arquivo `peers.json` com os peers
  conhecidos. A resolução de DIDs é feita localmente, sem consulta externa.

- **Validação de Regras (Key Guard):** Antes de assinar qualquer payload, o Key Guard em
  Go verifica se a transação obedece a regras de negócio rígidas (ex: limite máximo de
  envio de `100.0` unidades) e sanitiza palavras-chave proibidas
  (`private_key`, `secret_key`, `sudo`).

- **Detecção Cognitiva de Injeções (Python):** O monitor da camada cognitiva intercepta
  injeções conhecidas como *"ignore previous instructions"* ou *"override rules"*.

- **Circuit Breaker Distribuído (Auto-Revogação P2P):** Se uma anomalia for detectada,
  o monitor:
  1. Registra o peer afetado em sua lista negra local (SQLite).
  2. Solicita ao Key Guard o disparo de uma mensagem de auto-revogação assinada
     (`https://didcomm.org/revocation/1.0/revoke`) diretamente ao par afetado.
  3. O Key Guard do destinatário intercepta o alerta, valida a assinatura e insere o
     remetente em sua blacklist local (`blacklist.json`), derrubando a sessão e
     rejeitando quaisquer mensagens futuras com `401 Unauthorized` de forma 100%
     autônoma e offline.

---

## Estrutura do Projeto

```
a2a-secure-net/
  cognitive/                    # Lógica do agente inteligente em Python
    agent.py                    #   CognitiveAgent + tools LangGraph + monitor de injeções
    agent_main.py               #   Listener e console interativo para o agente

  key-guard/                    # Camada criptográfica em Go
    main.go                     #   Servidor HTTP REST e roteamento de endpoints
    crypto/crypto.go            #   Geração e manipulação de chaves Ed25519
    peers/peers.go              #   Cache JSON local para resolução offline de DIDs
    didcomm/didcomm.go          #   Envelope de assinatura JWS DIDComm v2
    rules/rules.go              #   Validador de esquemas e limites determinísticos
    blacklist/blacklist.go      #   Blacklist local temporária de peers com expiração TTL

  dashboard/                    # Painel de monitoramento visual interativo
    server.py                   #   Servidor Flask (porta 9000)
    templates/index.html        #   Frontend com dark mode e glassmorphism

  tests/
    simulation_test.py          # Testes automatizados E2E com cenários de ataque

  docker-compose.yml            # Redis para filas de mensagens (uso opcional)
```

---

## Como Executar e Testar

### Pré-requisitos
- Python 3 instalado
- Compilador Go instalado

### 1. Configurar o Ambiente Python
```bash
python3 -m venv venv
source venv/bin/activate
pip install flask pydantic requests
```

### 2. Compilar o Key Guard em Go
```bash
cd key-guard
go build -o key-guard-bin .
cd ..
```

### 3. Rodar Testes de Integração Automatizados (E2E)
```bash
./venv/bin/python3 tests/simulation_test.py
```

Os testes simulam:
1. **Comunicação P2P normal** — Alfa envia mensagem segura para Beta
2. **Violação de regra de negócio** — Key Guard bloqueia amount > 100.0
3. **Violação de regra de segurança** — Key Guard bloqueia palavras-chave proibidas
4. **Circuit Breaker** — Detecção de prompt injection + auto-revogação P2P

---

## Painel Interativo Web (Dashboard)

Você pode interagir e simular cenários visualmente usando o painel em Flask:

1. Inicie o servidor do painel:
   ```bash
   ./venv/bin/python3 dashboard/server.py
   ```
2. Abra no navegador: **`http://localhost:9000`**
3. Clique em **"Direct Handshake"** nos nós para conectar o Agente Alfa e o Agente Beta.
4. Experimente enviar mensagens seguras normais ou utilize a seção
   **"Attack Simulation Panel"** para disparar prompt injections ou valores abusivos
   e acompanhar em tempo real o Key Guard e a camada de Auto-Revogação isolando os nós!
