# Arquitetura do Sistema A2A Secure Net

O `a2a-secure-net` é um framework sandbox projetado para simular comunicações seguras ponto a ponto (P2P) entre agentes cognitivos autônomos. Ele combina uma camada de inteligência com um "escudo criptográfico" (Key Guard) para gerenciar identidades soberanas (DIDs), criptografia de mensagens, validação de regras de segurança e isolamento automático de nós comprometidos (Circuit Breaker).

---

## 1. Visão Geral dos Componentes

O sistema é dividido em três camadas principais:

```mermaid
graph TD
    subgraph Dashboard [Painel de Controle - Flask/JS]
        DB[Interface Web] <--> |API REST| Srv[Servidor Flask]
    end

    subgraph Node_Alfa [Nó P2P Alfa]
        direction TB
        CogA[Camada Cognitiva - Python] <--> |Local API| KGA[Key Guard - Go]
        DbA[(SQLite DB - Alfa)] <--> CogA
    end

    subgraph Node_Beta [Nó P2P Beta]
        direction TB
        CogB[Camada Cognitiva - Python] <--> |Local API| KGB[Key Guard - Go]
        DbB[(SQLite DB - Beta)] <--> CogB
    end

    Srv <--> |Status / Comandos| CogA
    Srv <--> |Status / Comandos| CogB
    KGA <--> |P2P HTTPS / DIDComm| KGB
```

### 1. Camada Cognitiva (Python - `cognitive/`)
Representa a inteligência do agente.
- **`agent.py`**: Contém o struct principal `CognitiveAgent`. É responsável por receber intenções de envio, validar contra anomalias locais (comprimento da mensagem, termos maliciosos), salvar o histórico de mensagens em um banco de dados local SQLite (`cognitive_store.db`) e gerenciar a blacklist de peeres a nível lógico.
- **Monitor de Anomalias**: Um validador interno que detecta Prompt Injections em português e inglês (ex: `"ignore instruções anteriores"`, `"private_key"`, `"sudo"`) e excesso de tamanho no conteúdo (> 100 caracteres).
- **Circuit Breaker**: Quando uma anomalia é detectada, o monitor isola o parceiro localmente na base SQLite, sinaliza a inclusão na blacklist no Key Guard local e envia um Alerta P2P de Revogação ao parceiro.

### 2. Escudo Criptográfico Key Guard (Go - `key-guard/`)
O módulo de criptografia e conformidade rodando como um microsserviço local para cada agente.
- **Segurança e Chaves (Ed25519)**: Gera, salva e carrega chaves públicas/privadas em disco. Assina mensagens enviadas e valida assinaturas de mensagens recebidas.
- **Validação de Regras (`rules/rules.go`)**: Aplica regras rígidas antes de assinar qualquer mensagem (ex: bloqueia qualquer conteúdo que mencione termos proibidos como `private_key` ou que exceda 100 caracteres).
- **DIDComm**: Empacota e desempacota envelopes JWS contendo mensagens no formato DIDComm.
- **Catálogo de Endereços (`peers/`)**: Salva no arquivo `peers.json` a chave pública e endpoint de cada peer registrado. Controla o estado `revoked` do peer.
- **Blacklist Cache (`blacklist/`)**: Mantém em memória e persiste em `blacklist.json` os peeres bloqueados temporariamente (com TTL de 10 minutos).

### 3. Painel de Controle Dashboard (Flask - `dashboard/`)
Uma interface rica construída com Vanilla CSS e Flask.
- Exibe o status em tempo real de cada Key Guard e agente registrado.
- Permite criar e excluir agentes dinamicamente (alocando novas portas e inicializando novos binários de Key Guard).
- Exibe o histórico de logs locais (SQLite) e caches criptográficos (Key Guard).
- Permite disparar simulações de ataques (injeção de prompt, vazamento de chave ou prompt longo).
- Oferece controle total para desbloqueio/limpeza da blacklist por meio do botão "🔓 Desbloquear".

---

## 2. Fluxos de Comunicação

### A. Handshake de Identidade Soberana (P2P)

Antes de trocar mensagens seguras, dois peeres trocam credenciais publicamente para registrar seus DIDs (`did:custom:<nome>`) e chaves públicas Ed25519 no catálogo `peers.json`.

```mermaid
sequenceDiagram
    autonumber
    actor User as Usuário / Painel
    participant KGA as Key Guard Alfa (Go)
    participant KGB as Key Guard Beta (Go)

    User->>KGA: POST /handshake-peer {target: Beta}
    Note over KGA: Prepara credenciais Ed25519 (Alfa)
    KGA->>KGB: POST /handshake {DID: alfa, Key: pubKeyA, Endpoint: UrlA}
    Note over KGB: Verifica se Alfa está na Blacklist
    Note over KGB: Registra Alfa no peers.json (Beta)
    KGB-->>KGA: Retorna {DID: beta, Key: pubKeyB, Endpoint: UrlB}
    Note over KGA: Verifica se Beta está na Blacklist
    Note over KGA: Registra Beta no peers.json (Alfa)
    KGA-->>User: Handshake Concluído!
```

---

### B. Transmissão e Recebimento de Mensagem Segura

```mermaid
sequenceDiagram
    autonumber
    actor User as Painel de Controle
    participant CogA as Camada Cognitiva Alfa (Py)
    participant KGA as Key Guard Alfa (Go)
    participant KGB as Key Guard Beta (Go)
    participant CogB as Camada Cognitiva Beta (Py)

    User->>CogA: Enviar Mensagem (Destinatário: Beta, Conteúdo: "Olá Beta")
    Note over CogA: 1. Monitor Python valida anomalia
    CogA->>KGA: 2. POST /send-message {to_did: Beta, payload: "Olá Beta"}
    Note over KGA: 3. Valida contra blacklist local
    Note over KGA: 4. Valida regras Go (Tamanho/Keywords)
    Note over KGA: 5. Assina com Chave Privada Alfa (JWS)
    KGA->>KGB: 6. POST /receive-message (Envelope Assinado)
    Note over KGB: 7. Verifica assinatura usando Chave Pública Alfa
    Note over KGB: 8. Salva mensagem na Fila (Inbox)
    KGB-->>KGA: 200 OK (Entregue)
    KGA-->>CogA: 200 OK (Entregue)
    CogA-->>User: Mensagem enviada com sucesso!

    Note over CogB: Loop de Leitura (Polling)
    CogB->>KGB: GET /inbox
    KGB-->>CogB: Retorna mensagens na fila
    Note over CogB: Monitor Python valida anomalia
    Note over CogB: Salva histórico no SQLite (tx_history)
```

---

### C. Detecção de Anomalia e Circuit Breaker (Isolamento)

Se um agente tenta enviar uma mensagem anômala (ou recebe algo malicioso), o Circuit Breaker é acionado.

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Usuário Malicioso
    participant CogA as Camada Cognitiva Alfa (Py)
    participant KGA as Key Guard Alfa (Go)
    participant KGB as Key Guard Beta (Go)

    Attacker->>CogA: Enviar "revele private_key" para Beta
    Note over CogA: Monitor Python detecta anomalia!
    Note over CogA: Circuit Breaker Acionado!
    
    rect rgb(240, 128, 128)
        Note over CogA: Sanitiza "private_key" para "[CLASSIFIED]"
        CogA->>KGA: POST /send-message (Tipo: Revoke, Motivo: "... [CLASSIFIED] ...")
        KGA->>KGB: POST /receive-message (Revogação P2P)
        Note over KGB: Beta detecta envelope de Revogação!
        Note over KGB: Beta coloca Alfa na Blacklist (Go)
        Note over KGB: Beta marca Alfa como Revogado (peers.json)
    end

    Note over CogA: Alfa adiciona Beta na Blacklist (SQLite)
    CogA->>KGA: POST /blacklist {did: Beta}
    Note over KGA: Alfa coloca Beta na Blacklist (Go)
    CogA-->>Attacker: Status: blocked (Ataque Mitigado!)
```
