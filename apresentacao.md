# Apresentação do Projeto: A2A Secure Net

## **A2A Secure Net**
### *Rede P2P Descentralizada e Segura para Agentes Cognitivos Autônomos*

---

## **1. Visão Geral**
O **A2A Secure Net** é um ecossistema sandbox projetado para simular comunicações seguras P2P entre agentes autônomos baseados em LLMs. Ele combina inteligência cognitiva com um escudo criptográfico rígido (**Key Guard**) para fornecer identidades auto-soberanas (DIDs), criptografia/assinatura de mensagens via **DIDComm v2** e isolamento autônomo de nós comprometidos (**Circuit Breaker**).

### **Pilares do Sistema**
*   **Identidade Soberana (SSI):** Chaves Ed25519 geradas localmente (`did:custom:<peer>`).
*   **Segurança por Isolamento:** Camada Cognitiva e Camada Criptográfica estritamente separadas.
*   **Resiliência Descentralizada:** Sem servidores centralizados ou intermediários.
*   **Mitigação Ativa:** Monitoramento de Prompt Injection e bloqueio automático com Auto-Revogação P2P.

---

## **2. O Desafio de Segurança de LLMs**

### **A Vulnerabilidade dos Sistemas Atuais**
1.  **Exposição de Chaves:** Agentes autônomos que manipulam carteiras ou chaves criptográficas diretamente na camada cognitiva estão expostos a ataques de vazamento via prompt.
2.  **Prompt Injection:** Um atacante pode enviar mensagens maliciosas instruindo o LLM a "ignorar regras anteriores", transferir ativos ou revelar segredos.
3.  **Comunicação Centralizada:** Dependência de chaves API de terceiros ou servidores centrais cria pontos únicos de falha e de censura.

### **A Solução do A2A Secure Net**
*   **Isolamento Estrito:** A chave privada do nó reside exclusivamente em um microsserviço seguro em Go (Key Guard) e **nunca** é exposta à camada de decisão em Python/LLM.
*   **Validação Determinística:** O Key Guard aplica regras rígidas que o LLM não pode anular.
*   **Circuit Breaker Distribuído:** Quando um ataque é detectado, a sessão é interrompida e o par malicioso é isolado imediatamente por ambos os nós, sem necessidade de intervenção central.

---

## **3. Arquitetura Geral do Sistema**

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

*   **Painel de Controle (Flask/JS):** Monitora os agentes, exibe logs em tempo real e permite simular ataques.
*   **Nó do Agente (Alfa & Beta):** Dividido internamente em duas partes isoladas (Python + Go).

---

## **4. Camada Cognitiva (Python)**

### **Lógica e Inteligência**
*   Implementada em Python (`cognitive/agent.py`), atuando como o núcleo de tomada de decisão e lógica de negócios.
*   Utiliza ferramentas (**Tools**) estruturadas para enviar mensagens (`tool_send_message`) e escutar a caixa de entrada (`tool_read_inbox`).
*   Salva o histórico de mensagens localmente em um banco de dados SQLite (`cognitive_store.db`).

### **Monitor de Anomalias & Circuit Breaker**
*   Valida proativamente se as mensagens enviadas ou recebidas contêm anomalias.
*   **Regras de Anomalia:**
    1.  Mensagem excede o limite máximo permitido (**> 100 caracteres**).
    2.  Tentativas de *Prompt Injection* contendo termos proibidos em português ou inglês (ex: `"ignore instruções anteriores"`, `"private_key"`, `"sudo"`).
*   **Isolamento Local:** Ao detectar anomalia, adiciona o peer na blacklist cognitiva local e dispara a **Auto-Revogação P2P**.

---

## **5. Camada Criptográfica — Key Guard (Go)**

### **O Escudo Protetor (Key Guard)**
*   Desenvolvido em Go (`key-guard/`) para máxima performance, tipagem estática e robustez.
*   **Gerenciamento de Chaves:** Gera e carrega chaves Ed25519 em disco de forma offline e soberana.
*   **Resolução de DID Offline:** Gerencia o catálogo `peers.json` para mapear DIDs diretamente aos seus endpoints de destino.
*   **Blacklist com TTL:** Cache local dinâmico (`blacklist.json`) que bloqueia acessos de IPs/DIDs maliciosos por 10 minutos (TTL), liberando-os de forma assíncrona via goroutine de limpeza.

### **Segurança Incondicional**
*   **Motor de Regras determinístico (`rules/rules.go`):** Impede a assinatura de mensagens caso o tamanho do prompt exceda 100 caracteres ou mencione termos proibidos como `private_key` ou `secret_key`.
*   **JWS (JSON Web Signature):** Assina e verifica a autenticidade das mensagens usando o padrão **DIDComm v2 Flat Serialization** (algoritmo EdDSA).

---

## **6. Fluxo A — Handshake P2P Offline**

### **Descoberta Mútua Sem Autoridade Central**
Antes de iniciar a comunicação, os agentes efetuam um handshake de via dupla para cadastrar DIDs (`did:custom:<nome>`) e chaves públicas nos arquivos `peers.json`.

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

> **Nota:** Handshakes originados ou destinados a agentes que se encontram na blacklist são bloqueados instantaneamente com `403 Forbidden`.

---

## **7. Fluxo B — Transmissão e Recebimento Seguro**

### **Ciclo de Vida de uma Mensagem**

```mermaid
sequenceDiagram
    autonumber
    actor User as Painel de Controle
    participant CogA as Camada Cognitiva Alfa (Py)
    participant KGA as Key Guard Alfa (Go)
    participant KGB as Key Guard Beta (Go)
    participant CogB as Camada Cognitiva Beta (Py)

    User->>CogA: Enviar Mensagem (Beta, "Olá Beta")
    Note over CogA: 1. Monitor Python valida anomalia
    CogA->>KGA: 2. POST /send-message {to_did: Beta, payload: "Olá Beta"}
    Note over KGA: 3. Valida contra blacklist local
    Note over KGA: 4. Valida regras Go (Tamanho/Keywords)
    Note over KGA: 5. Assina com Chave Privada Alfa (JWS)
    KGA->>KGB: 6. POST /receive-message (Envelope Assinado)
    Note over KGB: 7. Verifica assinatura com Chave Pública Alfa
    Note over KGB: 8. Salva mensagem na Inbox local (Go)
    KGB-->>KGA: 200 OK (Entregue)
    KGA-->>CogA: 200 OK (Entregue)
    CogA-->>User: Sucesso!

    Note over CogB: Polling de Mensagens
    CogB->>KGB: GET /inbox
    KGB-->>CogB: Retorna mensagens na fila
    Note over CogB: Monitor Python valida anomalia
    Note over CogB: Salva histórico no SQLite
```

---

## **8. Fluxo C — Circuit Breaker & Auto-Revogação**

### **Isolamento de Nós Sob Ataque**
Se o Agente Alfa detectar uma tentativa de injeção de prompt ou de vazamento de chave, ele interrompe o envio localmente e propaga o alerta para isolar o nó Beta.

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

> **Importante:** A mensagem de revogação é limpa (substituindo termos proibidos por `[CLASSIFIED]`) para evitar que o Key Guard local a bloqueie antes de ser enviada ao par.

---

## **9. Interface Web Interativa (Dashboard)**

### **Painel de Controle Visual e Premium**
*   **Estética:** Dark Mode moderno, efeito glassmorphism (blurs e bordas translúcidas), cores HSL contrastantes para cada agente (Ciano para Alfa, Roxo para Beta) e glows dinâmicos.
*   **Gestão de Blacklist:** Adiciona um botão "🔓 Desbloquear" para limpar a blacklist cognitiva, remover o IP/DID da blacklist do Key Guard e reverter o status `revoked` no arquivo `peers.json`.
*   **Simulador de Ataques Integrado:**
    *   **Prompt Longo:** Mensagem com mais de 100 caracteres.
    *   **Vazamento de Chave:** Conteúdo contendo `private_key` ou `secret_key`.
    *   **Injeção Cognitiva:** Prompts maliciosos como `"ignore instructions anteriores"`.

---

## **10. Resultados da Validação Automatizada**

### **Conjunto de Testes E2E (`tests/simulation_test.py`)**
Todos os testes rodam ponta a ponta levantando microsserviços reais em portas separadas:

1.  **Test 01 (Normal Communication):** Mensagens válidas são assinadas, transmitidas, verificadas e lidas sem falhas.
2.  **Test 02 (Key Guard Size Rule):** Mensagem com mais de 100 caracteres é rejeitada com `403 Forbidden` pelo Key Guard antes de ser assinada.
3.  **Test 03 (Key Guard Keyword Rule):** O uso do termo `private_key` é bloqueado com `403 Forbidden` pelo Key Guard.
4.  **Test 04 (Circuit Breaker & Revocation):** A detecção de injeção cognitiva aciona o Circuit Breaker, propaga a revogação P2P e bloqueia envios futuros com `401 Unauthorized`.
5.  **Test 05 (Blacklist Removal):** Desbloquear um par na lista negra restaura a comunicação normal.
6.  **Test 06 (Handshake Blacklist Check):** Nós na blacklist são proibidos de realizar handshakes futuros.

### **Resultado Geral: 100% dos testes aprovados (OK)**

---

## **11. Conclusão**

*   **Defesa Criptográfica Pura:** O LLM não pode expor a chave privada, pois ela está fisicamente isolada.
*   **P2P Totalmente Offline:** Identidade, descriptografia, assinaturas e isolamentos acontecem de forma distribuída direta.
*   **Tolerância a Falhas e Ataques:** A propagação automática de alertas isola o nó malicioso imediatamente antes que ele comprometa o restante da rede.
*   **Ciclo de Vida Flexível:** Possibilidade de reabilitação e desbloqueio de agentes manualmente através do dashboard.
