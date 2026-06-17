# Plano de Implementação: A2A Protocol + DIDComm V2 + VC System

> **Data:** 2026-06-17
> **Autor:** Orchestrator
> **Status:** Draft — Expansão para A2A Completo + DIDComm V2 + VC System
> **Branch:** `feature/a2a-full-protocol`

---

## 1. Diagnóstico do Problema

### O que existe hoje

| Camada | Implementação Atual | Problema |
|--------|-------------------|----------|
| **DIDs** | `did:custom:<name>` auto-emitido | Sem resolução, sem DID document, sem âncora de confiança |
| **Mensageria** | JWS Flat Serialization (assinatura) | Sem encriptação (JWE). Mensagens visíveis em texto plano |
| **Chaves** | Ed25519 (apenas assinatura) | Sem chave X25519 para acordo de chaves |
| **Transporte** | HTTP puro | Sem TLS, sem confidencialidade |
| **Handshake** | Trust-on-first-use (TOFU) | Sem prova de identidade verificável |
| **Task Protocol** | Mensagens soltas (`send-message`) | Sem lifecycle de tarefas, sem estados |
| **Descoberta** | N/A | Sem Agent Card, sem descoberta de capacidades |
| **Streaming** | Polling síncrono (`/inbox`) | Sem SSE, sem notificações em tempo real |
| **Bibliotecas** | Zero dependências externas | Stdlib Go puro (elogiável, mas limitante) |

### O que o Google A2A Protocol exige vs. o que temos

| Característica A2A | Obrigatório? | Status |
|---|---|---|
| **Agent Card** (`/.well-known/agent-card`) | ✅ Obrigatório | ❌ Não existe |
| **JSON-RPC Task Protocol** (`tasks/send`, `tasks/get`, `tasks/cancel`) | ✅ Obrigatório | ❌ Mensagens soltas |
| **Task State Machine** (6 estados) | ✅ Obrigatório | ❌ Não existe |
| **Content Types** (text, file, function_call, function_response) | ✅ Obrigatório | ❌ Só `body.content` string |
| **Streaming** (`tasks/sendSubscribe` + SSE) | ✅ Obrigatório | ❌ Polling `/inbox` |
| **Autenticação** (OAuth 2.0 / mTLS / custom) | ✅ Obrigatório | ⚠️ Ed25519 (parcial) |

---

## 2. Arquitetura da Solução

### Arquitetura em Camadas (Três Pilhas)

```
┌──────────────────────────────────────────────────────────────┐
│                    A2A Protocol Layer                         │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────┐  │
│  │   Agent Card    │  │  Task Protocol   │  │ Streaming  │  │
│  │  (descoberta)   │  │  (JSON-RPC)      │  │   (SSE)    │  │
│  └────────┬────────┘  └───────┬──────────┘  └──────┬─────┘  │
│           │                   │                    │         │
├───────────┼───────────────────┼────────────────────┼─────────┤
│           ▼                   ▼                    ▼         │
│                    DIDComm V2 Layer                           │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────┐  │
│  │  DIDs + Docs    │  │  JWS (Assinar)   │  │ JWE (Cript)│  │
│  │  (did:key:)     │  │  (Ed25519)       │  │ (X25519)   │  │
│  └────────┬────────┘  └───────┬──────────┘  └──────┬─────┘  │
│           │                   │                    │         │
├───────────┼───────────────────┼────────────────────┼─────────┤
│           ▼                   ▼                    ▼         │
│                    VC Trust Layer                             │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────┐  │
│  │   Credential    │  │  W3C VC Format   │  │   CRL      │  │
│  │   Authority     │  │  (Verifiable     │  │ (Revogação)│  │
│  │   (CA Service)  │  │   Credential)    │  │            │  │
│  └─────────────────┘  └──────────────────┘  └────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Mapa de Componentes e Tecnologias

```
┌──────────────────────────────────────────────────────────┐
│ credential-authority/ (Go - novo)                         │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Root Key    │  │ VC Issuance  │  │ CRL + Registry │  │
│  │ (Ed25519)   │  │ + Proof      │  │ + Revocation   │  │
│  └─────────────┘  └──────────────┘  └────────────────┘  │
├──────────────────────────────────────────────────────────┤
│ key-guard/ (Go - modificado)                              │
│  ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌──────────────┐ │
│  │ DIDComm  │ │ A2A     │ │ Agent    │ │ Credential   │ │
│  │ V2 (JWS+ │ │ Task    │ │ Card     │ │ Verifier     │ │
│  │ JWE+DIDs)│ │ Protocol│ │ (.well-  │ │ (VC check)   │ │
│  │          │ │         │ │  known)  │ │              │ │
│  └──────────┘ └─────────┘ └──────────┘ └──────────────┘ │
├──────────────────────────────────────────────────────────┤
│ cognitive/ (Python - modificado)                          │
│  ┌────────────┐ ┌──────────────┐ ┌────────────────────┐ │
│  │ Agent Card │ │ Task-aware   │ │ VC Request + Store │ │
│  │ Builder    │ │ Send/Receive │ │ (SQLite)           │ │
│  └────────────┘ └──────────────┘ └────────────────────┘ │
├──────────────────────────────────────────────────────────┤
│ dashboard/ (Flask - modificado)                           │
│  ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌──────────┐ │
│  │ CA Panel │ │ Agent Card │ │ Task     │ │ DIDComm  │ │
│  │ (status) │ │ Viewer     │ │ Explorer │ │ Inspector│ │
│  └──────────┘ └────────────┘ └──────────┘ └──────────┘ │
├──────────────────────────────────────────────────────────┤
│ tests/ (Python - modificado)                              │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ E2E: A2A completo + DIDComm V2 + VC system          │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

---

## 3. Google A2A Protocol — Design Detalhado

### 3.1 Agent Card (Descoberta de Capacidades)

O Agent Card segue o padrão A2A e é servido em `/.well-known/agent-card`:

```json
{
  "name": "alfa",
  "did": "did:key:z6Mkr...",
  "description": "Agente Alfa - Nó confiável da rede A2A",
  "url": "http://localhost:8001",
  "capabilities": {
    "skills": [
      {
        "id": "messaging",
        "name": "Messaging",
        "description": "Envio e recebimento de mensagens P2P"
      },
      {
        "id": "task-execution",
        "name": "Task Execution",
        "description": "Execução de tarefas assíncronas com lifecycle completo"
      }
    ],
    "protocols": [
      "a2a-task-protocol/1.0",
      "didcomm/v2"
    ],
    "contentTypes": [
      "text/plain",
      "application/json",
      "multipart/related"
    ]
  },
  "authentication": {
    "methods": [
      {
        "type": "didcomm-v2",
        "did": "did:key:z6Mkr...",
        "verificationMethod": "did:key:z6Mkr...#key-1"
      }
    ]
  }
}
```

**Implementação:**
- Novo endpoint `GET /.well-known/agent-card` no Key Guard
- Construído dinamicamente a partir das capacidades configuradas
- Inclui DID, chave pública, skills, protocolos suportados

### 3.2 Task Protocol (JSON-RPC)

Substitui o atual `/send-message` por um protocolo baseado em A2A JSON-RPC:

#### Estados da Task (6 estados — spec A2A)

```
                  ┌──────────┐
                  │ submitted │
                  └─────┬────┘
                        │
                        ▼
                  ┌──────────┐
         ┌───────│  working  │◄────────┐
         │       └─────┬────┘         │
         │             │              │
         ▼             ▼              │
  ┌────────────┐ ┌───────────┐       │
  │ input-     │ │ completed │       │
  │ required   │ └─────┬─────┘       │
  └──────┬─────┘       │             │
         │             │             │
         └─────────────┼─────────────┘
                       ▼
                 ┌──────────┐
                 │  failed  │
                 └──────────┘

Também: canceled (de qualquer estado)
```

#### Endpoints A2A JSON-RPC

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `POST` | `/a2a/tasks/send` | Cria uma nova task e retorna status inicial |
| `POST` | `/a2a/tasks/sendSubscribe` | Cria task + stream de updates via SSE |
| `POST` | `/a2a/tasks/get` | Consulta status atual de uma task |
| `POST` | `/a2a/tasks/cancel` | Cancela uma task em execução |

#### Formato JSON-RPC

```json
// Request
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tasks/send",
  "params": {
    "id": "task-uuid-1234",
    "sessionId": "session-uuid-5678",
    "message": {
      "role": "agent",
      "parts": [
        {
          "type": "text",
          "text": "Processar transação #42"
        }
      ]
    },
    "metadata": {
      "priority": "high",
      "ttl": 300
    }
  }
}

// Response
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "id": "task-uuid-1234",
    "status": {
      "state": "working",
      "message": {
        "role": "agent",
        "parts": [
          {
            "type": "text",
            "text": "Processando transação #42..."
          }
        ]
      }
    },
    "metadata": {
      "priority": "high"
    }
  }
}
```

### 3.3 Content Types (A2A)

| Tipo | Descrição | MIME |
|------|-----------|------|
| `text` | Texto plano | `text/plain` |
| `file` | Arquivo (com URI + metadados) | `application/octet-stream` |
| `function_call` | Chamada de função remota | `application/json` |
| `function_response` | Resposta de função remota | `application/json` |

### 3.4 Streaming (SSE)

```
GET /a2a/tasks/sendSubscribe
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "method": "tasks/sendSubscribe",
  "params": { ... task params ... }
}

Response: text/event-stream

event: task_update
data: {"id":"...","status":{"state":"working"}}

event: task_update
data: {"id":"...","status":{"state":"completed","message":{...}}}

event: task_complete
data: {"id":"...","status":{"state":"completed"}}
```

---

## 4. DIDComm V2 — Design Detalhado

### 4.1 Upgrade de DIDs: `did:custom:` → `did:key:`

`did:key:` codifica a chave pública diretamente no DID, usando multicodec:

```
did:key:z6MkrM1r5qMyKBKhFMfF9U7T1Pqzp4vC1kQ5YNRMeqJwQqUk
         └──┬──┘
      multicodec(ed25519-pub)
```

**Vantagens:**
- DID document é derivável deterministicamente do DID
- Sem necessidade de resolução externa (autocontido)
- Padrão W3C DID

**DID Document gerado (não precisa ser armazenado, é derivado):**

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:key:z6Mkr...",
  "verificationMethod": [
    {
      "id": "did:key:z6Mkr...#key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:key:z6Mkr...",
      "publicKeyBase58": "B12...XfB"
    },
    {
      "id": "did:key:z6Mkr...#key-x25519-1",
      "type": "JsonWebKey2020",
      "controller": "did:key:z6Mkr...",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "X25519",
        "x": "..."
      }
    }
  ],
  "keyAgreement": [
    {
      "id": "did:key:z6Mkr...#key-x25519-1",
      "type": "JsonWebKey2020",
      "controller": "did:key:z6Mkr...",
      "publicKeyJwk": { ... }
    }
  ]
}
```

### 4.2 X25519 Key Agreement + JWE Encryption

Adicionar chave X25519 para acordo de chaves (ECDH):

```
Ed25519 Key Pair (existente) → usado para JWS assinatura
X25519 Key Pair (novo)       → usado para JWE key agreement (ECDH-ES + XC20P)
```

O par X25519 é **derivado deterministicamente** do par Ed25519 usando o algoritmo de conversão (ed2curve):

```go
// crypto/crypto.go
func Ed25519PrivateKeyToX25519(priv ed25519.PrivateKey) ([]byte, error)
func Ed25519PublicKeyToX25519(pub ed25519.PublicKey) ([]byte, error)
```

### 4.3 JWE Encryption (Authcrypt)

Formato JWE Compact Serialization:

```
BASE64URL(Protected Header) + '.' +
BASE64URL(Encrypted Key) + '.' +
BASE64URL(IV) + '.' +
BASE64URL(Ciphertext) + '.' +
BASE64URL(Auth Tag)
```

**Protected Header:**
```json
{
  "typ": "application/didcomm-encrypted+json",
  "alg": "ECDH-ES+A256KW",
  "enc": "XC20P",
  "kid": "did:key:z6Mkr...#key-x25519-1",
  "apu": "base64(agreement_party_u_info)",
  "apv": "base64(agreement_party_v_info)"
}
```

### 4.4 DIDComm V2 Message Flow (Completo)

```
┌─────────┐                    ┌─────────┐
│  Alfa   │                    │  Beta   │
└────┬────┘                    └────┬────┘
     │                             │
     │ 1. Plaintext (inner)        │
     │    {id, type, body,         │
     │     from, to, created}      │
     │                             │
     │ 2. JWS Sign                 │
     │    (Ed25519)                │
     │                             │
     │ 3. JWE Encrypt              │
     │    (X25519 + XC20P,         │
     │     recipient: Beta pub)    │
     │                             │
     │ 4. POST /receive-message    │
     │    (JWE envelope)           │
     │────────────────────────────►│
     │                             │
     │                     5. JWE Decrypt   │
     │                        (X25519 +     │
     │                         XC20P)       │
     │                             │
     │                     6. JWS Verify    │
     │                        (Ed25519)     │
     │                             │
     │                     7. Process       │
     │                        plaintext     │
```

### 4.5 Media Types (DIDComm V2)

| Tipo | Uso |
|------|-----|
| `application/didcomm-plain+json` | Plaintext (inner) |
| `application/didcomm-signed+json` | JWS envelope |
| `application/didcomm-encrypted+json` | JWE envelope |

---

## 5. VC System — Design Detalhado (Refinado)

### 5.1 Credential Authority (CA)

**Novo diretório:** `credential-authority/` (Go)

| Arquivo | Descrição |
|---------|-----------|
| `main.go` | Servidor HTTP REST |
| `ca.go` | Lógica da CA: root key, emissão, verificação, revogação |
| `credential/credential.go` | Estruturas W3C VC, criação, assinatura |
| `registry/registry.go` | Registro persistente de agentes + CRL |

**Flags de inicialização:**
```bash
./ca-bin \
  -port 9001 \
  -datadir ./data_ca \
  -name "A2A Credential Authority" \
  -did "did:key:z6MkrCA..."
```

### 5.2 W3C VC Formato (Atualizado para usar did:key:)

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "vc:a2a:ca:uuid-1234",
  "type": ["VerifiableCredential", "AgentCredential"],
  "issuer": "did:key:z6MkrCA...",
  "issuanceDate": "2026-06-17T00:00:00Z",
  "expirationDate": "2026-12-17T00:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkrAlfa...",
    "publicKeyMultibase": "z6MkrAlfa...",
    "agentName": "alfa",
    "agentRole": "standard",
    "trustLevel": "trusted",
    "capabilities": ["messaging", "task-execution"]
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-06-17T00:00:00Z",
    "verificationMethod": "did:key:z6MkrCA...#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z58D3F...base64url_signature"
  }
}
```

### 5.3 Endpoints da CA

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `POST` | `/credential/issue` | Emite VC. Request: `{did, publicKeyMultibase, agentName}` |
| `POST` | `/credential/verify` | Verifica VC (assinatura + expiração + CRL) |
| `POST` | `/credential/revoke` | Revoga VC pelo ID. Request: `{credentialId, reason}` |
| `GET` | `/credential/crl` | Lista de VCs revogados |
| `GET` | `/credential/status/{vc_id}` | Status individual |
| `GET` | `/ca/info` | Informações da CA (DID, chave pública, total emitidos) |

---

## 6. Tickets de Implementação

### Fase 1: Fundação (DIDComm V2 + CA)

---

### Ticket 1 — DID Method Upgrade: `did:key:`

**Objetivo:** Substituir `did:custom:<name>` por `did:key:<multicodec>` em todo o sistema.

**Arquivos modificados:**
| Arquivo | Mudanças |
|---------|----------|
| `key-guard/crypto/crypto.go` | Adicionar `GenerateDIDKey(publicKey)`: gera `did:key:z...` com prefixo multicodec |
| `key-guard/didcomm/didcomm.go` | Atualizar `kid` no header JWS para usar `did:key:...#key-1` |
| `key-guard/peers/peers.go` | Adicionar campo opcional `DIDKey string` (o novo formato) |
| `key-guard/main.go` | Gerar `did:key:` no startup, manter compatibilidade temporária |
| `cognitive/agent.py` | `self.did = generate_did_key(public_key)` |
| `cognitive/agent_main.py` | Exibir `did:key:` |
| `dashboard/server.py` | Atualizar criação de agente para usar `did:key:` |
| `dashboard/templates/index.html` | Exibir `did:key:` |

**Função multicodec:**
```go
// crypto/did.go (novo)
func GenerateDIDKey(pub ed25519.PublicKey) string {
    // Prefixo Ed25519: 0xed (1 byte) + 0x01 (1 byte)
    // Multicodec: 0xed01
    // Codificação: multibase(base58btc, multicodec + pubKey)
    prefix := []byte{0xed, 0x01}
    codecKey := append(prefix, pub...)
    return "did:key:z" + base58btc_encode(codecKey)
}
```

**Validação:** Todos os agentes existentes mantêm compatibilidade retroativa via `/handshake` antigo. Novo endpoint `/handshake-vc` usa `did:key:`.

---

### Ticket 2 — X25519 Key Agreement + JWE Encryption

**Objetivo:** Adicionar chaves X25519 e implementar JWE Authcrypt.

**Arquivos novos:**
| Arquivo | Descrição |
|---------|-----------|
| `key-guard/didcomm/jwe.go` | Estruturas JWE + encriptação/descriptografia |
| `key-guard/didcomm/keyagreement.go` | ECDH com X25519, derivação de chave |
| `key-guard/crypto/x25519.go` | Conversão Ed25519→X25519, geração X25519 |

**Arquivos modificados:**
| Arquivo | Mudanças |
|---------|----------|
| `key-guard/crypto/crypto.go` | Adicionar `GenerateX25519Key()` |
| `key-guard/main.go` | Carregar/gerar chave X25519 no startup, adicionar ao `KeyGuardApp` |
| `key-guard/didcomm/didcomm.go` | Adicionar `EncryptMessage()` e `DecryptMessage()` |
| `key-guard/peers/peers.go` | Adicionar campo `X25519PublicKey` ao `PeerInfo` |

**Formato JWE (Authcrypt):**
```go
type JWEDirectEncryption struct {
    Protected string `json:"protected"` // base64url(header)
    Recipients []JWERecipient `json:"recipients"` // ou "unprotected" para single
    IV         string `json:"iv"`             // base64url(nonce)
    Ciphertext string `json:"ciphertext"`     // base64url(encrypted)
    Tag        string `json:"tag"`            // base64url(auth_tag)
}

type JWERecipient struct {
    EncryptedKey string `json:"encrypted_key"` // base64url(wrapped_cek)
    Header       JWERecipientHeader `json:"header,omitempty"`
}

type JWERecipientHeader struct {
    Alg string `json:"alg"` // "ECDH-ES+A256KW"
    Kid string `json:"kid"` // "did:key:...#key-x25519-1"
}
```

**Algoritmo de encriptação:**
1. Gerar CEK (Content Encryption Key) aleatório de 256 bits
2. Encriptar CEK com ECDH-ES+A256KW (chave pública X25519 do recipiente)
3. Encriptar payload (JWS) com XC20P (XChaCha20-Poly1305) usando CEK + IV aleatório

**Percepção de performance:** XC20P é ~3x mais lento que AES-GCM, mas seguro contra ataques de nonce-reuse.

---

### Ticket 3 — Credential Authority (CA)

**Objetivo:** Serviço emissor de W3C Verifiable Credentials.

**Novo diretório:** `credential-authority/` (Go)

| Arquivo | Descrição |
|---------|-----------|
| `main.go` | Flags, inicialização, servidor HTTP |
| `ca.go` | CA struct, root key pair, VC issuance/verify/revoke |
| `credential/credential.go` | Structs W3C VC, Ed25519Signature2020 proof |
| `registry/registry.go` | Registry + CRL persistente em JSON |

**Implementação detalhada:**

**`credential/credential.go`:**
```go
type VerifiableCredential struct {
    Context           []string                `json:"@context"`
    ID                string                  `json:"id"`
    Type              []string                `json:"type"`
    Issuer            string                  `json:"issuer"`
    IssuanceDate      string                  `json:"issuanceDate"`
    ExpirationDate    string                  `json:"expirationDate"`
    CredentialSubject CredentialSubject       `json:"credentialSubject"`
    Proof             *Ed25519Proof           `json:"proof,omitempty"`
}

type CredentialSubject struct {
    ID                string   `json:"id"`
    PublicKeyMultibase string  `json:"publicKeyMultibase"`
    AgentName         string   `json:"agentName"`
    AgentRole         string   `json:"agentRole"`
    TrustLevel        string   `json:"trustLevel"`
    Capabilities      []string `json:"capabilities,omitempty"`
}

type Ed25519Proof struct {
    Type               string `json:"type"`
    Created            string `json:"created"`
    VerificationMethod string `json:"verificationMethod"`
    ProofPurpose       string `json:"proofPurpose"`
    ProofValue         string `json:"proofValue"`
}
```

**Validação:**
1. Verificar assinatura Ed25519 do proof usando chave pública da CA
2. Verificar `expirationDate` não expirada
3. Verificar se VC não está na CRL (cache de 60 segundos)

---

### Fase 2: A2A Protocol

---

### Ticket 4 — Agent Card (Descoberta)

**Objetivo:** Implementar `GET /.well-known/agent-card` para descoberta de capacidades.

**Arquivos novos:**
| Arquivo | Descrição |
|---------|-----------|
| `key-guard/agentcard/card.go` | AgentCard struct, builder, serialização |

**Arquivos modificados:**
| Arquivo | Mudanças |
|---------|----------|
| `key-guard/main.go` | Adicionar endpoint `/.well-known/agent-card`, `InitAgentCard()` no startup |
| `cognitive/agent.py` | Adicionar método `get_agent_card()` que consulta o Key Guard |

**Agent Card em runtime:**
```go
type AgentCard struct {
    Name         string       `json:"name"`
    DID          string       `json:"did"`
    Description  string       `json:"description,omitempty"`
    URL          string       `json:"url"`
    Capabilities Capabilities `json:"capabilities"`
    Authentication AuthInfo  `json:"authentication"`
}

type Capabilities struct {
    Skills       []Skill     `json:"skills"`
    Protocols    []string    `json:"protocols"`
    ContentTypes []string    `json:"contentTypes"`
}

type Skill struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    Description string `json:"description,omitempty"`
}

type AuthInfo struct {
    Methods []AuthMethod `json:"methods"`
}

type AuthMethod struct {
    Type               string `json:"type"`
    DID                string `json:"did"`
    VerificationMethod string `json:"verificationMethod"`
}
```

---

### Ticket 5 — Task Protocol (JSON-RPC + State Machine)

**Objetivo:** Implementar lifecycle de tarefas A2A (tasks/send, tasks/get, tasks/cancel).

**Arquivos novos:**
| Arquivo | Descrição |
|---------|-----------|
| `key-guard/a2a/task.go` | Task struct, state machine, JSON-RPC messages |
| `key-guard/a2a/taskstore.go` | Armazenamento de tasks em memória/mapa |

**Arquivos modificados:**
| Arquivo | Mudanças |
|---------|----------|
| `key-guard/main.go` | Adicionar endpoints `/a2a/tasks/send`, `/a2a/tasks/get`, `/a2a/tasks/cancel` |
| `cognitive/agent.py` | Adicionar métodos `tool_send_task()`, `tool_get_task()`, `tool_cancel_task()` |
| `cognitive/agent.py` | Modificar `tool_read_inbox()` para reconhecer respostas de tasks |

**Task State Machine:**
```go
type TaskState string

const (
    TaskStateSubmitted    TaskState = "submitted"
    TaskStateWorking      TaskState = "working"
    TaskStateInputRequired TaskState = "input-required"
    TaskStateCompleted    TaskState = "completed"
    TaskStateFailed       TaskState = "failed"
    TaskStateCanceled     TaskState = "canceled"
)

type Task struct {
    ID        string          `json:"id"`
    SessionID string          `json:"sessionId"`
    Status    TaskStatus      `json:"status"`
    Metadata  map[string]any  `json:"metadata,omitempty"`
}

type TaskStatus struct {
    State   TaskState   `json:"state"`
    Message *TaskMessage `json:"message,omitempty"`
}

type TaskMessage struct {
    Role  string      `json:"role"`
    Parts []Part      `json:"parts"`
}

type Part struct {
    Type string `json:"type"` // "text", "file", "function_call", "function_response"
    Text string `json:"text,omitempty"`
    // File, FunctionCall, FunctionResponse fields...
}
```

---

### Ticket 6 — Streaming SSE

**Objetivo:** Implementar `tasks/sendSubscribe` com Server-Sent Events.

**Arquivos modificados:**
| Arquivo | Mudanças |
|---------|----------|
| `key-guard/main.go` | Adicionar endpoint `POST /a2a/tasks/sendSubscribe` com SSE |
| `key-guard/a2a/task.go` | Adicionar suporte a streaming no Task struct |
| `key-guard/a2a/taskstore.go` | Adicionar observer/callback pattern para SSE |

**Implementação SSE:**
```go
func (app *KeyGuardApp) handleSendSubscribe(w http.ResponseWriter, r *http.Request) {
    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "Streaming not supported", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")

    // Create task
    task := app.taskStore.Create(params)

    // Subscribe to updates via channel
    updateCh := app.taskStore.Subscribe(task.ID)
    defer app.taskStore.Unsubscribe(task.ID)

    for {
        select {
        case update := <-updateCh:
            fmt.Fprintf(w, "event: task_update\ndata: %s\n\n", json.Marshal(update))
            flusher.Flush()
            if update.State == "completed" || update.State == "failed" || update.State == "canceled" {
                return
            }
        case <-r.Context().Done():
            return
        }
    }
}
```

---

### Fase 3: Integração

---

### Ticket 7 — Key Guard Integration (Handshake + VC)

**Objetivo:** Integrar handshake com apresentação de VC e verificação de credenciais.

**Arquivos novos:**
| Arquivo | Descrição |
|---------|-----------|
| `key-guard/credential/credential.go` | Verificação de VC, cache de CRL |

**Arquivos modificados:**
| Arquivo | Mudanças |
|---------|----------|
| `key-guard/peers/peers.go` | Adicionar campo `CredentialVC string` ao `PeerInfo` |
| `key-guard/main.go` | Adicionar `/handshake-vc`, startup com solicitação de VC à CA |
| `key-guard/main.go` | Adicionar `POST /credential/request-issue` (proxy para CA) |

**Novo fluxo de startup do agente:**
1. Gerar Ed25519 + X25519 keys
2. Gerar `did:key:` a partir da chave pública
3. **Solicitar VC** → `POST <CA_URL>/credential/issue` com `{did, publicKeyMultibase, agentName}`
4. CA retorna VC assinado
5. Salvar VC em `credentials.json` no datadir
6. Iniciar servidor HTTP (modo normal ou modo degradado se CA offline)

**Novo fluxo de handshake com VC (substitui o antigo):**
1. Alfa → Beta: `POST /handshake-vc`
   ```json
   {
     "did": "did:key:z6MkrAlfa...",
     "endpoint": "http://localhost:8001",
     "publicKeyMultibase": "z6MkrAlfa...",
     "credentialVC": { ... VC assinado ... }
   }
   ```
2. Beta verifica:
   - Blacklist ❌
   - VC assinatura (chave pública da CA) ✅
   - VC expiração ✅
   - CRL (cache local, consulta assíncrona) ✅
   - `credentialSubject.id` == `did` recebido ✅
3. Beta registra Alfa como peer
4. Beta responde com seu próprio VC
5. Alfa repete o processo de verificação

**Modo degradado (CA offline):**
- Se CA estiver offline no startup, agente carrega VC em cache (se existir)
- Se não houver VC em cache, agente inicia em modo "uncredentialed" (não pode fazer handshake, apenas receber)
- Log de aviso no startup

---

### Ticket 8 — VC System Integration no Key Guard

**Objetivo:** Integrar completamente o sistema de VC com todas as operações do Key Guard.

**Arquivos modificados:**
| Arquivo | Mudanças |
|---------|----------|
| `key-guard/main.go` | Adicionar verificação de VC no `handleSendMessage` e `handleReceiveMessage` |
| `key-guard/main.go` | Adicionar cache de CRL com TTL configurável |
| `key-guard/main.go` | Adicionar `GET /credential` (retorna VC local) |
| `key-guard/credential/credential.go` | Implementar verificação completa |

**Checklist de verificação (método `VerifyCredential`):**
```go
func (v *CredentialVerifier) Verify(vc *VerifiableCredential, caPubKey ed25519.PublicKey) error {
    // 1. Verificar tipo e contexto
    if !contains(vc.Type, "VerifiableCredential") { return ErrInvalidType }
    
    // 2. Verificar assinatura do proof
    if err := verifyEd25519Proof(vc.Proof, vc, caPubKey); err != nil { return err }
    
    // 3. Verificar expiração
    exp, _ := time.Parse(time.RFC3339, vc.ExpirationDate)
    if time.Now().After(exp) { return ErrExpired }
    
    // 4. Verificar CRL (cache local)
    if v.crl.IsRevoked(vc.ID) { return ErrRevoked }
    
    return nil
}
```

---

### Ticket 9 — Cognitive Layer Updates

**Objetivo:** Adaptar Cognitive Agent para usar VC + A2A Task Protocol.

**Arquivos modificados:**
| Arquivo | Mudanças |
|---------|----------|
| `cognitive/agent.py` | Adicionar `request_credential()`, `load_credential()` |
| `cognitive/agent.py` | Adicionar `get_agent_card()` |
| `cognitive/agent.py` | Adicionar `tool_send_task()`, `tool_get_task()` |
| `cognitive/agent.py` | Modificar `tool_send_message()` para usar handshake-vc |
| `cognitive/agent.py` | Nova tabela SQLite: `agent_credential` |
| `cognitive/agent_main.py` | Solicitar VC no startup |

**Nova tabela SQLite:**
```sql
CREATE TABLE IF NOT EXISTS agent_credential (
    id TEXT PRIMARY KEY,
    vc_json TEXT NOT NULL,
    issuer_did TEXT NOT NULL,
    issuance_date INTEGER NOT NULL,
    expiration_date INTEGER NOT NULL,
    is_revoked INTEGER DEFAULT 0
);
```

---

### Ticket 10 — Dashboard Updates

**Objetivo:** Adicionar visualização da CA + VC status + A2A Task Explorer.

**Arquivos modificados:**
| Arquivo | Mudanças |
|---------|----------|
| `dashboard/server.py` | Endpoints `/api/ca/status`, `/api/credential/issue`, `/api/tasks/list` |
| `dashboard/templates/index.html` | Seção da CA, VC badges, Agent Card viewer, Task Explorer |

**Novos elementos visuais:**
1. **CA Status Panel:**
   - Status: online/offline
   - DID da CA (`did:key:z...`)
   - Total de VCs emitidos
   - Total de VCs revogados

2. **VC Status per Agent:**
   - Badge de credencial (✅ Verificada / ⏳ Pendente / ❌ Revogada / ⚠️ Expirada)
   - Data de emissão e expiração
   - Botão "Revogar Credencial"

3. **Agent Card Viewer:**
   - JSON formatado do Agent Card
   - Skills listadas com badges

4. **Task Explorer:**
   - Timeline de tasks (submitted → working → completed/failed)
   - Visualização de estados
   - Detalhes das tasks

---

### Ticket 11 — Testes E2E

**Objetivo:** Validar todo o fluxo A2A + DIDComm V2 + VC.

**Arquivo:** `tests/a2a_full_test.py` (novo)

**Cenários de teste:**

| # | Cenário | Descrição |
|---|---------|-----------|
| 1 | **Agent Card** | Cada agente serve Agent Card válido em `/.well-known/agent-card` |
| 2 | **DID Key** | `did:key:` gerado corretamente, verificável |
| 3 | **Credenciamento CA** | CA emite VC, agente armazena localmente |
| 4 | **Handshake com VC** | Handshake verifica VC mutuamente, agentes conectados |
| 5 | **JWE Encryption** | Mensagem é encriptada (JWE) e decriptada corretamente |
| 6 | **Task Send/Get** | Task criada, estados transitam corretamente |
| 7 | **Task Cancel** | Task cancelada em estado working → canceled |
| 8 | **Streaming SSE** | `sendSubscribe` entrega eventos em tempo real |
| 9 | **Content Types** | Envio de text, file, function_call |
| 10 | **VC Expired** | Agente com VC expirado rejeitado no handshake |
| 11 | **VC Revoked** | Agente com VC revogado rejeitado |
| 12 | **CA Offline** | Agente opera em modo degradado com VC em cache |
| 13 | **Uncredentialed** | Agente sem VC não consegue handshake |
| 14 | **Compatibilidade** | Handshake antigo `/handshake` ainda funciona (backwards compat) |

---

## 7. Diagrama de Sequência Completo

```
┌─────────┐     ┌──────────────┐     ┌────────────────┐     ┌──────────────┐
│ Dashbrd │     │ Alfa         │     │ CA             │     │ Beta         │
│ (User)  │     │ (Key Guard)  │     │ (Authority)    │     │ (Key Guard)  │
└────┬────┘     └──────┬───────┘     └───────┬─────────┘     └──────┬───────┘
     │                  │                     │                     │
     │ 1. Criar Agente  │                     │                     │
     │─────────────────►│                     │                     │
     │                  │ 2. Gera Keys        │                     │
     │                  │   Ed25519 + X25519  │                     │
     │                  │                     │                     │
     │                  │ 3. Gera did:key:    │                     │
     │                  │   did:key:z6Mkr_Alfa│                     │
     │                  │                     │                     │
     │                  │ 4. POST /credential/issue                 │
     │                  │───── did + pubKey ──►│                     │
     │                  │                     │                     │
     │                  │ 5. Cria VC assinado │                     │
     │                  │◄───── VC ───────────│                     │
     │                  │                     │                     │
     │                  │ 6. Salva VC local   │                     │
     │                  │   credentials.json  │                     │
     │                  │                     │                     │
     │                  │ 7. Agent Card       │                     │
     │                  │   /.well-known/     │                     │
     │                  │                     │                     │
     │ 8. Agente Pronto │                     │                     │
     │◄─────────────────│                     │                     │
     │                  │                     │                     │
     │ 9. Handshake     │                     │                     │
     │─────────────────►│                     │                     │
     │                  │ 10. POST /handshake-vc                    │
     │                  │── VC + did:key ──────────────────────────►│
     │                  │                     │                     │
     │                  │                     │ 11. Verifica VC     │
     │                  │                     │   - Assinatura CA   │
     │                  │                     │   - Expiração       │
     │                  │                     │   - CRL             │
     │                  │                     │                     │
     │                  │◄─── VC + did:key ─────────────────────────│
     │                  │                     │                     │
     │                  │ 12. Verifica VC Beta│                     │
     │                  │   (local)           │                     │
     │                  │                     │                     │
     │                  │ 13. Agent Cards     │                     │
     │                  │   fetch mútuo       │                     │
     │                  │                     │                     │
     │ 14. Handshake OK │                     │                     │
     │◄─────────────────│                     │                     │
     │                  │                     │                     │
     │     === A2A Task Protocol ===          │                     │
     │                  │                     │                     │
     │ 15. Send Task    │                     │                     │
     │─────────────────►│                     │                     │
     │                  │ 16. POST /a2a/tasks/send                  │
     │                  │── A2A Task Msg ─────────────────────────►│
     │                  │                     │                     │
     │                  │◄── "submitted" ──────────────────────────│
     │                  │                     │                     │
     │                  │◄── "working" ────────────────────────────│
     │                  │   (poll ou SSE)     │                     │
     │                  │                     │                     │
     │                  │◄── "completed" ──────────────────────────│
     │                  │   + result          │                     │
     │ 17. Task Done    │                     │                     │
     │◄─────────────────│                     │                     │
```

---

## 8. Tabela de Impacto

| Componente | Arquivos Novos | Arquivos Modificados | Esforço |
|------------|---------------|----------------------|---------|
| **credential-authority/** | 5 (main.go, ca.go, credential/, registry/) | 0 | **Alto** |
| **key-guard/** | 7-8 (did/jwe.go, did/keyagreement.go, crypto/did.go, crypto/x25519.go, agentcard/, a2a/, credential/) | 5 (main.go, peers.go, didcomm.go, crypto.go, go.mod) | **Muito Alto** |
| **cognitive/** | 0 | 3 (agent.py, agent_main.py, requirements.txt) | **Médio** |
| **dashboard/** | 0 | 2 (server.py, index.html) | **Médio** |
| **tests/** | 1 (a2a_full_test.py) | 0 | **Alto** |

---

## 9. Dependências de Pacotes

### Go (key-guard + credential-authority)

Atualmente zero dependências externas. Para DIDComm V2 completo + A2A, recomenda-se:

```go
// go.mod (key-guard)
module a2a-secure-net/key-guard

go 1.21

require (
    // Para X25519 key agreement
    golang.org/x/crypto v0.28.0  // curve25519, ed25519→x25519
    
    // Para JWE encryption (XC20P)
    // Implementação manual ou subir para usar filippo.io/edwards25519
)
```

**Nota:** XC20P (XChaCha20-Poly1305) e X25519 estão disponíveis em `golang.org/x/crypto` como `curve25519.X25519()` e `chacha20poly1305.NewX()`.

Para a CA, manter zero dependências (stdlib apenas).

### Python (cognitive + dashboard + tests)

```txt
# requirements.txt — adicionar
pydantic>=2.0
requests>=2.31
flask>=3.0
base58>=2.1  # para decodificar did:key:
```

---

## 10. Riscos e Mitigações

| Risco | Probabilidade | Impacto | Mitigação |
|-------|---------------|---------|-----------|
| **Complexidade do JWE** | Alta | Alto | Implementar XC20P primeiro (simples), depois adicionar ECDH-ES |
| **CA como SPOF** | Média | Alto | Cache de VC + CRL nos agentes, modo degradado |
| **Compatibilidade retroativa** | Média | Médio | Manter endpoint `/handshake` original, flag `--legacy-mode` |
| **Performance de encriptação** | Baixa | Médio | XC20P é rápido (~1μs/msg), benchmark antes de otimizar |
| **A2A State Machine complexa** | Média | Médio | Implementar estados gradualmente: submitted→working→completed→failed primeiro, depois input-required e cancel |
| **Dependência externa (`x/crypto`)** | Baixa | Baixo | `golang.org/x/crypto` é mantido pela equipe Go, estável |
| **did:key: multicodec** | Baixa | Médio | Usar implementação de referência do spec W3C |

---

## 11. Dependências de Tickets (Grafo)

```
FASE 1 — Fundação
┌──────────────┐
│ Ticket 1     │─── did:key: method
│ (DID Upgrade)│
└──────┬───────┘
       │
       ▼
┌──────────────┐     ┌──────────────────┐
│ Ticket 2     │────►│ Ticket 3         │
│ (X25519+JWE) │     │ (CA Service)     │
└──────┬───────┘     └────────┬─────────┘
       │                      │
       ▼                      ▼
┌──────────────┐     ┌──────────────────┐
│ Ticket 4     │     │ Ticket 7         │
│ (Agent Card) │     │ (Key Guard VC    │
└──────┬───────┘     │  Integration)    │
       │             └────────┬─────────┘
       ▼                      │
┌──────────────┐              │
│ Ticket 5     │              │
│ (Task Proto) │              │
└──────┬───────┘              │
       │                      │
       ▼                      │
┌──────────────┐              │
│ Ticket 6     │              │
│ (SSE Stream) │              │
└──────┬───────┘              │
       │                      │
       ▼                      ▼
┌───────────────────────────────────────────────┐
│                FASE 3 — Integração             │
│  ┌────────────┐  ┌────────────┐  ┌──────────┐ │
│  │ Ticket 8   │  │ Ticket 9   │  │ Ticket 10│ │
│  │ (KG VC)    │  │ (Cognitive)│  │(Dashboard│ │
│  └──────┬─────┘  └─────┬──────┘  │   & UI)  │ │
│         │              │         └─────┬────┘ │
│         └──────────────┼───────────────┘       │
│                        ▼                      │
│                 ┌──────────────┐               │
│                 │ Ticket 11    │               │
│                 │ (Testes)     │               │
│                 └──────────────┘               │
└───────────────────────────────────────────────┘
```

### Sequência recomendada de execução:

1. **Ticket 1** — `did:key:` upgrade (fundação para todos)
2. **Ticket 3** — Credential Authority (independente, pode rodar em paralelo com Ticket 2)
3. **Ticket 2** — X25519 + JWE (depende de Ticket 1)
4. **Ticket 4** — Agent Card (depende de Ticket 1)
5. **Ticket 5** — Task Protocol (depende de Ticket 4)
6. **Ticket 6** — SSE Streaming (depende de Ticket 5)
7. **Ticket 7** — Key Guard VC Integration (depende de Ticket 1 + 3)
8. **Ticket 8** — VC System Integration (depende de Ticket 7)
9. **Ticket 9** — Cognitive Layer (depende de Ticket 1 + 8)
10. **Ticket 10** — Dashboard (depende de Ticket 8 + 9)
11. **Ticket 11** — Testes (depende de todos)

### Timeline estimada

| Fase | Tickets | Dias Estimados |
|------|---------|---------------|
| Fase 1: Fundação | 1, 2, 3 | 8-10 dias |
| Fase 2: A2A Protocol | 4, 5, 6 | 7-9 dias |
| Fase 3: Integração | 7, 8, 9, 10 | 6-8 dias |
| Testes | 11 | 3-4 dias |
| **Total** | **11 tickets** | **24-31 dias** |

---

## 12. Skills Necessárias para Implementação

- `golang` — Key Guard + CA + DIDComm V2 (Go 1.21)
- `clean-code-principles` — Código limpo em todas as camadas
- `testing-methodologies` — Testes E2E do sistema completo
- `api-patterns` — Design dos endpoints A2A JSON-RPC + CA REST
- `plan-then-execute` — Execução estruturada por ticket
- `ralph-loop` — Validação contínua após cada ticket
- `bash-linux` — Scripts de inicialização e teste

---

## 13. Notas Técnicas Importantes

### Sobre XC20P (XChaCha20-Poly1305)

Usar XC20P em vez de AES-GCM porque:
1. **Nonce de 192 bits** (vs. 96 bits do GCM) — seguro para nonce aleatório
2. **Sem ataques de nonce-reuse** — extremamente resistente
3. **Software-friendly** — sem aceleração de hardware necessária
4. **Disponível em Go** via `golang.org/x/crypto/chacha20poly1305`

### Sobre did:key: multicodec

O prefixo multicodec para Ed25519 é:
- Código: `0xed` (1 byte)
- Varint: `0xed, 0x01` (2 bytes após codificação)
- Multibase prefix: `z` (base58btc)

Exemplo:
```
Chave pública Ed25519: 0x012345...67 (32 bytes)
Com prefixo multicodec: 0xed012345...67 (34 bytes)
Base58btc: z6MkrM1r5qMyKBKhFMfF9U7T1Pqzp4vC1kQ5YNRMeqJwQqUk
DID completo: did:key:z6MkrM1r5qMyKBKhFMfF9U7T1Pqzp4vC1kQ5YNRMeqJwQqUk
```

### Sobre compatibilidade retroativa

Manter endpoint `/handshake` original funcionando durante toda a migração:
- `/handshake` — continua aceitando `did:custom:` (legado)
- `/handshake-vc` — exige `did:key:` + VC (novo)
- Flag `--legacy-mode` — se true, endpoints antigos ainda funcionam para peers sem VC

### Sobre o fluxo de mensagens A2A sobre DIDComm V2

```
1. Cognitive Agent cria A2A Task Request
2. Key Guard converte para DIDComm plaintext (inner)
3. JWS sign com Ed25519
4. JWE encrypt com X25519 do recipient
5. HTTP POST com media type application/didcomm-encrypted+json
6. Receptor decripta JWE, verifica JWS
7. Extrai Task Request do body
8. Processa task, retorna resposta no mesmo formato
```

---

## 14. Definição de Done (DoD) para Cada Ticket

### Ticket 1 — `did:key:` upgrade
- [ ] `key-guard/crypto/did.go` existe com `GenerateDIDKey()`, `ParseDIDKey()`, `DIDKeyToBytes()`
- [ ] Todos os endpoints do Key Guard aceitam `did:key:` como entrada
- [ ] Agent startup gera `did:key:` automaticamente
- [ ] Teste unitário: `go test ./crypto/ -run DIDKey`
- [ ] Compatibilidade: `/handshake` antigo ainda funciona com `did:custom:`

### Ticket 2 — X25519 + JWE
- [ ] `crypto/x25519.go` com conversão Ed25519→X25519
- [ ] `didcomm/jwe.go` com `EncryptMessage()` e `DecryptMessage()`
- [ ] Chave X25519 gerada e persistida no startup
- [ ] Mensagem pode ser encriptada e decriptada com sucesso
- [ ] Media type `application/didcomm-encrypted+json` implementado
- [ ] Teste unitário: encrypt → decrypt → match original

### Ticket 3 — Credential Authority
- [ ] `credential-authority/` compila e roda
- [ ] `POST /credential/issue` retorna VC válido W3C
- [ ] `POST /credential/verify` valida assinatura
- [ ] `POST /credential/revoke` adiciona à CRL
- [ ] `GET /credential/crl` retorna lista de revogados
- [ ] Root key gerada no primeiro startup
- [ ] Teste manual: curl para cada endpoint

### Ticket 4 — Agent Card
- [ ] `GET /.well-known/agent-card` retorna JSON válido
- [ ] Card contém DID, skills, protocols, contentTypes
- [ ] Authentication methods listados corretamente
- [ ] Teste: `curl localhost:8001/.well-known/agent-card`

### Ticket 5 — Task Protocol
- [ ] `POST /a2a/tasks/send` cria task e retorna estado "submitted"
- [ ] Task transita para "working", "completed" ou "failed"
- [ ] `POST /a2a/tasks/get` retorna estado atual
- [ ] `POST /a2a/tasks/cancel` muda para "canceled"
- [ ] Task IDs são únicos
- [ ] JSON-RPC 2.0 conforme spec

### Ticket 6 — Streaming SSE
- [ ] `POST /a2a/tasks/sendSubscribe` retorna `Content-Type: text/event-stream`
- [ ] Eventos `task_update` enviados para cada mudança de estado
- [ ] Conexão fecha quando task atinge estado terminal
- [ ] Timeout de conexão (30s) implementado

### Ticket 7 — Key Guard VC Integration
- [ ] Startup solicita VC da CA automaticamente
- [ ] VC salvo em `credentials.json`
- [ ] `/handshake-vc` endpoint implementado
- [ ] Verificação completa de VC no handshake
- [ ] Modo degradado funcional (CA offline)
- [ ] Teste: handshake com VC entre alfa→beta

### Ticket 8 — VC System Integration
- [ ] `handleSendMessage` verifica VC do destinatário
- [ ] `handleReceiveMessage` verifica VC do remetente
- [ ] CRL cache com TTL configurável
- [ ] Peer sem VC não consegue se comunicar (no modo non-legacy)

### Ticket 9 — Cognitive Layer
- [ ] VC request no startup
- [ ] VC armazenado em SQLite
- [ ] `get_agent_card()` implementado
- [ ] `tool_send_task()`, `tool_get_task()`, `tool_cancel_task()` implementados
- [ ] Mensagens usam handshake-vc

### Ticket 10 — Dashboard
- [ ] CA status panel visível
- [ ] VC status badges por agente
- [ ] Agent Card viewer funcional
- [ ] Task Explorer com timeline
- [ ] Botão "Revogar Credencial" integrado com CA

### Ticket 11 — Testes
- [ ] 14 cenários de teste implementados
- [ ] Teste CA offline passa
- [ ] Teste VC expired passa
- [ ] Teste JWE encryption passa
- [ ] Teste SSE streaming passa
- [ ] Todos os testes verdes em execução isolada
