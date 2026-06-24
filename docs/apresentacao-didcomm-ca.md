# 🎤 Guia de Apresentação: DIDComm V2 + Autoridade de Credenciais

## Implementação Concreta no A2A Secure P2P Network

> **Apresentação técnica sobre a implementação do DIDComm V2 (JWS + JWE) e da Autoridade de Credenciais (W3C VCs) em uma rede P2P de agentes.**

---

### Como agentes de IA se comunicam de forma segura sem depender de um servidor central?

**Contexto:**

- Agentes autônomos (LLMs) precisam se comunicar em rede P2P
- Riscos: **prompt injection**, **vazamento de chaves privadas**, **identidade falsa**, **censura centralizada**
- Solução: **SSI (Self-Sovereign Identity)** + **DIDComm V2** + **W3C Verifiable Credentials**

**Diferenciais do projeto:**

- ❌ Sem blockchain — resolução de DIDs é **offline via handshake direto**
- ❌ Sem orquestrador central — rede **totalmente descentralizada**
- ✅ Duas camadas isoladas: **Cognitive (Python/LLM)** ≠ **Crypto (Go)**
- ✅ Chave privada **nunca** exposta ao LLM (mitigação estrutural contra prompt injection)
- ✅ Circuit Breaker distribuído — auto-revogação P2P

---

### Cada nó de agente possui isolamento rígido entre cognição e criptografia

```
+----------------------------------------------------------+
|              CAMADA COGNITIVA (Python/Flask)               |
|  - LLM Engine / LangGraph                                 |
|  - Monitor de Anomalias (SQLite) — detecta prompt injection|
|  - Circuit Breaker — dispara auto-revogação P2P           |
|  - Dashboard Web (porta 9000)                             |
+---------------------------+------------------------------+
                            | HTTP REST (localhost — interno)
+---------------------------v------------------------------+
|         CAMADA CRIPTOGRÁFICA — KEY GUARD (Go)             |
|  - Geração e gestão de chaves Ed25519                     |
|  - DIDComm V2: JWS (assinatura) + JWE (criptografia)      |
|  - Motor de Regras Determinísticas (rules.go)             |
|  - Peer Store (peers.json) — resolução local de DIDs      |
|  - Blacklist Cache (blacklist.json) — TTL de 10 min       |
|  - Credential Cache (CRL) — verificação offline de VCs    |
+---------------------------+------------------------------+
                            | HTTP P2P (externo)
                            v
                    (Outros Agentes na rede)
```

### Por que duas camadas?

| Camada        | Linguagem | Responsabilidade       | Acesso à chave privada? |
| ------------- | --------- | ---------------------- | ----------------------- |
| Cognitiva     | Python    | Decisão, monitoria, UI | ❌ Nunca                |
| Criptográfica | Go        | Crypto, regras, P2P    | ✅ Apenas aqui          |

**Isolamento físico:** A chave privada Ed25519 reside **apenas** no processo Go. A camada Python envia intenções por HTTP, mas **não consegue extrair a chave**. Mesmo que o LLM seja comprometido por prompt injection, a chave privada está segura.

---

> Cada agente possui um **DID (Decentralized Identifier)** gerado localmente a partir do seu par de chaves Ed25519

### Formato: `did:key:<multibase><multicodec><public_key>`

```go
// key-guard/crypto/did.go

// Gera did:key:z<base58btc(multicodec_prefix + pub_key)>
func GenerateDIDKey(pub ed25519.PublicKey) string {
    // Multicodec prefix para Ed25519: varint(0xed) = [0xed, 0x01]
    prefix := []byte{0xed, 0x01}
    codecKey := append(prefix, pub...)
    return "did:key:z" + base58btcEncode(codecKey)
}
```

### Anatomia do DID:

```
did:key:z6MktafZc3fRJHfJxQFuHevpvKMK67FNMVMDJDyA6LqdEYha
├──────┘ ├┘ ├──────────────────────────────────────────────┘
 método  │  base58btc(multicodec(0xed01) + pubkey(32 bytes))
       multibase
       prefix 'z'
```

| Componente       | Tamanho   | Descrição                        |
| ---------------- | --------- | -------------------------------- |
| `did:key:`       | 8 chars   | Método DID autocontido           |
| `z`              | 1 char    | Prefixo multibase (base58btc)    |
| `0xed01`         | 2 bytes   | Multicodec identificando Ed25519 |
| Chave pública    | 32 bytes  | Chave Ed25519                    |
| Total codificado | ~44 chars | String final do DID              |

### Por que Ed25519?

| Característica           | Ed25519          | RSA-2048  |
| ------------------------ | ---------------- | --------- |
| Tamanho da chave pública | 32 bytes         | 256 bytes |
| Tamanho da chave privada | 64 bytes         | 512 bytes |
| Assinatura               | 64 bytes         | 256 bytes |
| Velocidade de sign       | ~50μs            | ~200μs    |
| Velocidade de verify     | ~25μs            | ~10μs     |
| Suporte Go stdlib        | ✅ Desde Go 1.13 | ✅        |

### Função de Parse (resolução offline):

```go
// Reconstrói a chave pública a partir do did:key:
func ParseDIDKey(didKey string) ([]byte, error) {
    // Remove prefixo "did:key:" e multibase "z"
    // Decodifica base58btc
    // Verifica multicodec 0xed01
    // Retorna os 32 bytes da chave pública
    return decoded[2:], nil
}
```

**Resolução é local** — o `peers.json` mapeia `did:key` → chave pública + endpoint. Sem blockchain, sem lookup externo.

---

> Toda mensagem enviada entre agentes é **assinada digitalmente** pelo remetente usando Ed25519

### Estrutura da Mensagem DIDComm:

```go
// key-guard/didcomm/didcomm.go

type DIDCommMessage struct {
    ID          string                 `json:"id"`          // UUID único
    Type        string                 `json:"type"`        // "https://didcomm.org/basicmessage/2.0/message"
    Body        map[string]interface{} `json:"body"`        // Conteúdo da mensagem
    From        string                 `json:"from,omitempty"` // DID do remetente
    To          []string               `json:"to,omitempty"`   // DIDs dos destinatários
    CreatedTime int64                  `json:"created_time,omitempty"`
    ExpiresTime int64                  `json:"expires_time,omitempty"`
}
```

### Tipos de Mensagem Suportados:

```
https://didcomm.org/basicmessage/2.0/message   → Mensagem normal
https://didcomm.org/revocation/1.0/revoke       → Alerta de revogação P2P
```

### Algoritmo de Assinatura (SignMessage):

```go
func SignMessage(msg *DIDCommMessage, privKey ed25519.PrivateKey) (*SignedMessage, error) {
    // 1. Serializa mensagem para JSON
    msgBytes, _ := json.Marshal(msg)

    // 2. Codifica payload em base64url (sem padding)
    payloadEncoded := base64.RawURLEncoding.EncodeToString(msgBytes)

    // 3. Cria header protegido com algoritmo e key identifier
    header := map[string]string{
        "alg": "EdDSA",                     // Algoritmo Ed25519
        "kid": msg.From + "#key-1",         // DID do remetente + fragmento
    }

    // 4. Assina: Ed25519(protected_b64 + "." + payload_b64)
    sigInput := protectedEncoded + "." + payloadEncoded
    sigBytes := ed25519.Sign(privKey, []byte(sigInput))
}
```

### Algoritmo de Verificação (VerifyMessage):

```go
func VerifyMessage(signed *SignedMessage, pubKey ed25519.PublicKey) (*DIDCommMessage, error) {
    // 1. Reconstroi signing input: protected + "." + payload
    sigInput := sigObj.Protected + "." + signed.Payload

    // 2. Decodifica assinatura base64url
    sigBytes, _ := base64.RawURLEncoding.DecodeString(sigObj.Signature)

    // 3. Verifica com Ed25519
    if !ed25519.Verify(pubKey, []byte(sigInput), sigBytes) {
        return nil, errors.New("invalid signature")
    }

    // 4. Decodifica payload e retorna mensagem original
    payloadBytes, _ := base64.RawURLEncoding.DecodeString(signed.Payload)
    var msg DIDCommMessage
    json.Unmarshal(payloadBytes, &msg)
    return &msg, nil
}
```

### Envelope JWS — Flat Serialization:

```json
{
  "payload": "eyJpZCI6IjEyMyIsInR5cGUiOiJodHRwczovL2RpZGNvbW0ub3JnL2Jhc2ljbWVzc2FnZS8yLjAvbWVzc2FnZSIsImJvZHkiOnsidGV4dCI6Ik9s4bogQmV0YSJ9LCJmcm9tIjoiZGlkOmtleTp6Nk1rdGFmWi4uLiIsInRvIjpbImRpZDprZXk6ejZNa3RhZlouLi4iXSwiY3JlYXRlZF90aW1lIjoxNzE5MDAwMDAwfQ",
  "signatures": [
    {
      "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa3RhZlouLi4ja2V5LTEifQ",
      "signature": "VGVzdGVkX3NpZ25hdHVyZV9kYXRhX2Zvcl9wcmVzZW50YXRpb25fcHVycG9zZXNfMDAwMA"
    }
  ]
}
```

### Conteúdo decodificado do header:

```json
{
  "alg": "EdDSA",
  "kid": "did:key:z6MktafZc3fRJHfJxQFuHevpvKMK67FNMVMDJDyA6LqdEYha#key-1"
}
```

### Fluxo:

```
Remetente                               Destinatário
   |                                         |
   | 1. Cria DIDCommMessage                  |
   | 2. JSON → base64url (payload)           |
   | 3. Cria header protegido                |
   | 4. Ed25519(protected.payload) → sig     |
   | 5. Monta JWS Flat Serialization         |
   |---------------------------------------->|
   |                                         | 6. Parseia JWS
   |                                         | 7. Resolve DID → chave pública (peers.json)
   |                                         | 8. Ed25519.Verify(protected.payload, sig)
   |                                         | 9. Decodifica payload → DIDCommMessage
```

---

> O JWS assinado é **criptografado** para o destinatário específico, garantindo que **apenas** ele possa ler

### Algoritmo: ECDH-ES + XC20P (XChaCha20-Poly1305)

```
ECDH-ES:  Elliptic Curve Diffie-Hellman Ephemeral Static
XC20P:    XChaCha20-Poly1305 (AEAD com nonce de 24 bytes)
```

### O Desafio: Uma Chave Só, Dois Propósitos

Cada agente tem **um único par de chaves Ed25519**. Precisamos dela para:

| Operação           | Algoritmo     | Chave                     |
| ------------------ | ------------- | ------------------------- |
| Assinar (JWS)      | Ed25519       | Ed25519 privada           |
| Criptografar (JWE) | X25519 + ECDH | X25519 privada (derivada) |

### Solução: Ed25519 → X25519 (ed2curve)

```go
// key-guard/crypto/x25519.go

// Converte deterministicamente Ed25519 → X25519
func Ed25519PrivateKeyToX25519(priv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
    // 1. Extrai seed (primeiros 32 bytes dos 64)
    seed := priv.Seed()

    // 2. SHA-512(seed) → pega primeiros 32 bytes
    h := sha512.Sum512(seed)
    xPriv := h[:32]

    // 3. Clamp (RFC 7748 §5) — limpeza dos bits
    xPriv[0] &= 248    // zera 3 bits inferiores
    xPriv[31] &= 127   // zera bit superior
    xPriv[31] |= 64    // seta bit 6

    return ecdh.X25519().NewPrivateKey(xPriv)
}
```

**Propriedade importante:** A conversão é **determinística** — a mesma Ed25519 sempre produz a mesma X25519. Ambos os lados podem derivar sem comunicação extra.

### Algoritmo de Criptografia (EncryptMessage):

```go
func EncryptMessage(plaintext []byte, recipientPubKey *ecdh.PublicKey, kid string) ([]byte, error) {
    // 1. Gera chave efêmera X25519 (NOVA a cada mensagem!)
    curve := ecdh.X25519()
    ephPriv, _ := curve.GenerateKey(rand.Reader)

    // 2. ECDH: ephemeral_priv + recipient_pub = shared_secret
    sharedSecret, _ := ephPriv.ECDH(recipientPubKey)

    // 3. Deriva CEK: SHA-256(shared_secret)
    cek := sha256.Sum256(sharedSecret)

    // 4. Cria nonce aleatório de 24 bytes (seguro para XChaCha20)
    nonce := make([]byte, chacha20poly1305.NonceSizeX)  // 24 bytes
    rand.Read(nonce)

    // 5. Criptografa com XC20P (AAD = protected header)
    aead, _ := chacha20poly1305.NewX(cek[:])
    ciphertextWithTag := aead.Seal(nil, nonce, plaintext, []byte(protectedEncoded))

    // 6. Separa ciphertext (ct) do authentication tag (16 bytes)
    ct := ciphertextWithTag[:len(ciphertextWithTag)-16]
    tag := ciphertextWithTag[len(ciphertextWithTag)-16:]
}
```

### Algoritmo de Descriptografia (DecryptMessage):

```go
func DecryptMessage(jweData []byte, ownPrivKey *ecdh.PrivateKey) ([]byte, error) {
    // 1. Parseia JWE JSON
    var jwe JWEDirectEncryption
    json.Unmarshal(jweData, &jwe)

    // 2. Extrai chave efêmera pública (epk) do header protegido
    //    epk está em base64url dentro do protected header
    epkBytes, _ := base64.RawURLEncoding.DecodeString(epkX)
    ephPubKey, _ := ecdh.X25519().NewPublicKey(epkBytes)

    // 3. ECDH: own_priv + ephemeral_pub = shared_secret (mesmo segredo!)
    sharedSecret, _ := ownPrivKey.ECDH(ephPubKey)

    // 4. Deriva CEK: SHA-256(shared_secret)
    cek := sha256.Sum256(sharedSecret)

    // 5. Descriptografa com XC20P
    aead, _ := chacha20poly1305.NewX(cek[:])
    plaintext, _ := aead.Open(nil, nonce, fullCt, []byte(jwe.Protected))

    return plaintext, nil
}
```

### Envelope JWE — ECDH-ES + XC20P:

```json
{
  "protected": "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiWEMyMFAiLCJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkFBQUFCIn0sImtpZCI6ImRpZDprZXk6ejZNa3RhZlouLi4ja2V5LTEifQ",
  "recipients": [
    {
      "encrypted_key": "",
      "header": {
        "alg": "ECDH-ES",
        "kid": "did:key:z6MktafZ...#key-1"
      }
    }
  ],
  "iv": "ODFhNzI5YjM0YzVkNmI3MTIzNDU2",
  "ciphertext": "N2M0OGI5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz",
  "tag": "YWJjZGVmMDEyMzQ1Njc4"
}
```

### Header protegido decodificado:

```json
{
  "alg": "ECDH-ES",
  "enc": "XC20P",
  "epk": {
    "kty": "OKP",
    "crv": "X25519",
    "x": "AABB..." // chave pública efêmera
  },
  "kid": "did:key:z6MktafZ...#key-1"
}
```

### Por que XC20P (XChaCha20-Poly1305)?

| Característica            | AES-GCM                        | XChaCha20-Poly1305                     |
| ------------------------- | ------------------------------ | -------------------------------------- |
| Tamanho do nonce          | 12 bytes                       | **24 bytes**                           |
| Risco de colisão de nonce | Alto (após 2³² msgs)           | **Desprezível**                        |
| Aceleração por hardware   | AES-NI                         | SIMD                                   |
| Performance em software   | Lenta                          | **Rápida**                             |
| Disponível em Go          | `crypto/aes` + `crypto/cipher` | `golang.org/x/crypto/chacha20poly1305` |

### Fluxo Completo (Sign-then-Encrypt):

```
                   ┌─────────────────────┐
                   │  "Olá Beta" texto   │
                   └─────────┬───────────┘
                             │
                   ┌─────────▼───────────┐
                   │  DIDCommMessage      │
                   │  (JSON estruturado)  │
                   └─────────┬───────────┘
                             │
                   ┌─────────▼───────────┐
                   │  JWS (Ed25519 sign)  │ ← Autenticidade + Não-repúdio
                   └─────────┬───────────┘
                             │
                   ┌─────────▼───────────┐
                   │  JWE (X25519 ECDH   │ ← Confidencialidade
                   │   + XC20P encrypt)  │
                   └─────────┬───────────┘
                             │
                   ┌─────────▼───────────┐
                   │  Envio P2P via HTTP │
                   └─────────────────────┘
```

---

### Handshake de Identidade Soberana

Antes de trocar mensagens, dois agentes precisam se conhecer. O handshake é o **momento de descoberta e troca de credenciais**.

```
Agente A (Alfa)                       Agente B (Beta)
   |                                       |
   |── POST /handshake-vc ────────────────>|
   |   {                                    |
   |     "did": "did:key:z6MktafZ...",     |
   |     "publicKey": "base64...",          |
   |     "x25519PublicKey": "base64...",    |
   |     "endpoint": "http://localhost:8001",
   |     "vc": { ... W3C VC assinado ... }  |
   |   }                                    |
   |                                       | 1. Verifica blacklist
   |                                       | 2. Verifica VC (assinatura + validade + CRL)
   |                                       | 3. Registra em peers.json
   |                                       |
   |<── 200 OK ───────────────────────────-|
   |   {                                    |
   |     "did": "did:key:z6MktbB...",      |
   |     "publicKey": "base64...",          |
   |     "x25519PublicKey": "base64...",    |
   |     "endpoint": "http://localhost:8002",
   |     "vc": { ... VC do Beta ... }       |
   |   }                                    |
   |                                       |
   | 4. Verifica blacklist                  |
   | 5. Verifica VC do Beta                 |
   | 6. Registra Beta em peers.json         |
```

### Três Modos de Handshake:

| Endpoint               | Requer VC? | Uso                                            |
| ---------------------- | ---------- | ---------------------------------------------- |
| `POST /handshake`      | ❌         | Trust-on-first-use (legado)                    |
| `POST /handshake-vc`   | ✅         | Handshake seguro com verificação de credencial |
| `POST /handshake-peer` | ❌         | Disparado pelo dashboard/cliente               |

### Registro no Peer Store (`peers.json`):

```json
{
  "did:key:z6MktafZc3fRJHfJxQFuHevpvKMK67FNMVMDJDyA6LqdEYha": {
    "did": "did:key:z6MktafZc3fRJHfJxQFuHevpvKMK67FNMVMDJDyA6LqdEYha",
    "publicKey": "MCowBQYDK2VwAyEA...",
    "x25519PublicKey": "MCowBQYDK2VwAyEA...",
    "endpoint": "http://localhost:8001",
    "status": "active"
  }
}
```

### Transmissão de Mensagem Segura (Fluxo Completo):

```
Dashboard/CLI                Agente A                    Agente B
   |                           |                           |
   | 1. "Enviar Olá para Beta" |                           |
   |-------------------------->|                           |
   |                           |                           |
   |                   2. Monitor Cognitivo (Python)
   |                      - Verifica anomalias
   |                      - Verifica blacklist
   |                      - Tamanho < 100 chars
   |                      - Sem keywords proibidas
   |                           |                           |
   |                   3. POST /send-message (intenção)
   |<------------------------->|                           |
   |                           |                           |
   |                   4. Key Guard (Go):
   |                      - Valida regras (rules.go)
   |                      - Busca DID → endpoint (peers.json)
   |                      - Busca chave X25519 do destino
   |                      - Cria JWS (assina com Ed25519)
   |                      - Cria JWE (criptografa com X25519)
   |                           |                           |
   |                           |── POST /receive-message ──>|
   |                           |   (JWE envelope)          |
   |                           |                           |
   |                           |                   5. Key Guard Beta:
   |                           |                      - Descriptografa JWE (X25519)
   |                           |                      - Verifica JWS (Ed25519)
   |                           |                      - Verifica blacklist
   |                           |                      - Enfileira na inbox
   |                           |                           |
   |                           |<── 200 OK ────────────────|
   |                           |                           |
   |<── 200 OK ───────────────|                           |
   |                           |                           |
   |                           |                   6. Polling GET /inbox
   |                           |<──────────────────────────|
   |                           |    (Cognitive lê mensagem)|
```

---

> Uma **âncora de confiança central** que emite, verifica e revoga **W3C Verifiable Credentials** para os agentes da rede

### Arquitetura da CA

```
┌─────────────────────────────────────────────┐
│      CREDENTIAL AUTHORITY (Go — porta 9001)   │
│                                               │
│  ┌─────────────┐  ┌──────────────────────┐   │
│  │ Root Key    │  │      Registry         │   │
│  │ Ed25519     │  │  ┌────────────────┐   │   │
│  │ (gerada na  │  │  │ VCs emitidos   │   │   │
│  │  primeira   │  │  ├────────────────┤   │   │
│  │  execução)  │  │  │ CRL (Lista de  │   │   │
│  └─────────────┘  │  │ Revogação)     │   │   │
│                   │  └────────────────┘   │   │
│                   └──────────────────────┘   │
│                                               │
│  Endpoints REST:                              │
│  GET    /ca/info                              │
│  POST   /credential/issue                     │
│  POST   /credential/verify                    │
│  POST   /credential/revoke                    │
│  GET    /credential/crl                       │
│  GET    /credential/status/{id}               │
│  GET    /credential/list                      │
│  POST   /admin/reset                          │
└─────────────────────────────────────────────┘
```

### Chave Raiz da CA

```go
// credential-authority/ca.go

type CredentialAuthority struct {
    name       string
    did        string                // did:key: da própria CA
    privateKey ed25519.PrivateKey    // Chave raiz (gera na 1ª execução)
    publicKey  ed25519.PublicKey
    reg        *registry.Registry    // Registry + CRL persistidos em JSON
    datadir    string                // data_ca/
}
```

**Geração da chave raiz:**

```go
func loadOrGenerateRootKey(datadir string) (ed25519.PrivateKey, error) {
    // Tenta carregar existente
    if _, err := os.Stat(privPath); err == nil {
        privData, _ := os.ReadFile(privPath)
        decoded, _ := base64.StdEncoding.DecodeString(string(privData))
        return ed25519.PrivateKey(decoded), nil
    }

    // Gera nova
    pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)

    // Salva com permissões restritas
    os.WriteFile(privPath, []byte(base64.StdEncoding.EncodeToString(privKey)), 0600)
    os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pubKey)), 0644)

    return privKey, nil
}
```

### W3C Verifiable Credential — Estrutura

```go
// credential-authority/credential/credential.go

type VerifiableCredential struct {
    Context           []string          `json:"@context"`
    ID                string            `json:"id"`
    Type              []string          `json:"type"`
    Issuer            string            `json:"issuer"`
    IssuanceDate      string            `json:"issuanceDate"`
    ExpirationDate    string            `json:"expirationDate"`
    CredentialSubject CredentialSubject `json:"credentialSubject"`
    Proof             *Ed25519Proof     `json:"proof,omitempty"`
}

type CredentialSubject struct {
    ID                 string   `json:"id"`                 // DID do agente
    PublicKeyMultibase string   `json:"publicKeyMultibase"` // Chave pública
    AgentName          string   `json:"agentName"`
    AgentRole          string   `json:"agentRole"`          // "standard"
    TrustLevel         string   `json:"trustLevel"`         // "trusted"
    Capabilities       []string `json:"capabilities"`       // ["messaging", "task-execution"]
}

type Ed25519Proof struct {
    Type               string `json:"type"`               // "Ed25519Signature2020"
    Created            string `json:"created"`
    VerificationMethod string `json:"verificationMethod"` // issuerDID#key-1
    ProofPurpose       string `json:"proofPurpose"`       // "assertionMethod"
    ProofValue         string `json:"proofValue"`         // assinatura base64url
}
```

### JSON Exemplo de um VC Emitido:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "vc:a2a:ca:Alfa-1719000000123456",
  "type": ["VerifiableCredential", "AgentCredential"],
  "issuer": "did:key:z6MkcaCA...",
  "issuanceDate": "2025-06-23T10:00:00Z",
  "expirationDate": "2025-12-20T10:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MktafZc3fRJHfJxQFuHevpvKMK67FNMVMDJDyA6LqdEYha",
    "publicKeyMultibase": "z6MktafZc3fRJHfJxQFuHevpvKMK67FNMVMDJDyA6LqdEYha",
    "agentName": "Alfa",
    "agentRole": "standard",
    "trustLevel": "trusted",
    "capabilities": ["messaging", "task-execution"]
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2025-06-23T10:00:00Z",
    "verificationMethod": "did:key:z6MkcaCA...#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "eyJzaWciOiJGRXhhbXBsZV9zaWduYXR1cmVfZm9yX3ByZXNlbnRhdGlvbl9wdXJwb3Nlc19vbmx5In0"
  }
}
```

### Assinatura do VC (Sign):

```go
// A prova é feita sobre o JSON sem a proof (canonicalização simples)
func (vc *VerifiableCredential) Sign(signerDID string, privateKey ed25519.PrivateKey) error {
    // 1. Cria cópia sem proof
    signingVC := *vc
    signingVC.Proof = nil

    // 2. Serializa para JSON
    data, _ := json.Marshal(signingVC)

    // 3. Assina com Ed25519
    signature := ed25519.Sign(privateKey, data)

    // 4. Adiciona proof ao VC original
    vc.Proof = &Ed25519Proof{
        Type:               "Ed25519Signature2020",
        Created:            time.Now().UTC().Format(time.RFC3339),
        VerificationMethod: signerDID + "#key-1",
        ProofPurpose:       "assertionMethod",
        ProofValue:         base64.RawURLEncoding.EncodeToString(signature),
    }
    return nil
}
```

### Verificação do VC (Verify):

```go
func (vc *VerifiableCredential) Verify(publicKey ed25519.PublicKey) error {
    // 1. Cria cópia sem proof (mesmo procedimento do Sign)
    signingVC := *vc
    signingVC.Proof = nil
    data, _ := json.Marshal(signingVC)

    // 2. Decodifica assinatura
    sigBytes, _ := base64.RawURLEncoding.DecodeString(vc.Proof.ProofValue)

    // 3. Verifica
    if !ed25519.Verify(publicKey, data, sigBytes) {
        return fmt.Errorf("invalid credential signature")
    }
    return nil
}
```

### API REST da CA

| Método | Endpoint                  | Corpo                                  | Resposta                                                |
| ------ | ------------------------- | -------------------------------------- | ------------------------------------------------------- |
| `GET`  | `/ca/info`                | —                                      | `{name, did, publicKey, totalIssued, totalRevoked}`     |
| `POST` | `/credential/issue`       | `{did, publicKeyMultibase, agentName}` | VC completo com proof                                   |
| `POST` | `/credential/verify`      | `{credential: {...}}`                  | `{verified: true/false, error?, subject?, issuer?}`     |
| `POST` | `/credential/revoke`      | `{credentialId, reason?}`              | `{revoked: true, id}`                                   |
| `GET`  | `/credential/crl`         | —                                      | `{totalRevoked, entries: [{id, revokedAt, reason}]}`    |
| `GET`  | `/credential/status/{id}` | —                                      | `{id, status: "valid"/"revoked"/"not_found", ...}`      |
| `GET`  | `/credential/list`        | —                                      | `{totalIssued, credentials: [{id, subject, issuedAt}]}` |
| `POST` | `/admin/reset`            | —                                      | `{status: "reset", totalIssued: 0, totalRevoked: 0}`    |

### Emissão de Credencial (IssueCredential):

```go
func (ca *CredentialAuthority) IssueCredential(agentDID, publicKeyMultibase, agentName string) (*credential.VerifiableCredential, error) {
    // Reusa VC existente se ainda válido
    if existing := ca.reg.FindByAgentDID(agentDID); existing != nil {
        expDate, _ := time.Parse(time.RFC3339, existing.ExpirationDate)
        if time.Now().Before(expDate) {
            return existing, nil  // Idempotente
        }
    }

    // Cria subject com capabilities
    subject := credential.CredentialSubject{
        ID:                 agentDID,
        PublicKeyMultibase: publicKeyMultibase,
        AgentName:          agentName,
        AgentRole:          "standard",
        TrustLevel:         "trusted",
        Capabilities:       []string{"messaging", "task-execution"},
    }

    // Cria VC com validade de 180 dias
    vc := credential.NewVerifiableCredential(credID, ca.did, subject, 180)

    // Assina com a chave raiz da CA
    vc.Sign(ca.did, ca.privateKey)

    // Registra
    ca.reg.Add(vc)
    return vc, nil
}
```

### Destaques Técnicos da CA:

| Característica    | Detalhe                                                                          |
| ----------------- | -------------------------------------------------------------------------------- |
| **Dependências**  | **Zero dependências externas** — apenas Go stdlib                                |
| **Persistência**  | Chave raiz em `data_ca/root_key.{priv,pub}`, registry em `data_ca/registry.json` |
| **Permissões**    | Chave privada salva com `0600` (apenas dono lê)                                  |
| **Idempotência**  | Reusa VC existente se ainda válido (mesmo DID não gera duplicatas)               |
| **Validade**      | 180 dias por padrão, configurável                                                |
| **Thread-safety** | `sync.RWMutex` em todas as operações                                             |

---

### O Key Guard como Cliente da CA

O Key Guard de cada agente possui um **cache da CRL** e verifica credenciais **localmente** antes de aceitar handshakes e mensagens.

### Verificação de Credencial no Key Guard:

```go
// key-guard/credential/credential.go (pseudocódigo do fluxo)

func VerifyCredentialLocally(vc *VerifiableCredential) error {
    // 1. Verifica tipo
    if !contains(vc.Type, "VerifiableCredential") {
        return errors.New("invalid credential type")
    }

    // 2. Verifica assinatura (chave pública da CA, conhecida por todos)
    if err := vc.Verify(caPublicKey); err != nil {
        return fmt.Errorf("signature verification failed: %w", err)
    }

    // 3. Verifica expiração
    if vc.IsExpired() {
        return errors.New("credential expired")
    }

    // 4. Verifica CRL (cache local com TTL)
    if crlCache.IsRevoked(vc.ID) {
        return errors.New("credential has been revoked")
    }

    return nil
}
```

### CRL Cache:

```go
type CRLCache struct {
    revoked   map[string]bool  // ID → revoked
    lastFetch time.Time        // Última atualização
    ttl       time.Duration    // 5 minutos padrão
    mu        sync.RWMutex
}

func (c *CRLCache) IsRevoked(id string) bool {
    c.mu.RLock()
    revoked := c.revoked[id]
    c.mu.RUnlock()

    // Se cache expirou, força refresh assíncrono
    if time.Since(c.lastFetch) > c.ttl {
        go c.ForceRefresh()
    }

    return revoked
}
```

### Fluxo de Verificação no Handshake:

```
Agente A                          Agente B                    CA (porta 9001)
   |                                 |                           |
   |── POST /handshake-vc ─────────>|                           |
   |   (inclui VC do A)             |                           |
   |                                 |                           |
   |                         1. Verifica assinatura            |
   |                            (Ed25519, chave pública CA)     |
   |                                 |                           |
   |                         2. Verifica expiração             |
   |                                 |                           |
   |                         3. Consulta CRL:                  |
   |                            GET /credential/crl ──────────>|
   |                            <── [{id, revokedAt, reason}] -|
   |                                 |                           |
   |                         4. Cacheia CRL (TTL 5 min)        |
   |                                 |                           |
   |                         5. Verifica se VC.ID está na CRL  |
   |                                 |                           |
   |                         6. ✅ Aceita handshake            |
   |<── 200 OK ────────────────────|                           |
```

### Revogação de Credencial:

```go
// CA: revoga e adiciona à CRL
func (ca *CredentialAuthority) RevokeCredential(credentialID, reason string) error {
    return ca.reg.Revoke(credentialID, reason)
}

// Registry: persistente em registry.json
func (r *Registry) Revoke(id, reason string) error {
    // 1. Verifica se credential existe e não está revogada
    // 2. Adiciona à CRL com timestamp
    // 3. Salva registry.json em disco
    // 4. Remove do mapa de válidos
}
```

### Registry persistido (`data_ca/registry.json`):

```json
{
  "issued": {
    "vc:a2a:ca:Alfa-1719000000123456": {
      "id": "vc:a2a:ca:Alfa-1719000000123456",
      "subject": "did:key:z6MktafZ...",
      "agentName": "Alfa",
      "issuedAt": "2025-06-23T10:00:00Z",
      "expirationDate": "2025-12-20T10:00:00Z"
    }
  },
  "crl": [
    {
      "id": "vc:a2a:ca:Beta-1719000000123457",
      "revokedAt": "2025-06-23T12:00:00Z",
      "reason": "agent compromised"
    }
  ]
}
```

### Propriedades do Sistema de Credenciais:

| Propriedade                     | Descrição                                                     |
| ------------------------------- | ------------------------------------------------------------- |
| **Verificação local**           | Agentes verificam VCs sem consultar a CA (usando CRL cache)   |
| **Resiliência offline**         | Cache com TTL permite operação mesmo se CA ficar indisponível |
| **Revogação imediata**          | CA atualiza CRL → agentes pegam na próxima consulta           |
| **Sem single point of failure** | Cache + handshake direto mantém a rede funcionando            |
| **Prova criptográfica**         | Assinatura Ed25519 garante autenticidade do VC                |

---

### Pré-requisitos (já instalados):

```bash
# Python 3 + Go
python3 --version
go version
```

### 1. Compilar e Iniciar a Autoridade de Credenciais:

```bash
cd credential-authority
go build -o ca-bin .
./ca-bin -port 9001 -name "A2A Credential Authority" &
cd ..
```

### 2. Compilar e Iniciar os Key Guards:

```bash
cd key-guard
go build -o key-guard-bin .

# Agente Alfa (porta 8001)
./key-guard-bin -port 8001 -name Alfa &

# Agente Beta (porta 8002)
./key-guard-bin -port 8002 -name Beta &
cd ..
```

### 3. Emitir Credenciais para os Agentes:

```bash
# Descobrir DIDs
curl -s http://localhost:8001/status | python3 -m json.tool

# Emitir VC para Alfa
curl -X POST http://localhost:9001/credential/issue \
  -H "Content-Type: application/json" \
  -d '{"did":"did:key:z6MktafZc3fRJHfJxQFuHevpvKMK67FNMVMDJDyA6LqdEYha","publicKeyMultibase":"z6MktafZc3fRJHfJxQFuHevpvKMK67FNMVMDJDyA6LqdEYha","agentName":"Alfa"}'

# Emitir VC para Beta
curl -X POST http://localhost:9001/credential/issue \
  -H "Content-Type: application/json" \
  -d '{"did":"did:key:z6MktbB...","publicKeyMultibase":"z6MktbB...","agentName":"Beta"}'
```

### 4. Executar Handshake com VC:

```bash
# Handshake: Alfa → Beta
curl -X POST http://localhost:8001/handshake-peer \
  -H "Content-Type: application/json" \
  -d '{"target":"http://localhost:8002"}'
```

### 5. Executar Testes E2E Completos:

```bash
python3 tests/a2a_full_test.py
```

### Resultado Esperado:

```
Starting Key Guard subprocesses...
Starting CA subprocess...
Waiting for services to start (5s)...

--- Test 01: Normal P2P Communication ---
✅ Test 01 passed: Normal secure message sent, signed, resolved, and verified successfully.

--- Test 02: Key Guard Business Rule Violation ---
✅ Test 02 passed: Key Guard successfully blocked signature for exceeding limit.

--- Test 03: Key Guard Security Rule Violation ---
✅ Test 03 passed: Key Guard successfully blocked signature containing forbidden keywords.

--- Test 04: Cognitive Anomaly Detection and Circuit Breaker ---
✅ Test 04 passed: Circuit Breaker triggered. Faulty agent isolated, and P2P revocation alert verified.

--- Test 05: VC Handshake ---
✅ Test 05 passed: VC handshake completed with mutual credential verification.

--- Test 06: Revocation Propagation ---
✅ Test 06 passed: Revoked credential detected and rejected.

Terminating subprocesses...
----------------------------------------------------------------------
Ran 6 tests in 12.847s

OK
```

### 6. (Opcional) Dashboard Visual:

```bash
./venv/bin/python3 dashboard/server.py &
open http://localhost:9000
```

---

### O que foi implementado:

| Componente                  | Padrão/Especificação                      | Status | Arquivo                                         |
| --------------------------- | ----------------------------------------- | ------ | ----------------------------------------------- |
| `did:key:`                  | W3C DID + multicodec (0xed01) + base58btc | ✅     | `key-guard/crypto/did.go`                       |
| JWS Flat Serialization      | DIDComm V2 (EdDSA/Ed25519)                | ✅     | `key-guard/didcomm/didcomm.go`                  |
| JWE ECDH-ES + XC20P         | DIDComm V2 (X25519 + XChaCha20-Poly1305)  | ✅     | `key-guard/didcomm/jwe.go`                      |
| Ed25519 → X25519            | ed2curve (RFC 7748)                       | ✅     | `key-guard/crypto/x25519.go`                    |
| W3C Verifiable Credential   | `Ed25519Signature2020` proof              | ✅     | `credential-authority/credential/credential.go` |
| Certificate Revocation List | W3C padrão (cache com TTL)                | ✅     | `credential-authority/registry/registry.go`     |
| A2A Task Protocol           | Google A2A (6 estados)                    | ✅     | `key-guard/a2a/task.go`                         |
| Agent Card                  | `/.well-known/agent-card`                 | ✅     | `key-guard/agentcard/card.go`                   |
| Circuit Breaker             | P2P Revocation Alert                      | ✅     | `cognitive/agent.py`                            |

### Lições Aprendidas:

**1. Ed25519 → X25519 via ed2curve é limpo e determinístico**

- Mesmo par de chaves serve para assinar (Ed25519) e para acordo de chaves (X25519)
- Conversão via SHA-512 + clamp por RFC 7748
- Ambos os lados derivam sem comunicação extra

**2. Go é a escolha certa para crypto**

- stdlib completa (`crypto/ed25519`, `crypto/ecdh`, `crypto/sha512`)
- `golang.org/x/crypto` para XChaCha20-Poly1305
- Sem GC pauses, performance previsível, tipagem forte
- Zero dependências para a CA

**3. Sign-then-Encrypt é o padrão correto**

- Primeiro assina (JWS) → autenticidade + não-repúdio
- Depois criptografa (JWE) → confidencialidade
- Destinatário: descriptografa primeiro, verifica assinatura depois
- Evita ataques de padding oracle e permite verificação por terceiros

**4. CRL cache com TTL dá resiliência**

- Agentes funcionam offline por até 5 minutos sem a CA
- Refresh assíncrono não bloqueia operações
- Revogações são efetivas em no máximo 5 minutos

**5. Isolamento de camadas previne exfiltração de chaves**

- Chave privada nunca sai do processo Go
- Mesmo com prompt injection no LLM, a chave está segura
- Camada cognitiva só vê o resultado das operações (sucesso/erro)

### Estatísticas do Projeto:

| Métrica                      | Valor                         |
| ---------------------------- | ----------------------------- |
| Total de linhas (Go)         | ~3.500                        |
| Total de linhas (Python)     | ~1.400                        |
| Total de arquivos            | ~25                           |
| Dependências (Go)            | 1 (`golang.org/x/crypto`)     |
| Dependências (Python)        | 3 (Flask, Pydantic, requests) |
| Testes E2E                   | 6 cenários                    |
| Tempo de execução dos testes | ~13 segundos                  |

### Próximos Passos (para produção):

- [ ] TLS mútuo (mTLS) nas comunicações P2P
- [ ] Rate limiting e proteção contra DDoS
- [ ] Logging estruturado (JSON) + observabilidade
- [ ] Health checks e graceful shutdown
- [ ] Testes de concorrência (race conditions)
- [ ] Rotação de chaves (key rotation)
- [ ] Suporte a múltiplos métodos DID (ex: `did:web:`)
- [ ] DIDComm V2.0 message packing (mais compacto que JSON)

---

### Para mostrar código ao vivo, foque nestes trechos:

| O que mostrar         | Arquivo                                               | Linhas | Tempo |
| --------------------- | ----------------------------------------------------- | ------ | ----- |
| Geração de `did:key:` | `key-guard/crypto/did.go:81-86`                       | 6      | 30s   |
| Assinatura JWS        | `key-guard/didcomm/didcomm.go:35-68`                  | 34     | 1min  |
| Criptografia JWE      | `key-guard/didcomm/jwe.go:47-124`                     | 78     | 2min  |
| Ed25519 → X25519      | `key-guard/crypto/x25519.go:16-27`                    | 12     | 30s   |
| Assinatura do VC      | `credential-authority/credential/credential.go:60-80` | 21     | 1min  |
| Verificação do VC     | `credential-authority/ca.go:128-157`                  | 30     | 1min  |
| CRL Cache             | `key-guard/credential/credential.go` (estrutura)      | —      | 30s   |

### Perguntas e Respostas:

**P: Por que não usar blockchain para resolver DIDs?**

R: Para este cenário (agentes P2P em rede local/controlada), blockchain adiciona latência, custo e complexidade desnecessários. A resolução via handshake direto com `peers.json` é mais rápida (milissegundos vs segundos) e suficiente. Se um dia precisar de resolução global, basta adicionar um método `did:web:` ou `did:orb:`.

**P: Por que JWS + JWE? Não bastaria só criptografia?**

R: _Sign-then-encrypt_ é o padrão recomendado pelo DIDComm V2 e pela criptografia moderna:

- **JWS** (assinatura): garante autenticidade (quem enviou) e não-repúdio (não pode negar)
- **JWE** (criptografia): garante confidencialidade (só o destinatário lê)
- Se só criptografar, um intermediário pode forjar mensagens (não sabe o conteúdo, mas pode reordenar/repetir)
- Se só assinar, qualquer um na rede pode ler o conteúdo

**P: O projeto é production-ready?**

R: É um **protótipo funcional** que demonstra todos os conceitos. Para produção precisaria de: mTLS, rate limiting, logging estruturado, health checks, testes de concorrência, rotação de chaves e suporte a múltiplos métodos DID. A arquitetura, no entanto, foi projetada para evoluir naturalmente para produção.

**P: Quantas linhas de código no total?**

R: Aproximadamente 5.000 linhas divididas em ~3.500 em Go (a parte crítica de crypto e rede) e ~1.500 em Python (cognição e dashboard). A CA tem zero dependências externas — apenas Go stdlib.

### Referência rápida de comandos:

```bash
# Compilar Key Guard
cd key-guard && go build -o key-guard-bin .

# Compilar CA
cd credential-authority && go build -o ca-bin .

# Iniciar CA
./ca-bin -port 9001 -name "A2A CA" &

# Iniciar Key Guards
./key-guard -port 8001 -name Alfa -cauri http://localhost:9001 &
./key-guard -port 8002 -name Beta -cauri http://localhost:9001 &

# Testes
python3 tests/a2a_full_test.py

# Dashboard
python3 dashboard/server.py &  # → http://localhost:9000
```

---
