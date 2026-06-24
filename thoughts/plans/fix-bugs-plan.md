# Plano de Correção: Bug Fixes — A2A Secure P2P Network

> **Data:** 2026-06-23
> **Autor:** Orchestrator
> **Status:** Draft — Aguardando aprovação
> **Branch:** `fix/bug-fixes-p0`

---

## Resumo dos Problemas

| # | Severidade | Issue | Arquivo(s) | Esforço |
|---|-----------|-------|-----------|---------|
| 1 | 🔴 **CRITICAL** | CRL Cache race condition (leitura sem lock) | `credential/credential.go:236` | 5 min |
| 2 | 🟠 **MAJOR** | Testes `did:custom:` → `did:key:` — 35 referências | `tests/simulation_test.py`, `tests/a2a_full_test.py` | 1h |
| 3 | 🟠 **MAJOR** | Dashboard `did:custom:` hardcoded | `dashboard/server.py:117`, `dashboard/templates/index.html:1252` | 30 min |
| 4 | 🟡 **MEDIUM** | CA URL port mismatch (9999 vs 9001) | `dashboard/server.py:20` | 2 min |
| 5 | 🟡 **MEDIUM** | Dashboard `-ca-enabled` mas CA nunca inicia | `dashboard/server.py:90-91` | 15 min |
| 6 | 🟡 **MEDIUM** | E2E test binary name errado | `tests/a2a_full_test.py:33` | 2 min |
| 7 | 🟡 **MEDIUM** | Reset não revoga credenciais antigas no CA | `dashboard/server.py:500-535` | 30 min |
| 8 | 🔵 **LOW** | Cognitive agent fallback `did:custom:` | `cognitive/agent.py:51` | 5 min |
| 9 | 🔵 **LOW** | Docs desatualizadas | `README.md`, `system_architecture.md` | 15 min |

**Esforço total estimado:** ~3 horas

---

## Dependências

```
Ticket 1 (Race Condition) ─── independente, pode ser feito a qualquer momento
        │
Ticket 2 (Testes DID) ──────── independente (mas ideal fazer após entender o formato certo)
        │
Ticket 3 (Dashboard DID) ───── depende de decidir formato DID (did:key: vs did:custom:)
        │
Ticket 4 (CA Port) ─────────── independente, correção trivial
        │
Ticket 5 (CA Auto-start) ───── ideal fazer junto com Ticket 4
        │
Ticket 6 (E2E binary) ──────── independente
        │
Ticket 7 (Reset Revoke) ────── depende de entender fluxo CA ↔ Dashboard
        │
Ticket 8 (Agent fallback) ──── depende da decisão de formato DID
        │
Ticket 9 (Docs) ────────────── último (após todas as correções)
```

---

## Ticket 1 — 🔴 CRITICAL: CRL Cache Race Condition

### Problema
Em `credential/credential.go:236`, após liberar o `RLock` e chamar `refresh()`, o método `IsRevoked` lê `c.revoked` sem nenhum lock:

```go
func (c *CRLCache) IsRevoked(credentialID string) bool {
    c.mu.RLock()
    if time.Since(c.lastFetch) < c.ttl {
        val := c.revoked[credentialID]
        c.mu.RUnlock()
        return val
    }
    c.mu.RUnlock()

    c.refresh()              // ← refresh() adquire write lock internamente
    return c.revoked[credentialID]  // ← SEM LOCK! Race condition
}
```

### Solução
Fazer a leitura dentro do `refresh()` ou re-adquirir o lock após o refresh:

```go
func (c *CRLCache) IsRevoked(credentialID string) bool {
    c.mu.RLock()
    if time.Since(c.lastFetch) < c.ttl {
        val := c.revoked[credentialID]
        c.mu.RUnlock()
        return val
    }
    c.mu.RUnlock()

    c.refresh()  // refresh adquire e libera write lock internamente

    c.mu.RLock()
    defer c.mu.RUnlock()
    return c.revoked[credentialID]
}
```

### Arquivos modificados
| Arquivo | Mudança |
|---------|---------|
| `key-guard/credential/credential.go` | Adicionar `RLock` após `refresh()` na linha 236 |

### Verificação
- [ ] `go build ./...` passa
- [ ] `go test -race ./...` não detecta data races no CRLCache
- [ ] Código lê `c.revoked` apenas dentro de lock (RLock ou WLock)

---

## Ticket 2 — 🟠 MAJOR: Atualizar Testes para `did:key:`

### Problema
Os testes `simulation_test.py` e `a2a_full_test.py` usam `did:custom:alfa` / `did:custom:beta` em **35 referências**. Desde o commit `df3917b`, os Key Guards geram `did:key:z...`. As mensagens buscam peers por `did:custom:` mas o handshake registrou como `did:key:` → 404.

### Solução
Substituir todas as referências de `did:custom:alfa` e `did:custom:beta` por `did:key:z...` nos testes.

**Estratégia:** Em vez de hardcodar os DIDs did:key (que mudam a cada execução), usar o endpoint `/agent-info` dos Key Guards para descobrir o DID real, ou usar um helper `resolve_did()` que consulta o processo.

### Implementação

```python
# Helper de resolução de DID
def get_agent_did(port):
    """Get the actual did:key: from a running Key Guard."""
    r = requests.get(f"http://localhost:{port}/agent-info", timeout=2)
    if r.status_code == 200:
        return r.json().get("did_key") or r.json().get("did")
    return None

# Uso nos testes
alfa_did = get_agent_did(8001)  # "did:key:z6Mkr..."
beta_did = get_agent_did(8002)  # "did:key:z6Mkr..."
```

**Importante:** Os testes precisam primeiro iniciar os Key Guards e esperar eles estarem prontos, depois descobrir os DIDs dinamicamente.

### Arquivos modificados
| Arquivo | Mudanças |
|---------|----------|
| `tests/simulation_test.py` | Substituir 35+ referências `did:custom:` por resolução dinâmica |
| `tests/a2a_full_test.py` | Substituir referências `did:custom:`, corrigir binary name (Ticket 6) |

### Verificação
- [ ] `python tests/simulation_test.py` passa 6/6 testes
- [ ] `python tests/a2a_full_test.py` passa (após corrigir binary name)
- [ ] Handshake resolve peers corretamente com `did:key:`

---

## Ticket 3 — 🟠 MAJOR: Dashboard `did:custom:` para `did:key:`

### Problema
- `dashboard/server.py:117`: `did = f"did:custom:{name}"` é o fallback se `/agent-info` falhar
- `dashboard/templates/index.html:1252`: envia mensagens com `did:custom:{name}` como recipient

### Solução

**server.py linha 117:** Já tenta pegar o `did_key` de `/agent-info`. Só mudar o fallback para usar `did_key` corretamente quando disponível. O código atual já faz isso:
```python
did = f"did:custom:{name}"
did_key = ""
if online:
    r = requests.get(...)
    if r.status_code == 200:
        did_key = info.get("did_key", "")
        if did_key:
            did = did_key
```
O código **já está correto** para leitura — o problema real é no **envio**.

**index.html linha 1252:** O template envia mensagens usando `did:custom:{name}` como recipient. Precisa usar o `did` real (que já é o `did:key:` se disponível via a API de status).

**Solução no server.py:** Adicionar um endpoint `/api/did/{name}` que retorna o DID real do agente, e o frontend usa esse endpoint para descobrir o DID antes de enviar.

**Solução no index.html:** Modificar o JavaScript de envio para buscar o DID real do recipient antes de enviar.

### Arquivos modificados
| Arquivo | Mudanças |
|---------|----------|
| `dashboard/server.py` | Adicionar endpoint `/api/did/{name}` |
| `dashboard/templates/index.html` | JS de envio usar DID dinâmico em vez de `did:custom:{name}` |

### Verificação
- [ ] Dashboard envia mensagem → usa `did:key:z...` como recipient
- [ ] Mensagem chega ao destino (Key Guard resolve o peer corretamente)
- [ ] Fallback `did:custom:` nunca é usado para envio

---

## Ticket 4 — 🟡 MEDIUM: CA URL Port Mismatch

### Problema
```python
# dashboard/server.py:20
CA_URL = os.environ.get("CA_URL", "http://localhost:9999")  # 9999
```
```go
// credential-authority/main.go:18
port := 9001  // CA escuta em 9001
```

### Solução
Mudar o default no dashboard:
```python
CA_URL = os.environ.get("CA_URL", "http://localhost:9001")
```

### Arquivos modificados
| Arquivo | Mudança |
|---------|---------|
| `dashboard/server.py:20` | `9999` → `9001` |

### Verificação
- [ ] Dashboard consegue consultar `/ca/info` sem configuração adicional
- [ ] `curl localhost:9001/ca/info` funciona do dashboard

---

## Ticket 5 — 🟡 MEDIUM: CA Auto-Start no Dashboard (Opcional)

### Problema
O dashboard sempre passa `-ca-enabled=true` aos Key Guards (linha 90), mas nunca inicia o processo do CA. Key Guards entram em modo degradado.

### Solução (Duas Opções)

**Opção A (Recomendada):** Dashboard gerencia o ciclo de vida do CA:
```python
def start_ca():
    ca_bin = os.path.join(PROJECT_DIR, "credential-authority", "ca-bin")
    if not os.path.exists(ca_bin):
        log.warning("CA binary not found at %s", ca_bin)
        return False
    if is_port_in_use(9001):
        return True  # já está rodando
    log.info("Starting Credential Authority...")
    os.makedirs(os.path.join(DATA_DIR, "ca"), exist_ok=True)
    log_file = open(os.path.join(DATA_DIR, "ca.log"), "w")
    subprocesses_dict["ca"] = subprocess.Popen(
        [ca_bin, "-port", "9001", "-datadir", os.path.join(DATA_DIR, "ca")],
        stdout=log_file, stderr=log_file, text=True
    )
    time.sleep(2)  # Aguardar startup
    return True
```

**Opção B (Mínima):** Remover `-ca-enabled` do start padrão, e adicionar um botão "Ativar CA" no dashboard.

Vou implementar a **Opção A** por ser mais robusta.

### Arquivos modificados
| Arquivo | Mudanças |
|---------|----------|
| `dashboard/server.py` | Adicionar `start_ca()`, chamar no startup e no `/api/reset` |
| `dashboard/templates/index.html` | Adicionar seção "CA Status" com status online/offline |

### Verificação
- [ ] Dashboard inicia CA automaticamente
- [ ] Key Guards não mostram warning "CA not reachable" no log
- [ ] `/api/reset` reinicia CA também
- [ ] Remoção de agente não derruba o CA

---

## Ticket 6 — 🟡 MEDIUM: E2E Test Binary Name

### Problema
```python
# tests/a2a_full_test.py:33
CA_BIN = os.path.join(PROJECT_DIR, "credential-authority", "credential-authority")
```
O binary real é `ca-bin` (definido no `docker-compose.yml` e no build).

### Solução
```python
CA_BIN = os.path.join(PROJECT_DIR, "credential-authority", "ca-bin")
```

### Arquivos modificados
| Arquivo | Mudança |
|---------|---------|
| `tests/a2a_full_test.py:33` | `credential-authority` → `ca-bin` |

### Verificação
- [ ] Teste E2E encontra o binary do CA

---

## Ticket 7 — 🟡 MEDIUM: `/api/reset` Não Revoga Credenciais Antigas

### Problema
Quando o dashboard faz reset (`/api/reset`, linha 500):
1. Mata todos os Key Guards
2. Deleta `data_dashboard/` (chaves, credentials, peers)
3. Cria novos Key Guards com **novas chaves Ed25519**
4. Key Guards solicitam **novos VCs** ao CA
5. Mas os **VELHOS VCs** no CA (`data_ca/registry.json`) **nunca são revogados**
6. O CRL fica vazio — credenciais órfãs permanecem como "válidas"

### Solução
Antes de limpar os dados, revogar todas as credenciais ativas no CA:

```python
def revoke_all_agent_credentials():
    """Revoga todas as credenciais dos agentes no CA antes do reset."""
    try:
        r = requests.get(f"{CA_URL}/credential/list", timeout=3)
        if r.status_code == 200:
            data = r.json()
            for cred in data.get("credentials", []):
                vc_id = cred.get("vcId")
                if vc_id and not cred.get("revoked", False):
                    requests.post(f"{CA_URL}/credential/revoke",
                        json={"credentialId": vc_id, "reason": "system_reset"},
                        timeout=3)
    except Exception as e:
        print(f"Warning: could not revoke credentials: {e}")
```

Também corrigir o vazamento de memória no `subprocesses_dict`:
```python
# Em vez de:
subprocesses_dict[key] = None
# Usar:
del subprocesses_dict[key]
```

### Arquivos modificados
| Arquivo | Mudanças |
|---------|----------|
| `dashboard/server.py:500-535` | Adicionar `revoke_all_agent_credentials()` antes do cleanup, corrigir `del` vs `= None` |

### Verificação
- [ ] Após reset, CA mostra old credentials como "revoked" no CRL
- [ ] `GET /credential/crl` mostra as credenciais antigas
- [ ] `subprocesses_dict` não acumula entradas `None`
- [ ] Dashboard inicia limpo após reset

---

## Ticket 8 — 🔵 LOW: Cognitive Agent Fallback `did:custom:`

### Problema
```python
# cognitive/agent.py:51
self.did = f"did:custom:{name}"  # fallback
```
Se `/agent-info` falhar, o agente usa `did:custom:{name}` como fallback.

### Solução
Mudar para um placeholder que indique "não resolvido":
```python
self.did = f"did:key:unresolved-{name}"  # fallback temporário
```

Ou melhor: não definir DID no fallback e deixar como `None` ou `""`, forçando erro cedo se algo tentar usar sem resolução.

### Arquivos modificados
| Arquivo | Mudança |
|---------|---------|
| `cognitive/agent.py:51` | Fallback `did:custom:` → `None` ou `did:key:pending-{name}` |

### Verificação
- [ ] Cognitive agent não gera `did:custom:` em logs
- [ ] Se fallback for ativado, log de warning é emitido

---

## Ticket 9 — 🔵 LOW: Documentação Desatualizada

### Problema
- `README.md`: refere-se a `did:custom:<agent_name>`
- `system_architecture.md`: refere-se ao formato antigo

### Solução
Atualizar para refletir `did:key:z...` e o novo sistema de credenciais.

### Arquivos modificados
| Arquivo | Mudanças |
|---------|----------|
| `README.md` | Atualizar seção de DIDs, adicionar CA info |
| `system_architecture.md` | Atualizar diagramas/explicações para `did:key:` |

### Verificação
- [ ] README não menciona `did:custom:`
- [ ] `system_architecture.md` reflete arquitetura atual

---

## Sequência Recomendada de Execução

```
FASE 1 — Bugs Críticos e de Infra (30 min)
  ├── Ticket 1 (Race Condition) — 5 min
  ├── Ticket 4 (CA Port) — 2 min
  └── Ticket 6 (E2E Binary) — 2 min

FASE 2 — DID Migration (1h 30 min)
  ├── Ticket 8 (Agent Fallback) — 5 min
  ├── Ticket 2 (Testes) — 1h
  └── Ticket 3 (Dashboard) — 30 min

FASE 3 — Dashboard e Reset (45 min)
  ├── Ticket 5 (CA Auto-start) — 15 min
  └── Ticket 7 (Reset Revoke) — 30 min

FASE 4 — Docs (15 min)
  └── Ticket 9 (Docs) — 15 min

Total: ~3 horas
```

---

## Skills Necessárias

- `golang` — Ticket 1 (race condition fix)
- `python` — Tickets 2, 3, 5, 7, 8 (testes, dashboard, agent)
- `clean-code-principles` — Qualidade geral do código
- `testing-methodologies` — Tickets 2, 6 (validação dos testes)
- `bash-linux` — Scripts de inicialização e verificação

---

## Definição de Done (Geral)

- [ ] `go build ./key-guard/...` passa
- [ ] `go build ./credential-authority/...` passa
- [ ] `go test -race ./key-guard/...` passa sem data races
- [ ] `python tests/simulation_test.py` passa 6/6
- [ ] Dashboard inicia e opera sem erros de DID
- [ ] Dashboard `localhost:9000` mostra agents online com DIDs `did:key:z...`
- [ ] Reset no dashboard revoga credenciais antigas no CA
- [ ] Mensagens P2P funcionam do dashboard
- [ ] Nenhuma referência a `did:custom:` no código (exceto legacy-mode flag)
