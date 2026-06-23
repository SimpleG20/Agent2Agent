# Roteiro da Apresentação: A2A Secure Net

Este documento fornece o roteiro completo de fala (guia do apresentador) correspondente aos slides da apresentação do **A2A Secure Net**. O conteúdo foi estruturado para ajudar você a apresentar o projeto de forma clara, profissional e impactante.

---

## **Slide 1: Capa (Introdução)**

*   **Texto Visual do Slide:** Título, Subtítulo e Pilares (SSI, Isolamento, P2P, Mitigação Ativa).
*   **Tempo Estimado:** 1 minuto.
*   **O que Falar (Roteiro):**
    > *"Olá a todos. Hoje vou apresentar o **A2A Secure Net**, um protótipo avançado de rede ponto a ponto (P2P) projetado especificamente para comunicação segura entre agentes cognitivos autônomos. Com a ascensão de agentes de IA baseados em LLMs que realizam transações e tomam decisões em nosso nome, garantir a segurança dessas comunicações tornou-se um desafio crítico. O A2A Secure Net responde a esse desafio trazendo os conceitos de Identidades Auto-Soberanas (SSI) e criptografia robusta diretamente para o fluxo de trabalho dos agentes de inteligência, sem depender de orquestradores ou blockchains públicas."*
*   **Dica do Apresentador:** Defina o tom da apresentação aqui. Mostre que o foco principal é resolver um problema real de segurança da nova era da IA (Agentes Autônomos).

---

## **Slide 2: O Desafio de Segurança de LLMs (O Problema)**

*   **Texto Visual do Slide:** Vulnerabilidades de LLMs (Exposição de chaves, Prompt Injection, Centralização) e a Solução de Isolamento.
*   **Tempo Estimado:** 1 minuto e meio.
*   **O que Falar (Roteiro):**
    > *"Por que precisamos disso? Hoje, se dermos chaves privadas ou privilégios de transação diretamente a um LLM ou à sua camada cognitiva baseada em prompts, criamos um risco de segurança inaceitável. LLMs são suscetíveis a ataques de **Prompt Injection** — onde um usuário ou um par malicioso pode injetar comandos camuflados para que a IA ignore suas instruções originais, revele dados confidenciais ou transfira ativos indevidamente. Além disso, as redes centralizadas tradicionais introduzem intermediários vulneráveis. A nossa proposta resolve isso separando rigidamente o cérebro (camada de decisão) do escudo (camada de criptografia e conformidade). As chaves privadas nunca são acessadas pelo LLM."*
*   **Dica do Apresentador:** Enfatize que o LLM é imprevisível por natureza (não-determinístico) e que a segurança precisa ser garantida por uma camada separada e determinística.

---

## **Slide 3: Arquitetura Geral do Sistema (A Estrutura)**

*   **Texto Visual do Slide:** Diagrama de fluxo de componentes (Dashboard, Nós Alfa e Beta, e suas conexões HTTP/DIDComm).
*   **Tempo Estimado:** 2 minutos.
*   **O que Falar (Roteiro):**
    > *"Aqui temos o panorama completo do ecossistema. Cada agente autônomo opera como um nó independente, contendo duas camadas que conversam de forma isolada: a **Camada Cognitiva** em Python, que toma as decisões de negócios e valida intenções, e a **Camada Criptográfica**, chamada de **Key Guard**, construída em Go, que gerencia chaves, valida regras duras de segurança e empacota mensagens. Externamente, os Key Guards conversam entre si usando chamadas HTTP diretas com envelopes criptográficos no padrão DIDComm v2. Por fim, temos um **Dashboard** visual construído em Flask que orquestra e monitora o estado de todos os nós em tempo real."*
*   **Dica do Apresentador:** Aponte para o diagrama no slide para guiar os olhos do público através das conexões entre o Python local, o Go local e a comunicação entre os nós P2P.

---

## **Slide 4: Camada Cognitiva (O Cérebro em Python)**

*   **Texto Visual do Slide:** Lógica Python, SQLite (`cognitive_store.db`), Monitor de Anomalias e Circuit Breaker.
*   **Tempo Estimado:** 1 minuto e meio.
*   **O que Falar (Roteiro):**
    > *"A Camada Cognitiva roda em Python e é onde reside a lógica de negócios da IA. Para interagir com o mundo externo, o agente utiliza ferramentas estruturadas como `tool_send_message` e `tool_read_inbox`. Mas antes de qualquer ação, o **Monitor de Anomalias** atua. Se o agente receber ou for solicitado a enviar uma mensagem com tamanho abusivo (definido em mais de 100 caracteres) ou que contenha indicadores de Prompt Injection — como 'ignore instruções anteriores' ou palavras-chave sensíveis como 'private_key' — a camada cognitiva bloqueia a ação localmente e dispara o **Circuit Breaker** para isolar o peer agressor."*
*   **Dica do Apresentador:** Explique que o banco SQLite guarda localmente um histórico de tentativas e o status de reputação dos parceiros.

---

## **Slide 5: Camada Criptográfica — Key Guard (O Escudo em Go)**

*   **Texto Visual do Slide:** Escudo protetor Go, chaves Ed25519 offline, regras determinísticas, DIDComm v2 (JWS), cache local e Blacklist TTL.
*   **Tempo Estimado:** 2 minutos.
*   **O que Falar (Roteiro):**
    > *"O Key Guard é o escudo determinístico do agente, escrito em Go. Ele gera e carrega de forma 100% local e offline chaves criptográficas Ed25519. A sua grande missão é garantir a conformidade absoluta: mesmo que o LLM seja enganado por um prompt malicioso, o Key Guard aplica regras fixas em Go na pasta `rules/` que o LLM não pode anular. Por exemplo, ele impede a assinatura física de qualquer payload que mencione termos proibidos ou que viole limites definidos pelo protocolo. Além disso, o Key Guard gerencia os arquivos `peers.json` para resolução de DIDs offline e uma `blacklist.json` dinâmica baseada em memória e disco com expiração TTL de 10 minutos, garantindo que peers maliciosos sejam rejeitados na camada de rede."*
*   **Dica do Apresentador:** Destaque o uso do padrão **DIDComm v2 JWS (JSON Web Signature)**, o qual garante autenticidade ponta a ponta por meio de assinaturas EdDSA.

---

## **Slide 6: Fluxo A — Handshake P2P Offline**

*   **Texto Visual do Slide:** Diagrama de sequência do handshake.
*   **Tempo Estimado:** 1 minuto.
*   **O que Falar (Roteiro):**
    > *"Como os agentes se conhecem sem um servidor central? Eles utilizam um fluxo de handshake direto de via dupla. O agente Alfa inicia uma requisição enviando suas credenciais: seu DID local, sua chave pública Ed25519 e seu endpoint. O Key Guard Beta recebe, verifica se o Alfa não está em sua lista negra, e o registra em seu cadastro local `peers.json`. Em seguida, Beta responde com suas próprias credenciais, que são registradas pelo Alfa. A partir desse instante, eles estão conectados de forma soberana. Vale ressaltar que se um agente estiver na blacklist, o handshake é sumariamente bloqueado com 403 Forbidden."*

---

## **Slide 7: Fluxo B — Transmissão e Recebimento Seguro**

*   **Texto Visual do Slide:** Diagrama de sequência do envio seguro e leitura de inbox.
*   **Tempo Estimado:** 1 minuto e meio.
*   **O que Falar (Roteiro):**
    > *"Quando o agente decide enviar uma mensagem, o fluxo é o seguinte: a camada cognitiva Python solicita o envio ao Key Guard local. O Key Guard local valida o conteúdo contra a blacklist e o motor de regras duras em Go. Se tudo estiver correto, ele assina o payload com a chave privada do agente Alfa, gerando um envelope JWS. Esse envelope é transmitido pela rede HTTP P2P até o Key Guard do destinatário, Beta. O Key Guard de Beta valida a assinatura usando a chave pública conhecida de Alfa e enfileira a mensagem limpa na fila local. A camada cognitiva de Beta, que realiza polling periódico na inbox, lê a mensagem segura, realiza sua validação cognitiva e salva no SQLite local."*

---

## **Slide 8: Fluxo C — Circuit Breaker & Auto-Revogação**

*   **Texto Visual do Slide:** Diagrama de sequência da detecção de ataque e isolamento do parceiro.
*   **Tempo Estimado:** 2 minutos.
*   **O que Falar (Roteiro):**
    > *"E o que acontece se ocorrer um ataque? Suponha que o agente Alfa seja enganado ou hackeado e tente enviar um comando abusivo ou malicioso para o agente Beta. O monitor de anomalias cognitivas de Alfa detecta a violação antes do envio. Imediatamente, ele aciona o Circuit Breaker local. O agente Alfa então atualiza sua própria blacklist cognitiva e solicita ao Key Guard o disparo de uma mensagem especial de **Auto-Revogação P2P** assinada. Para que essa mensagem passe pelo próprio Key Guard sem ser bloqueada pelas regras de palavras proibidas, o monitor Python faz uma **sanitização prévia**, substituindo strings confidenciais por '[CLASSIFIED]'. Ao receber o envelope de revogação, o Key Guard de Beta identifica a anomalia, adiciona Alfa na blacklist temporária com expiração (TTL) e atualiza o estado de Alfa para 'revogado' no catálogo de peers. O canal é derrubado instantaneamente."*
*   **Dica do Apresentador:** Enfatize que essa resposta é autônoma, imediata e descentralizada, impedindo a propagação de falhas na rede.

---

## **9. Interface Web Interativa (Dashboard)**

*   **Texto Visual do Slide:** Imagem do dashboard, recursos de simulação de ataque, gerenciamento e botão "Desbloquear".
*   **Tempo Estimado:** 1 minuto e meio.
*   **O que Falar (Roteiro):**
    > *"Para fins de demonstração e depuração, desenvolvemos um Dashboard completo. Ele possui um visual moderno com dark mode, glassmorphism e glows dinâmicos. Nele, conseguimos visualizar as portas de cada agente, suas tabelas de peers conhecidos, o estado das caixas de entrada e as listas negras. O dashboard traz um simulador de ataque onde podemos forçar injeções ou prompts longos para ver as defesas reagirem em tempo real. E, recentemente, adicionamos a funcionalidade de reabilitação: o botão 'Desbloquear' remove o peer das listas negras lógica (Python) e criptográfica (Go), limpando o status de revogação e restaurando a confiança entre os agentes de forma limpa."*

---

## **Slide 10: Resultados da Validação Automatizada (Validação)**

*   **Texto Visual do Slide:** Lista de testes do script de testes automatizados E2E.
*   **Tempo Estimado:** 1 minuto.
*   **O que Falar (Roteiro):**
    > *"Toda essa arquitetura foi exaustivamente testada e validada através de nossa suite de testes de integração de ponta a ponta (`tests/simulation_test.py`). Rodamos testes reais levantando os microsserviços em subprocessos. Validamos com sucesso cenários de comunicação normal, rejeições de tamanho e de palavras proibidas na camada criptográfica do Key Guard, o disparo do Circuit Breaker por injeção cognitiva com propagação da revogação, e os fluxos de desbloqueio e handshakes após banimentos. O resultado foi 100% de sucesso em todos os casos."*

---

## **Slide 11: Conclusão**

*   **Texto Visual do Slide:** Benefícios principais e visão de futuro.
*   **Tempo Estimado:** 1 minuto.
*   **O que Falar (Roteiro):**
    > *"Em resumo, o A2A Secure Net demonstra como podemos construir redes robustas para agentes autônomos onde a segurança não depende da confiabilidade de um modelo de linguagem ou de uma orquestração centralizada. Ao isolar as chaves Ed25519 no Go Key Guard, validar limites determinísticos e automatizar o isolamento com o Circuit Breaker, criamos uma rede resiliente por design. Os próximos passos incluem a expansão para múltiplos nós dinâmicos e testes com regras de conformidade mais complexas. Muito obrigado e fico aberto a quaisquer perguntas."*

---

## **Dicas Gerais para o Apresentador:**
1.  **Faça uma Demo Se Possível:** Após o Slide 9 (Dashboard), abra o painel web em `http://localhost:9000` e demonstre o ataque de Prompt Injection e a remoção subsequente da blacklist clicando no botão "Desbloquear". Isso fixa o conceito de forma excelente.
2.  **Mantenha o Foco na Inovação:** Lembre à audiência que o isolamento entre decisão (Python) e assinatura (Go) é um padrão de design de segurança inovador para ecossistemas de agentes autônomos.
