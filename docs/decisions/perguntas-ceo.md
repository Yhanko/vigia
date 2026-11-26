# Perguntas ao CEO — Decisões de Produto, Negócio e Operação (§24.2)

- **Data:** 2026-11-26
- **Preparado por:** Desenvolvedor (Gemini)
- **Decisor:** 👔 CEO (Yhanko)
- **Referências:** README §24.2; TASKS 0.3 (porta da Fase 0)

> **Como responder:** para cada pergunta apresento as opções práticas e uma recomendação alinhada com o MVP (error tracking compatível Sentry + alertas por email/Telegram/WhatsApp). Basta indicar a opção escolhida (ou escrever uma alternativa) na linha **"Decisão do CEO"**. A porta da Fase 0 abre assim que estas decisões estiverem fechadas.

---

### 1. Público inicial
**Quem são os primeiros clientes do Vigia?**
- **A)** Developers individuais / freelancers
- **B) (Recomendado)** Startups e PMEs tecnológicas em Angola/PALOP (equipas de 2–20 developers que precisam de monitorizar apps em produção com custos previsíveis em moeda/realidade local e alertas no WhatsApp/Telegram)
- **C)** Grandes empresas / bancos (enterprise com requisitos on-prem e SLA contratual pesado)

- **Decisão do CEO:** *(por preencher)*

---

### 2. Modelo de distribuição
**O Vigia será SaaS multi-tenant gerido pela Yhanko, self-hosted, ou ambos?**
- **A) (Recomendado)** **SaaS multi-tenant primeiro** (gerido pela Yhanko); manter o Docker Compose limpo para permitir *self-hosted* dedicado em contratos futuros
- **B)** Apenas uso interno da Yhanko inicialmente
- **C)** Self-hosted open-source/comercial desde o dia 1

- **Decisão do CEO:** *(por preencher)*

---

### 3. Volume esperado de ingestão no MVP (primeiros 6 meses)
**Que volume realista devemos usar para dimensionar o servidor inicial?**
- **A) (Recomendado)** Até **50 organizações**, **1–5 milhões de eventos de erro/mês** (~2 eventos/s médios sustentados a partir das quotas da pergunta 4, picos diurnos de 10–20/s, rajadas até **250 eventos/s**, ~35–40 GB em disco comprimido com 30 dias de retenção) — cabe num VPS modesto (4 vCPU, 8–16 GB RAM, 160–250 GB NVMe)
- **B)** Piloto fechado pequeno (≤ 10 organizações, < 500 mil eventos/mês)
- **C)** Escala elevada desde o dia 1 (> 50 milhões de eventos/mês — exige investimento maior em infra)

- **Decisão do CEO:** *(por preencher)*

---

### 4. Retenção default e limites por plano
**Qual a retenção padrão de `issue_events` e limites sugeridos por plano?**
- **A) (Recomendado)**
  - **Free / Piloto:** 7 dias de retenção, 10 000 eventos/mês, 2 projectos, 3 membros, email + Telegram (sem WhatsApp ou 20 msgs/mês)
  - **Pro / PME:** 30 dias de retenção, 100 000 eventos/mês, 10 projectos, 15 membros, email + Telegram + 200 msgs WhatsApp/mês
  - **Business:** 90 dias de retenção, 500 000 eventos/mês, projectos ilimitados (soft cap 50), 1 000 msgs WhatsApp/mês
  - `audit_logs`: mínimo **180 dias** (separado da telemetria)
- **B)** Plano único simples durante o beta (30 dias, 50 000 eventos/mês por org)

- **Decisão do CEO:** *(por preencher)*

---

### 5. Primeiro alvo de deployment (infraestrutura)
**Onde vai correr o Vigia em produção no go-live (Fase 2.9)?**
- **A) (Recomendado)** **VPS dedicado Linux** (ex.: Hetzner / DigitalOcean / provedor local) com Docker Compose endurecido + Caddy/Traefik (TLS automático) + backups encriptados em object storage S3-compatível (R2/S3/Backblaze)
- **B)** Cloud gerida (GCP Cloud Run / AWS ECS + RDS + ElastiCache) — custo mensal mais elevado
- **C)** Servidor on-premises da Yhanko

- **Decisão do CEO:** *(por preencher)*

---

### 6. Collector OpenTelemetry (Fase 9 — pós-V1)
**Quando chegarmos a OTel (Fase 9), o cliente envia directo para o endpoint OTLP do Vigia ou corre um collector próprio?**
- **A) (Recomendado)** Endpoint OTLP-HTTP nativo no Vigia (cliente envia directo ou via o seu OTel Collector se já tiver); não gerir collectors em infraestrutura de terceiros
- **B)** Fornecer collector pré-configurado gerido pelo Vigia

- **Decisão do CEO:** *(por preencher)*

---

### 7. Métricas de host na Fase 3: agent próprio vs exporters existentes
**Na Fase 3 (métricas de servidores), como recolher CPU/RAM/disco?**
- **A) (Recomendado)** Scripts leves / adaptador compatível com Prometheus exporters existentes (ex.: `node_exporter`) antes de investir num agent próprio em Go (que fica para a Fase 10 se houver procura)
- **B)** Construir um agent Go próprio logo na Fase 3

- **Decisão do CEO:** *(por preencher)*

---

### 8. Canais de notificação no MVP (já parcialmente decidido)
**Email + Telegram + WhatsApp estão definidos para a Fase 2. E quanto a SMS?**
- **A) (Recomendado)** Apenas **Email + Telegram + WhatsApp** no MVP (lançar com Email + Telegram caso a verificação da Meta atrase, conforme ADR-018); SMS fica opcional na Fase 5 apenas se clientes pedirem
- **B)** Incluir SMS já no MVP

- **Decisão do CEO:** *(por preencher)*

---

### 9. Dados proibidos e requisitos legais (Angola — Lei n.º 22/11)
**Confirmar a política de privacidade e enquadramento legal:**
- **Proposta (Recomendado):** proibir por defeito credenciais, cartões (Luhn), BI/NIF/passaporte, request bodies e IPs de utilizadores finais (detalhado em `docs/security/data-classification.md`); publicar Termos de Serviço e Política de Privacidade em conformidade com a **Lei n.º 22/11 (Protecção de Dados Pessoais de Angola)** antes do go-live da Fase 2.9.
- **Questão:** existe algum requisito sectorial adicional (ex.: BNA / banca) previsto para os primeiros clientes?

- **Decisão do CEO:** *(por preencher)*

---

### 10. Política de export/delete e residência de dados
**Como tratar pedidos de eliminação e localização dos dados no MVP?**
- **A) (Recomendado)** Suportar eliminação de issues/projectos/organizações (soft delete com 14 dias de graça + purge definitivo; eliminação imediata sob pedido legal) e export JSON na Fase 8; residência de dados numa única região (Europa ou África do Sul, conforme menor latência para Angola) no MVP, com multi-região apenas em enterprise futuro.
  > **⚠ Nota legal (Lei n.º 22/11):** a transferência internacional de dados pessoais para fora de Angola pode exigir **autorização prévia da Agência de Protecção de Dados (APD)**. Confirmar com jurista antes do go-live (Fase 2.9).
- **B)** Exigência de alojamento físico em território angolano desde o MVP

- **Decisão do CEO:** *(por preencher)*

---

### 11. SLOs realistas para a primeira infra
**Aprova os SLOs iniciais propostos em `docs/architecture/slos-capacity.md`?**
- Resumo: Product API **99,5%** (meta V1: 99,9%), Ingestão Sentry **99,9%**, alerta até 1.ª tentativa de notificação **< 60 s**, RPO metadata **≤ 1 h**, RTO **≤ 2 h**.
- **Decisão do CEO:** *(por preencher)*

---

### 12. SDK Go próprio vs SDKs Sentry / OpenTelemetry
**Confirma o cancelamento de SDKs próprios (Node/Go) no MVP?**
- **A) (Recomendado — já alinhado com decisão do CTO)** Usar os **SDKs oficiais Sentry (MIT)** para todas as linguagens (JS, Python, PHP/Laravel, Java, .NET, Go, mobile) na Fase 2, e HTTP simples/OpenTelemetry para métricas; SDK próprio fica adiado para a Fase 10 só se houver procura real.
- **B)** Construir SDK Go próprio cedo.

- **Decisão do CEO:** *(por preencher)*
