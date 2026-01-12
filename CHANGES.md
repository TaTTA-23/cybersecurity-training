Resumo de alterações e funcionalidades adicionadas
===============================================

Este documento descreve, em detalhe técnico e cronológico, todas as mudanças que foram feitas
no repositório durante a sessão de desenvolvimento. Serve como um "mapa de alterações" para
revisões, auditoria e para orientar a integração em ambientes de produção.

Estrutura do repositório afetada
--------------------------------
- monitor-integridade/
- analisador-logs-identificacao/
- tests/
- .github/workflows/ci.yml
- requirements.txt
- .pre-commit-config.yaml

Alterações por componente
-------------------------

1) monitor-integridade (monitor-integridade-ficheiros.py)
  - Criado `monitor-integridade/monitor-integridade-ficheiros.py` como implementação principal
    do monitor de integridade de ficheiros.
  - Funcionalidades:
    * Scanning recursivo do diretório especificado e cálculo de SHA-256 por ficheiro (leitura em chunks).
    * Geração de um baseline em JSON (por omissão: `.integrity_hashes.json`).
    * Modo `--init` para gerar baseline, modo one-shot para comparar e modo `--watch` para vigiar periodicamente.
    * Comparação que deteta ficheiros `added`, `removed` e `changed`.
    * Logging com níveis (INFO/DEBUG/WARNING) controlados por `-v`/`-vv`.
  - Melhorias adicionais (seguindo requisitos de segurança):
    * Suporte a assinatura HMAC do ficheiro de baseline: `--key-file` ou via `INTEGRITY_DB_KEY` ou arquivo `.integrity_db_key`.
      - Funções: `save_signed_hash_db`, `verify_signed_db`, `compute_hmac`.
    * Notificações: envio via webhook (`--webhook-url`) e via SMTP (`--smtp-server`, `--smtp-from`, `--smtp-to`).
    * Suporte opcional a `inotify` (`--use-inotify`) para vigilância baseada em eventos, com fallback para polling.
  - Compatibilidade:
    * Suporta o formato legacy (JSON com `files`) e o novo wrapper assinado ({payload, hmac}).

2) Shim de compatibilidade
  - O ficheiro original `Home Lab de Monitorização/monitor-integridade-ficheiros.py` foi substituído por um shim
    que reencaminha a execução para o novo local (`monitor-integridade/monitor-integridade-ficheiros.py`) para compatibilidade
    com scripts ou documentações antigas.

3) testes (pytest)
  - `tests/test_monitor_integridade.py` atualizado para cobrir:
    * Criação de baseline (arquivo JSON)
    * Deteção de ficheiro alterado
    * Deteção de ficheiro novo e removido
    * Testes de baseline assinado (criação) e rejeição quando HMAC inválido (código de saída 4)
  - Novos testes para o analisador de logs:
    * `tests/test_analisador_logs.py` — valida processamento de `auth.log`, extração de IPs, threshold e geração de CSV.
    * `tests/test_analisador_logs_webhook.py` — inicia um servidor HTTP local e valida o payload JSON enviado pelo `--webhook`.
    * Adicionado teste que valida suporte a ficheiros `.gz` e pattern/glob (múltiplos ficheiros rotacionados).

4) analisador-logs-identificacao
  - Criado `analisador-logs-identificacao/analisador-logs.sh` (script bash profissional):
    * Analisa `auth.log` e ficheiros rotacionados (`.gz`) via `--log-pattern` (glob) ou `--log-file`.
    * Extrai endereços IPv4 e IPv6 das linhas de falha (padrões: "Failed password", "Invalid user", "authentication failure").
    * Agrupa e conta ocorrências; gera CSV `IP,contagem` filtrando por `--threshold`.
    * Notificações: `--webhook` (POST JSON) e `--email FROM:TO` (envia via `sendmail`).
    * Suporte a execução periódica via systemd timer ou cron (exemplos no README).
    * Produzido com práticas seguras: `set -euo pipefail`, traps para temporários, leitura segura de `.gz` via `gzip -dc`.
  - README atualizado com exemplos `systemd` timer e `cron`, e instruções de uso (inclui notificações e padrão glob).

5) CI e Quality
  - Adicionado `requirements.txt` com dev dependencies: `pytest`, `pre-commit`, `ruff`, `black`, `inotify_simple`.
  - Adicionado `.pre-commit-config.yaml` com hooks `black` e `ruff`.
  - Atualizado `.github/workflows/ci.yml` para:
    * Instalar dependências: `pip install -r requirements.txt`.
    * Rodar `black --check .` e `ruff check .` antes dos testes.
    * Rodar `pytest -q` para executar toda a suite (inclui testes do webhook).

6) Formatação / Linters
  - Executados `ruff` e `black` localmente para manter padrão de código e estilo.
  - Corrigidos imports não usados e formatados ficheiros Python relevantes.

Observações sobre segurança e operação
------------------------------------
- A HMAC key não deve ser comitada. Preferir um secret manager ou ficheiro com permissões restritas.
- Em produção, proteja os ficheiros `report*` e o DB de hashes; considere armazenar a DB em local só leitura e/ou assiná-la com chave assimétrica.
- Para integração com SIEM/EDR/Triggering: envie sempre os relatórios para um colector central e configure retenção e alertas.
- O `analisador-logs.sh` usa `sendmail` sem autenticação por simplicidade — para SMTP autenticado, implementar envio via Python que suporte TLS/LOGIN.

Como reproduzir localmente
-------------------------
1. Instale dependências (ambiente dev):
   python3 -m pip install -r requirements.txt

2. Rodar testes:
   pytest -q

3. Executar monitor_integridade:
   python3 monitor-integridade/monitor-integridade-ficheiros.py --path /caminho --init

4. Executar analisador de logs (exemplo):
   ./analisador-logs-identificacao/analisador-logs.sh --log-pattern '/var/log/auth.log*' --threshold 5 --output /tmp/report.csv

Ficheiros criados/alterados (lista resumida)
-------------------------------------------
- monitor-integridade/monitor-integridade-ficheiros.py (novo)
- monitor-integridade/README.md (novo)
- Home Lab de Monitorização/monitor-integridade-ficheiros.py (shim)
- analisador-logs-identificacao/analisador-logs.sh (novo)
- analisador-logs-identificacao/README.md (atualizado)
- tests/test_monitor_integridade.py (atualizado)
- tests/test_analisador_logs.py (novo)
- tests/test_analisador_logs_webhook.py (novo)
- .github/workflows/ci.yml (atualizado)
- requirements.txt (novo)
- .pre-commit-config.yaml (novo)
- CHANGES.md (este ficheiro)

Se quiser, posso também gerar um `CHANGELOG` formal (com formato semântico) ou preparar um branch/PR com estas alterações pronto para revisão.

Fim do documento.
