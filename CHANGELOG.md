Keep a Changelog
=================

Todas as mudanças notáveis neste projeto serão documentadas neste ficheiro.

Formato
------
Seguindo o formato "Keep a Changelog" e versionamento semântico. As entradas estão ordenadas por data,
com a secção `Unreleased` no topo para alterações que ainda não foram lançadas.

Unreleased
----------
- Adicionado monitor de integridade de ficheiros em Python com suporte a:
  - Geração de baseline SHA-256;
  - Assinatura HMAC do ficheiro de baseline (verificação e geração);
  - Notificações via webhook e via SMTP (opcional);
  - Modo `--init`, modo one-shot e modo `--watch` com polling e suporte opcional a `inotify`.
- Adicionado analisador de logs de autenticação em Bash (`analisador-logs-identificacao`) com:
  - Suporte a ficheiros rotacionados `.gz` e glob patterns;
  - Extração de IPv4/IPv6 e agregação por contagem;
  - Geração de CSV e opções de notificação (webhook/email).
- Adicionados testes automatizados (`pytest`) cobrindo monitor de integridade e o analisador de logs,
  incluindo um teste que valida envio de payloads webhook.
- Adicionados ficheiros de qualidade/CI: `requirements.txt`, `.pre-commit-config.yaml` e `.github/workflows/ci.yml`.
- Adicionado `CHANGES.md` com resumo detalhado das alterações.

v0.1.0 - 2026-01-12
-------------------
Primeiro lançamento que inclui as funcionalidades listadas em `Unreleased` e representa uma baseline
funcional para monitorização local de integridade e análise de logs de autenticação.

Detalhes principais:

- Monitor de integridade (Python)
  - `monitor-integridade/monitor-integridade-ficheiros.py` — scanner recursivo, baseline JSON, HMAC-signed DB,
    comparação de estados (added/removed/changed) e notificações.
  - Shim de compatibilidade mantido em `Home Lab de Monitorização/monitor-integridade-ficheiros.py`.

- Analisador de logs (Bash)
  - `analisador-logs-identificacao/analisador-logs.sh` — script compatível com logs rotacionados e `.gz`, produz CSV
    e suporta webhook/email.

- Testes e CI
  - `tests/` contém testes do monitor e do analisador; GitHub Actions roda `black --check`, `ruff` e `pytest`.

Notas de segurança e operação
----------------------------
- A chave HMAC NÃO deve ser comprometida. Use um gestor de segredos em produção e restrinja permissões do ficheiro de chave.
- Para SMTP autenticado ou envio seguro de emails, considere implementar envio via Python com STARTTLS e autenticação.
- Revisões futuras: suporte a chaves assimétricas para assinatura de DB, integração com SIEM/EDR e políticas de bloqueio automáticas (fail2ban integration).

Créditos
--------
Desenvolvido por contribuições nesta sessão. Veja o PR associado para detalhes de commits e revisão: https://github.com/TaTTA-23/cybersecurity-training/pull/1
