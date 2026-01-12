Exemplo systemd timer (cria serviço que executa o script a cada 10 minutos):

1) Crie `/etc/systemd/system/analisador-logs.service`:

```
[Unit]
Description=Analisador de logs de autenticação

[Service]
Type=oneshot
ExecStart=/opt/analisador/analisador-logs.sh --log-pattern /var/log/auth.log* --threshold 5 --output /var/log/reports/ssh_bruteforce_report.csv
```

2) Crie `/etc/systemd/system/analisador-logs.timer`:

```
[Unit]
Description=Executa analisador-logs a cada 10 minutos

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
```

3) Ative:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now analisador-logs.timer
```

Exemplo cron (executa a cada 5 minutos):

```cron
*/5 * * * * /opt/analisador/analisador-logs.sh --log-pattern /var/log/auth.log* --threshold 5 --output /var/log/reports/ssh_bruteforce_report.csv
```
Notas de segurança:
 - Execute como root ou com permissões para ler `/var/log/auth.log`.
 - Para integração em produção, envie o relatório a um SIEM ou pipeline de alertas.
# Analisador de Logs de Autenticação

Script Bash que analisa um ficheiro de logs (por omissão `/var/log/auth.log`) e gera
um relatório com os IPs que terão efectuado mais de N tentativas falhadas de login via SSH.

Uso exemplo:

```bash
./analisador-logs.sh --log-file /var/log/auth.log --threshold 5 --output report.txt
```

O script procura por padrões comuns de falha (ex.: "Failed password", "Invalid user")
e extrai os endereços IPv4 e IPv6, sumarizando as ocorrências. Suporta também ficheiros
rotacionados comprimidos (`.gz`).

Opções principais:

- `--webhook URL` — envia o relatório para uma URL (POST). Requer `curl`.
- `--email FROM:TO` — envia o relatório por e-mail usando `sendmail` (TO pode ser vírgula-separado).

Exemplo com notificações:

```bash
./analisador-logs.sh --log-file /var/log/auth.log --threshold 5 --output report.txt --webhook https://meu/hook --email alerta@example.com:ops@example.com
```

Nota: para integração em produção, combine com um timer systemd ou cron e centralize os relatórios no SIEM.

Notas de segurança:
- Execute como root ou com permissões para ler `/var/log/auth.log`.
- Para integração em produção, envie o relatório a um SIEM ou pipeline de alertas.
