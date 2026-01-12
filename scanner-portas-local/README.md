# Scanner de Portas Local

Este pequeno utilitário detecta portas TCP abertas em localhost e compara com uma lista permitida.

Como usar
---------
1. Crie um ficheiro `allowed_ports.txt` no mesmo diretório (ou indique outro via `--allowed-file`) com uma porta por linha. Exemplo:

```
# portas permitidas
22
80
443
3306
```

2. Execute o scanner (varre por defeito as portas 1-1024):

```bash
python3 scanner-portas-local/scanner_portas_local.py --allowed-file allowed_ports.txt
```

3. Para variar o intervalo de portas ou especificar portas individuais:

```bash
python3 scanner-portas-local/scanner_portas_local.py --ports 22,80,8080-8090 --allowed-file allowed_ports.txt
```

Como isto ajuda na conformidade (ex: ISO 27001)
-----------------------------------------------
- Inventário e controlo de activos: Ajuda a identificar serviços em execução (activos) na infraestrutura local.
- Gestão de configuração: Detectar portas inesperadas permite aplicar controles (fechar firewall, desabilitar serviço) e manter a configuração em conformidade com políticas de segurança.
- Monitorização e deteção de incidentes: Avisos sobre portas não autorizadas suportam detecção precoce de atividade maliciosa ou configuração errada.
- Evidência e auditoria: Relatórios periódicos do scanner podem ser guardados como evidência de actividades de controlo operacional, um requisito comum em auditorias ISO 27001.

Notas
-----
- O scanner faz varredura TCP em `127.0.0.1`. Para detectar serviços ligados apenas a interfaces externas, ajuste `--host` para 0.0.0.0 ou o IP relevante, ou execute varredura de rede específica.
- Use com permissões adequadas; scans intensivos em intervalos grandes podem causar carga na máquina.

Execução periódica (systemd)
----------------------------
Exemplo de instalação rápida para correr periodicamente usando systemd (requer privilégios de root):

1. Instalar o script Python e o wrapper em locais padrão:

```bash
sudo mkdir -p /usr/local/lib/scanner-portas-local
sudo cp scanner-portas-local/scanner_portas_local.py /usr/local/lib/scanner-portas-local/
sudo cp scanner-portas-local/run_scan.sh /usr/local/bin/scanner-portas-local-run.sh
sudo chmod +x /usr/local/bin/scanner-portas-local-run.sh
```

2. Criar a pasta de configuração e o ficheiro de portas permitidas:

```bash
sudo mkdir -p /etc/scanner-portas-local
sudo cp scanner-portas-local/allowed_ports.txt /etc/scanner-portas-local/allowed_ports.txt 2>/dev/null || true
# edite /etc/scanner-portas-local/allowed_ports.txt conforme a política
sudo mkdir -p /var/log/scanner-portas-local
sudo chown root:root /var/log/scanner-portas-local
```

3. Instalar as units systemd (os ficheiros de exemplo estão em `scanner-portas-local/`):

```bash
sudo cp scanner-portas-local/scanner-portas-local.service /etc/systemd/system/
sudo cp scanner-portas-local/scanner-portas-local.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scanner-portas-local.timer
```

Isto criará um `timer` que executa a unit `scanner-portas-local.service` uma vez por hora (ajustável em `scanner-portas-local.timer`).

Exemplo cron
------------
Se preferir usar `cron` em vez do `systemd`, adicione uma entrada no crontab do root:

```cron
# Executa diariamente às 03:00
0 3 * * * /usr/local/bin/scanner-portas-local-run.sh
```

Logs e auditoria
---------------
Os resultados das execuções são guardados em `/var/log/scanner-portas-local/` como ficheiros timestamped e `last_scan.txt` aponta para a última execução. Arquive estes ficheiros ou transporte-os para um servidor de logs para fins de auditoria.
