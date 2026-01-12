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
