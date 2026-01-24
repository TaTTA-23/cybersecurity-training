# Plano de Melhorias - Cybersecurity Training

## Tarefas Executadas

### 1. scanner-portas-local/scanner_portas_local.py
- [x] Timeout corrigido para 0.3s e argumento configurável

### 2. analisador-logs-identificacao/analisador-logs.sh
- [x] Regex IPv4 melhorada (valida 1-3 dígitos por octeto)
- [x] Regex IPv6 melhorada
- [x] Unificada extração de IPs numa função `extract_ips()`

### 3. monitor-integridade/monitor-integridade-ficheiros.py
- [x] Removidos ~110 linhas de código duplicado no final do arquivo

## Verificação
- [x] Análise completa dos 3 scripts
- [x] Correção scanner_portas_local.py
- [x] Correção analisador-logs.sh
- [x] Correção monitor-integridade-ficheiros.py
- [x] **12/12 testes passaram** ✅

