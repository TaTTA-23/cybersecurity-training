#!/usr/bin/env bash
# analisador-logs.sh
#
# Script profissional e testável para analisar ficheiros de logs de autenticação
# e gerar um relatório com IPs (IPv4/IPv6) que tenham excedido um limiar de
# tentativas falhadas de autenticação SSH.
#
# Funcionalidades adicionadas:
# - Suporte a ficheiros .gz (logs rotacionados)
# - Extração de IPv4 e IPv6
# - Opções de notificação: webhook (curl) e e-mail (sendmail)
# - Saída CSV no formato: IP,contagem
#
set -euo pipefail

LOG_PATTERN="/var/log/auth.log*"
THRESHOLD=5
OUTPUT="report_auth_failures.txt"
WEBHOOK_URL=""
EMAIL_FROM=""
EMAIL_TO=""

print_usage() {
  cat <<EOF
Usage: $0 [--log-file PATH] [--threshold N] [--output PATH] [--webhook URL] [--email from:to]

Analisa um ficheiro de logs de autenticação (padrão: /var/log/auth.log) e
exporta um relatório CSV com os IPs que tiveram mais de N tentativas falhadas de SSH.

Options:
  --log-file PATH   (deprecated) Caminho para um ficheiro de logs (use --log-pattern para múltiplos). Aceita .gz
  --log-pattern PATTERN  Padrão de ficheiros a analisar (glob), ex: '/var/log/auth.log*' (padrão)
  --threshold N     Número mínimo de tentativas para reportar (padrão: 5)
  --output PATH     Ficheiro de saída (padrão: report_auth_failures.txt)
  --webhook URL     URL para enviar JSON com o relatório (opcional)
  --email FROM:TO   Envia relatório por e-mail usando sendmail (opcional). TO pode ser vírgula-separado
  --help            Mostrar esta ajuda
EOF
}

parse_email_arg() {
  IFS=":" read -r from to <<<"$1"
  EMAIL_FROM="$from"
  EMAIL_TO="$to"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --log-file)
      LOG_PATTERN="$2"; shift 2;;
    --log-pattern)
      LOG_PATTERN="$2"; shift 2;;
    --threshold)
      THRESHOLD="$2"; shift 2;;
    --output)
      OUTPUT="$2"; shift 2;;
    --webhook)
      WEBHOOK_URL="$2"; shift 2;;
    --email)
      parse_email_arg "$2"; shift 2;;
    --help)
      print_usage; exit 0;;
    *)
      echo "Parâmetro desconhecido: $1" >&2; print_usage; exit 2;;
  esac
done


# Resolve lista de ficheiros a partir do padrão
shopt -s nullglob
FILES=( $LOG_PATTERN )
shopt -u nullglob
if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "Nenhum ficheiro encontrado para o padrão: $LOG_PATTERN" >&2
  exit 3
fi

# Cria função para ler o ficheiro, suportando .gz
read_log() {
  local file="$1"
  if [[ "$file" == *.gz ]]; then
    if command -v gzip >/dev/null 2>&1; then
      gzip -dc -- "$file"
    else
      echo "gzip não encontrado para ler $file" >&2; return 1
    fi
  else
    cat -- "$file"
  fi
}

# Regex melhoradas para IPv4 e IPv6
# IPv4: 4 grupos de 1-3 dígitos
# IPv6: padrão simplificado que cobre casos comuns em logs SSH
RE_IPV4='[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
RE_IPV6='[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){0,6}'

# Função para extrair IPs de uma linha
extract_ips() {
    local line="$1"
    local ips=""
    # Extrai IPv4
    while [[ $line =~ $RE_IPV4 ]]; do
        ips+="${BASH_REMATCH[0]}"$'\n'
        line="${line/${BASH_REMATCH[0]}/X}"
    done
    # Extrai IPv6
    while [[ $line =~ $RE_IPV6 ]]; do
        ips+="${BASH_REMATCH[0]}"$'\n'
        line="${line/${BASH_REMATCH[0]}/X}"
    done
    echo "$ips"
}

TMP=$(mktemp)
SORTED=$(mktemp)
trap 'rm -f "$TMP" "$SORTED"' EXIT

# Filtra linhas de falha SSH e extrai IPs
for f in "${FILES[@]}"; do
  while IFS= read -r line; do
    extract_ips "$line" >> "$TMP"
  done < <(read_log "$f" | grep -iE "Failed password|Invalid user|authentication failure") || true
done

# Agrupa e conta ocorrências de todos os ficheiros
sort "$TMP" | uniq -c | sort -rn > "$SORTED"

# Gerar relatório CSV (IP,contagem) com threshold
{
  echo "Relatório de tentativas falhadas de SSH"
  echo "Gerado em: $(date -u +'%Y-%m-%d %H:%M:%SZ')"
  if [[ ${#FILES[@]} -gt 0 ]]; then
    echo -n "Fonte(s): "
    printf "%s " "${FILES[@]}"
    echo
  else
    echo "Fonte(s): $LOG_PATTERN"
  fi
  echo "Limite mínimo para reportar: $THRESHOLD"
  echo
  echo "IP,contagem"
  awk -v th="$THRESHOLD" '{ if ($1+0 > th) print $2","$1 }' "$SORTED"
} > "$OUTPUT"

echo "Relatório gerado: $OUTPUT"

# Notificações: webhook (JSON) e email via sendmail
if [[ -n "$WEBHOOK_URL" ]]; then
  if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    # Monta um JSON seguro usando python (evita depender de jq)
    # payload: { timestamp, sources: [...], report_lines: ["IP,contagem", ...] }
    json_payload=$(python3 - "$OUTPUT" "${FILES[@]}" "$LOG_PATTERN" <<'PY'
import json,sys
out=sys.argv[1]
files=sys.argv[2:-1]
pattern=sys.argv[-1]
lines=open(out,encoding='utf-8').read().splitlines()
data={'timestamp': __import__('datetime').datetime.utcnow().isoformat()+'Z', 'sources': files if files else [pattern], 'report_lines': lines[lines.index('IP,contagem')+1:] if 'IP,contagem' in lines else []}
print(json.dumps(data))
PY
)
    curl -s -X POST -H "Content-Type: application/json" -d "$json_payload" "$WEBHOOK_URL" || echo "Falha ao enviar webhook" >&2
  else
    echo "curl ou python3 não disponíveis; não foi possível enviar webhook" >&2
  fi
fi

if [[ -n "$EMAIL_FROM" && -n "$EMAIL_TO" ]]; then
  if command -v sendmail >/dev/null 2>&1; then
    SUBJECT="Alerta: tentativas falhadas SSH em $(hostname)"
    {
      echo "From: $EMAIL_FROM"
      echo "To: $EMAIL_TO"
      echo "Subject: $SUBJECT"
      echo
      cat "$OUTPUT"
    } | sendmail -t
  else
    echo "sendmail não encontrado; não foi possível enviar e-mail" >&2
  fi
fi

exit 0
