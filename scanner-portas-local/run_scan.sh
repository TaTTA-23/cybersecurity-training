#!/usr/bin/env bash
# Wrapper para executar o scanner de portas e guardar o resultado em /var/log
# Uso: o ficheiro pode ser chamado pelo systemd unit.

set -euo pipefail

# Valores por defeito (podem ser sobrepostos via Environment no systemd unit)
: ${ALLOWED_FILE:=/etc/scanner-portas-local/allowed_ports.txt}
: ${PY_SCRIPT:=/usr/local/lib/scanner-portas-local/scanner_portas_local.py}
: ${OUTPUT_DIR:=/var/log/scanner-portas-local}
: ${PORTS:="1-1024"}
: ${HOST:=127.0.0.1}
: ${IDENTIFY:="--identify-processes"}

mkdir -p "$OUTPUT_DIR"
timestamp=$(date +%Y%m%d-%H%M%S)
outfile="$OUTPUT_DIR/scan-$timestamp.txt"

if [ ! -f "$PY_SCRIPT" ]; then
  echo "Erro: script Python não encontrado em $PY_SCRIPT" >&2
  exit 2
fi

echo "Executando scanner de portas local em $HOST ($PORTS) — salvando em $outfile"

"/usr/bin/env" python3 "$PY_SCRIPT" --ports "$PORTS" --host "$HOST" --allowed-file "$ALLOWED_FILE" $IDENTIFY > "$outfile" 2>&1 || true

# Também atualizar um 'latest' para fácil consulta
ln -sf "$outfile" "$OUTPUT_DIR/last_scan.txt"

exit 0
