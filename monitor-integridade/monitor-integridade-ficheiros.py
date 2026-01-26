#!/usr/bin/env python3
"""
monitor-integridade-ficheiros.py

Script simples de monitorização de integridade de ficheiros.

Funcionalidades:
- Gera hashes SHA-256 de todos os ficheiros num diretório (recursivo).
- Guarda um baseline em JSON (por omissão: .integrity_hashes.json no diretório monitorizado).
- Compara periodicamente o estado atual com o baseline e alerta sobre:
  * ficheiros alterados
  * ficheiros novos
  * ficheiros removidos

Uso (exemplos):
  python monitor-integridade-ficheiros.py --path /etc --init
  python monitor-integridade-ficheiros.py --path /etc --watch --interval 10

Feito em pt-BR. Mensagens e comentários em português para treino/educação.
"""

import argparse
import hashlib
import hmac
import json
import logging
import os
import smtplib
import time
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, Iterable, Optional


HASH_DB_FILENAME = ".integrity_hashes.json"
CHUNK_SIZE = 8192

# Nome do ficheiro onde, opcionalmente, armazenamos a chave HMAC localmente
DEFAULT_KEY_FILENAME = ".integrity_db_key"


def compute_sha256(path: Path) -> str:
    """Compute SHA-256 for a file reading in chunks."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_directory(base_path: Path, exclude: set[str] | None = None) -> Dict[str, str]:
    """Return mapping relative_path -> sha256 for all regular files under base_path.

    relative paths are used as keys so the hash DB can move with the directory.
    """
    exclude = exclude or set()
    result: Dict[str, str] = {}
    for root, dirs, files in os.walk(base_path):
        for fname in files:
            full = Path(root) / fname
            rel = os.path.relpath(full, base_path)
            if rel in exclude:
                continue
            try:
                if not full.is_file():
                    continue
                result[rel] = compute_sha256(full)
            except (PermissionError, OSError) as e:
                logging.warning("Não foi possível ler %s: %s", full, e)
    return result


def compute_hmac(key: bytes, data: bytes) -> str:
    """Return hex HMAC-SHA256 for data."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def load_key_from_file(path: Path) -> Optional[bytes]:
    try:
        return path.read_bytes().strip()
    except OSError:
        return None


def get_signing_key(base_path: Path, key_file: Optional[str]) -> Optional[bytes]:
    # Priority: explicit key_file -> env INTEGRITY_DB_KEY -> default key file in base_path
    if key_file:
        p = Path(key_file)
        k = load_key_from_file(p)
        if k:
            return k
    env = os.getenv("INTEGRITY_DB_KEY")
    if env:
        return env.encode()
    default = base_path / DEFAULT_KEY_FILENAME
    return load_key_from_file(default)


def save_hash_db(
    base_path: Path, db: Dict[str, str], filename: str = HASH_DB_FILENAME
) -> None:
    out = base_path / filename
    tmp = out.with_suffix(".tmp")
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "files": db,
    }
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    tmp.replace(out)


def save_signed_hash_db(
    base_path: Path, db: Dict[str, str], key: bytes, filename: str = HASH_DB_FILENAME
) -> None:
    """Salva DB incluindo HMAC para proteger contra adulteração do ficheiro de baseline."""
    out = base_path / filename
    tmp = out.with_suffix(".tmp")
    payload = {"generated_at": datetime.utcnow().isoformat() + "Z", "files": db}
    raw = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    tag = compute_hmac(key, raw)
    wrapper = {"payload": payload, "hmac": tag}
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(wrapper, f, indent=2, ensure_ascii=False)
    tmp.replace(out)


def load_hash_db(
    base_path: Path, filename: str = HASH_DB_FILENAME
) -> Dict[str, str] | None:
    fpath = base_path / filename
    if not fpath.exists():
        return None
    try:
        with fpath.open("r", encoding="utf-8") as f:
            payload = json.load(f)
            # Support legacy format (files top-level) and signed wrapper format
            if "files" in payload and isinstance(payload.get("files"), dict):
                return payload.get("files")
            if "payload" in payload and "hmac" in payload:
                # return raw payload; caller may verify separately
                inner = payload.get("payload")
                if isinstance(inner, dict) and isinstance(inner.get("files"), dict):
                    return inner.get("files")
    except (OSError, json.JSONDecodeError) as e:
        logging.error("Erro ao carregar DB de hashes %s: %s", fpath, e)
    return None


def verify_signed_db(base_path: Path, filename: str, key: bytes) -> bool:
    """Verifica HMAC do ficheiro de DB; retorna True se válido."""
    fpath = base_path / filename
    try:
        with fpath.open("r", encoding="utf-8") as f:
            wrapper = json.load(f)
            tag = wrapper.get("hmac")
            payload = wrapper.get("payload")
            if not tag or not payload:
                return False
            raw = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
            calc = compute_hmac(key, raw)
            return hmac.compare_digest(calc, tag)
    except Exception:
        return False


def send_webhook(url: str, data: dict, timeout: int = 5) -> None:
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            logging.debug("Webhook response: %s", resp.read(200))
    except Exception as e:
        logging.error("Erro ao enviar webhook: %s", e)


def send_email(
    smtp_server: str,
    smtp_port: int,
    from_addr: str,
    to_addrs: Iterable[str],
    subject: str,
    body: str,
) -> None:
    try:
        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as s:
            s.send_message(msg)
        logging.info("E-mail enviado para %s", to_addrs)
    except Exception as e:
        logging.error("Erro ao enviar e-mail: %s", e)


def compare_hashes(old: Dict[str, str], new: Dict[str, str]) -> Dict[str, list[str]]:
    """Compare two maps and return lists of added/removed/changed files."""
    old_set = set(old.keys())
    new_set = set(new.keys())
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    changed = []
    for key in sorted(old_set & new_set):
        if old[key] != new[key]:
            changed.append(key)
    return {"added": added, "removed": removed, "changed": changed}


def human_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def alert_report(
    base_path: Path,
    diffs: Dict[str, list[str]],
    old: Dict[str, str],
    new: Dict[str, str],
) -> None:
    now = human_ts()
    if not any(diffs.values()):
        logging.debug("%s - Sem alterações detectadas.", now)
        return

    if diffs["added"]:
        logging.warning(
            "%s - Ficheiros NOVOS detectados: %s", now, ", ".join(diffs["added"])
        )
    if diffs["removed"]:
        logging.warning(
            "%s - Ficheiros REMOVIDOS detectados: %s", now, ", ".join(diffs["removed"])
        )
    if diffs["changed"]:
        logging.warning(
            "%s - Ficheiros ALTERADOS detectados: %s", now, ", ".join(diffs["changed"])
        )

    # For changed files print previous and current short-hashes for debugging
    for k in diffs["changed"]:
        logging.info(
            "%s - ALTERADO: %s\n  antigo: %s\n  novo:   %s",
            now,
            k,
            old.get(k),
            new.get(k),
        )


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor de integridade de ficheiros (SHA-256)"
    )
    p.add_argument("--path", "-p", required=True, help="Diretório a monitorizar")
    p.add_argument(
        "--init", action="store_true", help="Criar baseline (arquivo de hashes) e sair"
    )
    p.add_argument(
        "--watch",
        action="store_true",
        help="Executar em loop e verificar periodicamente",
    )
    p.add_argument(
        "--interval",
        "-i",
        type=int,
        default=10,
        help="Intervalo (segundos) entre verificações no modo --watch",
    )
    p.add_argument(
        "--db-file",
        default=HASH_DB_FILENAME,
        help="Nome do ficheiro de DB de hashes (relativo ao path)",
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Aumentar verbosidade (-v, -vv)",
    )
    p.add_argument(
        "--key-file",
        default=None,
        help="Ficheiro com a chave HMAC para assinar/verificar o baseline",
    )
    p.add_argument(
        "--webhook-url",
        default=None,
        help="URL para enviar JSON com alertas quando alterações forem detectadas",
    )
    p.add_argument(
        "--smtp-server",
        default=None,
        help="Servidor SMTP para envio de alertas por e-mail (host:port)",
    )
    p.add_argument(
        "--smtp-from", default=None, help="Endereço FROM para e-mails de alerta"
    )
    p.add_argument(
        "--smtp-to",
        default=None,
        help="Endereços TO para e-mails de alerta (vírgula separados)",
    )
    p.add_argument(
        "--use-inotify",
        action="store_true",
        help="Tentar usar inotify para vigiar alterações em tempo real (se disponível)",
    )
    return p


def configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s: %(message)s")


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    base = Path(args.path).resolve()
    if not base.exists() or not base.is_dir():
        print(f"Diretório inexistente: {base}")
        return 2

    configure_logging(args.verbose)

    dbfile = args.db_file

    # Exclude the DB file itself from scans (so it doesn't trigger changes)
    exclude = {dbfile}

    # Resolve signing key (if fornecida)
    key = get_signing_key(base, args.key_file)
    if args.init:
        logging.info("Gerando baseline de hashes em %s...", base)
        scan = scan_directory(base, exclude=exclude)
        if key:
            save_signed_hash_db(base, scan, key, filename=dbfile)
            print(
                f"Baseline assinado salvo em: {base / dbfile} ({len(scan)} ficheiros)"
            )
        else:
            save_hash_db(base, scan, filename=dbfile)
            print(f"Baseline salvo em: {base / dbfile} ({len(scan)} ficheiros)")
        return 0

    # Normal check: load DB and compare once, unless --watch is provided
    # If key is present, verify signature (if wrapped)
    if key:
        ok = verify_signed_db(base, dbfile, key)
        if not ok:
            print(
                f"Assinatura do ficheiro de baseline inválida ou ausente: {base / dbfile}"
            )
            return 4

    stored = load_hash_db(base, filename=dbfile)
    if stored is None:
        print(
            f"Nenhuma base de hashes encontrada em {base / dbfile}. Execute --init primeiro para criar a baseline."
        )
        return 3

    # Helper to send notifications if configured
    def notify_if_needed(diffs: Dict[str, list[str]]):
        if not any(diffs.values()):
            return
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "path": str(base),
            "diffs": diffs,
        }
        if getattr(args, "webhook_url", None):
            send_webhook(args.webhook_url, payload)
        if (
            getattr(args, "smtp_server", None)
            and getattr(args, "smtp_from", None)
            and getattr(args, "smtp_to", None)
        ):
            hostport = args.smtp_server.split(":")
            host = hostport[0]
            port = int(hostport[1]) if len(hostport) > 1 else 25
            to_addrs = [s.strip() for s in args.smtp_to.split(",") if s.strip()]
            subject = f"Alerta de integridade: alterações detectadas em {base}"
            body = json.dumps(payload, indent=2, ensure_ascii=False)
            send_email(host, port, args.smtp_from, to_addrs, subject, body)

    def single_check() -> Dict[str, list[str]]:
        current = scan_directory(base, exclude=exclude)
        diffs = compare_hashes(stored, current)
        alert_report(base, diffs, stored, current)
        notify_if_needed(diffs)
        return diffs

    diffs = single_check()

    if args.watch:
        print(f"A vigiar {base} a cada {args.interval}s. Ctrl-C para parar.")
        # If user requested inotify try to use it (optional dependency)
        if args.use_inotify:
            try:
                from inotify_simple import INotify, flags

                inotify = INotify()
                watch_flags = (
                    flags.CREATE
                    | flags.MODIFY
                    | flags.DELETE
                    | flags.MOVED_FROM
                    | flags.MOVED_TO
                )
                # Add watches for existing directories (simple recursive setup)
                for root, dirs, _ in os.walk(base):
                    try:
                        inotify.add_watch(root, watch_flags)
                    except Exception:
                        logging.debug("Não foi possível adicionar watch a %s", root)
                print("Usando inotify para detetar alterações (onde disponível)")
                try:
                    while True:
                        for event in inotify.read(timeout=1000):
                            # Em qualquer evento, executa uma verificação completa
                            diffs = single_check()
                except KeyboardInterrupt:
                    print("Monitor interrompido pelo utilizador.")
                    return 0
            except Exception:
                logging.warning("inotify não disponível, a usar polling com intervalo")

        try:
            while True:
                time.sleep(args.interval)
                diffs = single_check()
        except KeyboardInterrupt:
            print("Monitor interrompido pelo utilizador.")
            return 0

    # Return 0 when no differences, 1 if any detected
    if any(diffs.values()):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
