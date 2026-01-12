#!/usr/bin/env python3
"""
Scanner de Portas Local (TCP)

Varre portas TCP no localhost e compara as portas abertas com uma "lista permitida".
Se alguma porta aberta não estiver na lista permitida, o script reporta como alerta.

Uso básico:
  python3 scanner-portas-local/scanner_portas_local.py --start 1 --end 1024 --allowed-file allowed.txt

O ficheiro `allowed.txt` deve conter uma porta por linha (ex: 22) ou linhas comentadas com `#`.

Saída: resumo no stdout; código de saída 0 se só houver portas permitidas, 1 se houver portas inesperadas.

Observações:
 - O scanner realiza tentativas de conexão TCP a 127.0.0.1. Nem todos os serviços podem responder em localhost
   (por exemplo, serviços ligados apenas a interfaces externas) — ajuste conforme necessário.
 - Executar com privilégios apropriados para garantir visibilidade das portas locais.
"""
import argparse
import concurrent.futures
import socket
import sys
from pathlib import Path
from typing import Iterable, Set, Tuple

# Tentativa de import opcional de psutil para ligar portas a processos
try:
    import psutil

    HAVE_PSUTIL = True
except Exception:  # pragma: no cover - import guard
    psutil = None  # type: ignore
    HAVE_PSUTIL = False


def parse_allowed_file(path: Path) -> Set[int]:
    """Lê o ficheiro de portas permitidas e retorna um set de inteiros.

    Linhas vazias e linhas começadas com `#` são ignoradas. Qualquer número inválido será ignorado
    com um aviso.
    """
    allowed: Set[int] = set()
    if not path.exists():
        return allowed
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        # permitir entradas como "ssh=22" ou "22" ou "service/22"
        for token in [part for part in line.replace('=', '/').split('/') if part]:
            try:
                port = int(token)
                if 0 < port <= 65535:
                    allowed.add(port)
                    break
            except ValueError:
                continue
        else:
            print(f"Aviso: não foi possível parsear a linha permissões: '{raw}'", file=sys.stderr)
    return allowed


def build_port_list(start: int, end: int, ports: Iterable[int] | None) -> list[int]:
    if ports:
        # remove duplicados e ordena
        p = sorted(set(ports))
        return [x for x in p if 0 < x <= 65535]
    # range inclusive
    if start > end:
        start, end = end, start
    return list(range(max(1, start), min(65535, end) + 1))


def scan_port(host: str, port: int, timeout: float = 0.3) -> bool:
    """Tenta conectar via TCP ao par (host, port). Retorna True se a porta estiver aberta (accept connection).

    Usamos connect_ex com timeout curto para ser robusto e rápido.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0
    except OSError:
        return False


def concurrent_scan(host: str, ports: Iterable[int], timeout: float, workers: int = 200) -> list[int]:
    open_ports: list[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port = futures[fut]
            try:
                if fut.result():
                    open_ports.append(port)
            except Exception as e:
                print(f"Erro ao verificar porta {port}: {e}", file=sys.stderr)
    return sorted(open_ports)


def identify_processes_for_ports(ports: Iterable[int], host: str) -> dict[int, tuple[int, str]]:
    """Se `psutil` estiver disponível, tenta mapear portas para (pid, process_name).

    Retorna um dicionário port -> (pid, process_name). Se não for possível identificar,
    a porta não aparecerá no dicionário.
    """
    mapping: dict[int, tuple[int, str]] = {}
    if not HAVE_PSUTIL:
        return mapping

    try:
        # psutil.net_connections pode requerer privilégios para ver todas as ligações.
        conns = psutil.net_connections(kind='inet')
    except Exception:
        return mapping

    ports_set = set(ports)
    for c in conns:
        # c.laddr é (ip, port)
        try:
            laddr = c.laddr
            if not laddr:
                continue
            port = getattr(laddr, 'port', None) if hasattr(laddr, 'port') else laddr[1]
            if port in ports_set and c.status in ('LISTEN', psutil.CONN_LISTEN if hasattr(psutil, 'CONN_LISTEN') else 'LISTEN'):
                pid = c.pid or 0
                proc_name = ''
                try:
                    if pid:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                except Exception:
                    proc_name = ''
                mapping[port] = (pid or 0, proc_name or '')
        except Exception:
            continue

    return mapping


def parse_ports_list(ports_str: str) -> list[int]:
    """Parses comma separated ports and ranges like 22,80,8000-8100"""
    res: Set[int] = set()
    for part in ports_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            try:
                a_i = int(a); b_i = int(b)
                if a_i > b_i:
                    a_i, b_i = b_i, a_i
                for p in range(max(1, a_i), min(65535, b_i) + 1):
                    res.add(p)
            except ValueError:
                print(f"Aviso: intervalo inválido '{part}' ignorado", file=sys.stderr)
        else:
            try:
                res.add(int(part))
            except ValueError:
                print(f"Aviso: porta inválida '{part}' ignorada", file=sys.stderr)
    return sorted(res)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Scanner de portas local e comparador com lista permitida")
    p.add_argument('--start', type=int, default=1, help='Porta inicial do intervalo (inclusivo)')
    p.add_argument('--end', type=int, default=1024, help='Porta final do intervalo (inclusivo)')
    p.add_argument('--ports', type=str, default='', help='Lista de portas/intervalos (ex: 22,80,8000-8100)')
    p.add_argument('--allowed-file', type=Path, default=Path('allowed_ports.txt'), help='Ficheiro com portas permitidas')
    p.add_argument('--host', type=str, default='127.0.0.1', help='Host a usar para a varredura (por defeito: localhost)')
    p.add_argument('--timeout', type=float, default=0.25, help='Timeout por tentativa de conexão (segundos)')
    p.add_argument('--workers', type=int, default=200, help='Número de workers para varredura concorrente')
    p.add_argument('--identify-processes', action='store_true', help='Tentar identificar PID/processo associado a portas (psutil)')
    args = p.parse_args(argv)

    ports_specified = parse_ports_list(args.ports) if args.ports else None
    ports = build_port_list(args.start, args.end, ports_specified)

    allowed = parse_allowed_file(args.allowed_file)

    print(f"Varredura em {args.host} para {len(ports)} portas (timeout={args.timeout}s)...")
    open_ports = concurrent_scan(args.host, ports, args.timeout, workers=args.workers)

    if not open_ports:
        print("Nenhuma porta aberta encontrada no intervalo consultado.")
        return 0

    print("Portas abertas encontradas:")

    proc_map: dict[int, tuple[int, str]] = {}
    if args.identify_processes:
        if not HAVE_PSUTIL:
            print("Aviso: psutil não disponível — não será possível identificar processos (instale 'psutil').", file=sys.stderr)
        else:
            proc_map = identify_processes_for_ports(open_ports, args.host)

    for port in open_ports:
        note = "(permitida)" if port in allowed else "(NÃO PERMITIDA)"
        if port in proc_map:
            pid, pname = proc_map[port]
            proc_info = f"[pid:{pid} name:{pname}]" if pname else f"[pid:{pid}]"
        else:
            proc_info = ""
        print(f"  - {port} {note} {proc_info}")

    unexpected = [p for p in open_ports if p not in allowed]
    if unexpected:
        print("\nALERTA: portas inesperadas detectadas! \nResumo:")
        for p in unexpected:
            if p in proc_map:
                pid, pname = proc_map[p]
                pname_str = f" ({pname})" if pname else ""
                print(f"  * Porta {p} está aberta e não consta na lista permitida — PID {pid}{pname_str}")
            else:
                print(f"  * Porta {p} está aberta e não consta na lista permitida")
        print("\nAções recomendadas: verificar serviço em execução, avaliar a necessidade de exposição dessa porta e atualizar a lista permitida se for legítima.")
        return 1

    print("Todas as portas abertas encontradas estão na lista permitida.")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
