import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "analisador-logs-identificacao" / "analisador-logs.sh"


def run(args, **kwargs):
    cmd = [str(SCRIPT)] + args
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def test_detects_bruteforce_ips(tmp_path):
    # Criar ficheiro de log simulado
    content = """
Jan 12 10:00:00 host sshd[12345]: Failed password for invalid user admin from 192.0.2.1 port 22 ssh2
Jan 12 10:00:01 host sshd[12345]: Failed password for invalid user admin from 192.0.2.1 port 22 ssh2
Jan 12 10:00:02 host sshd[12345]: Failed password for invalid user admin from 192.0.2.1 port 22 ssh2
Jan 12 10:00:03 host sshd[12345]: Failed password for invalid user admin from 192.0.2.1 port 22 ssh2
Jan 12 10:00:04 host sshd[12345]: Failed password for invalid user admin from 192.0.2.1 port 22 ssh2
Jan 12 10:00:05 host sshd[12345]: Failed password for invalid user admin from 192.0.2.2 port 22 ssh2
Jan 12 10:00:06 host sshd[12345]: Failed password for invalid user admin from 192.0.2.2 port 22 ssh2
"""
    logf = tmp_path / "auth.log"
    logf.write_text(content)

    out = tmp_path / "report.csv"
    res = run(["--log-file", str(logf), "--threshold", "4", "--output", str(out)])
    assert res.returncode == 0
    assert out.exists()
    txt = out.read_text()
    # 192.0.2.1 has 5 attempts -> should appear
    assert "192.0.2.1,5" in txt
    # 192.0.2.2 has 2 attempts -> should not appear when threshold is 4
    assert "192.0.2.2" not in txt


def test_processes_gz_and_multiple_files(tmp_path):
    # cria dois ficheiros: um normal e outro .gz
    content1 = """
Jan 12 10:00:00 host sshd[1]: Failed password for invalid user admin from 198.51.100.1 port 22 ssh2
Jan 12 10:00:01 host sshd[1]: Failed password for invalid user admin from 198.51.100.1 port 22 ssh2
"""
    content2 = """
Jan 12 10:01:00 host sshd[2]: Failed password for invalid user admin from 198.51.100.2 port 22 ssh2
Jan 12 10:01:01 host sshd[2]: Failed password for invalid user admin from 198.51.100.2 port 22 ssh2
Jan 12 10:01:02 host sshd[2]: Failed password for invalid user admin from 198.51.100.2 port 22 ssh2
Jan 12 10:01:03 host sshd[2]: Failed password for invalid user admin from 198.51.100.2 port 22 ssh2
Jan 12 10:01:04 host sshd[2]: Failed password for invalid user admin from 198.51.100.2 port 22 ssh2
"""
    f1 = tmp_path / "auth.log.1"
    f1.write_text(content1)
    f2 = tmp_path / "auth.log.2"
    f2.write_text(content2)
    # gzip f2 and remove original to simulate rotation
    import gzip

    gzpath = str(f2) + ".gz"
    with gzip.open(gzpath, "wt", encoding="utf-8") as g:
        g.write(content2)
    f2.unlink()

    out = tmp_path / "report2.csv"
    # use pattern matching both files (glob)
    pattern = str(tmp_path / "auth.log*")
    res = run(["--log-pattern", pattern, "--threshold", "2", "--output", str(out)])
    assert res.returncode == 0
    txt = out.read_text()
    # 198.51.100.1 has 2 -> threshold 2 needs >2, so should not appear
    assert "198.51.100.1" not in txt
    # 198.51.100.2 has 5 -> should appear
    assert "198.51.100.2,5" in txt
