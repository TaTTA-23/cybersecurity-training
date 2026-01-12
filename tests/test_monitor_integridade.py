import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "monitor-integridade" / "monitor-integridade-ficheiros.py"


def run_script(args, **kwargs):
    cmd = [sys.executable, str(SCRIPT)] + args
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def test_init_creates_db(tmp_path):
    db_name = "db_test.json"
    r = run_script(["--path", str(tmp_path), "--init", "--db-file", db_name])
    assert r.returncode == 0
    db_file = tmp_path / db_name
    assert db_file.exists()
    payload = json.loads(db_file.read_text(encoding="utf-8"))
    assert "files" in payload


def test_init_with_key_creates_signed_db(tmp_path):
    db_name = "db_signed.json"
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(b"supersecretkey")
    r = run_script(
        [
            "--path",
            str(tmp_path),
            "--init",
            "--db-file",
            db_name,
            "--key-file",
            str(key_file),
        ]
    )
    assert r.returncode == 0
    db_file = tmp_path / db_name
    assert db_file.exists()
    wrapper = json.loads(db_file.read_text(encoding="utf-8"))
    assert "hmac" in wrapper and "payload" in wrapper


def test_invalid_signed_db_is_rejected(tmp_path):
    db_name = "db_signed.json"
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(b"supersecretkey")
    r = run_script(
        [
            "--path",
            str(tmp_path),
            "--init",
            "--db-file",
            db_name,
            "--key-file",
            str(key_file),
        ]
    )
    assert r.returncode == 0
    db_file = tmp_path / db_name
    wrapper = json.loads(db_file.read_text(encoding="utf-8"))
    # Corrupt HMAC
    wrapper["hmac"] = "00" * 32
    db_file.write_text(json.dumps(wrapper), encoding="utf-8")
    # Now running the check should fail with code 4 (assinatura inválida)
    r2 = run_script(
        ["--path", str(tmp_path), "--db-file", db_name, "--key-file", str(key_file)]
    )
    assert r2.returncode == 4


def test_detect_changed_file(tmp_path):
    db_name = "db_test.json"
    f = tmp_path / "file.txt"
    f.write_text("hello")
    r = run_script(["--path", str(tmp_path), "--init", "--db-file", db_name])
    assert r.returncode == 0

    # Modify file
    f.write_text("modified")
    r2 = run_script(["--path", str(tmp_path), "--db-file", db_name, "-v"])
    # Should detect changes -> return code 1
    assert r2.returncode == 1
    combined = (r2.stdout + r2.stderr).decode("utf-8", errors="ignore")
    assert (
        "ALTERADOS" in combined
        or "ALTERADO" in combined
        or "Ficheiros ALTERADOS" in combined
    )


def test_detect_new_and_removed(tmp_path):
    db_name = "db_test.json"
    a = tmp_path / "a.txt"
    a.write_text("one")
    r = run_script(["--path", str(tmp_path), "--init", "--db-file", db_name])
    assert r.returncode == 0

    # Remove 'a' and add 'b'
    a.unlink()
    b = tmp_path / "b.txt"
    b.write_text("two")

    r2 = run_script(["--path", str(tmp_path), "--db-file", db_name, "-v"])
    assert r2.returncode == 1
    combined = (r2.stdout + r2.stderr).decode("utf-8", errors="ignore")
    assert (
        "NOVOS" in combined or "REMOVIDOS" in combined or "Ficheiros NOVOS" in combined
    )
