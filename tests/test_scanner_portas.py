import importlib.util
from pathlib import Path


def load_scanner_module():
    path = Path(__file__).parent.parent / 'scanner-portas-local' / 'scanner_portas_local.py'
    spec = importlib.util.spec_from_file_location('scanner_portas_local', str(path))
    mod = importlib.util.module_from_spec(spec)
    loader = spec.loader
    assert loader is not None
    loader.exec_module(mod)
    return mod


def test_parse_ports_list_basic():
    mod = load_scanner_module()
    res = mod.parse_ports_list('22,80,8000-8002')
    assert res == [22, 80, 8000, 8001, 8002]


def test_parse_ports_list_invalid_and_ranges():
    mod = load_scanner_module()
    res = mod.parse_ports_list('22,abc,100-102,200-198')
    # 200-198 should be normalized to 198-200
    assert 22 in res
    assert 100 in res and 101 in res and 102 in res
    assert 198 in res and 200 in res


def test_build_port_list_and_range_swap():
    mod = load_scanner_module()
    # when ports iterable provided, it should return the sorted unique list
    lst = mod.build_port_list(1, 10, ports=[5, 3, 5])
    assert lst == [3, 5]

    # when start > end, swap
    lst2 = mod.build_port_list(100, 90, ports=None)
    assert lst2[0] == 90 and lst2[-1] == 100


def test_parse_allowed_file(tmp_path):
    mod = load_scanner_module()
    content = '\n'.join([
        '# comment',
        'ssh=22',
        'service/3306',
        'invalidline',
        '  8080  # web'
    ])
    p = tmp_path / 'allowed.txt'
    p.write_text(content)
    allowed = mod.parse_allowed_file(p)
    assert 22 in allowed
    assert 3306 in allowed
    assert 8080 in allowed
    # invalidline should not add anything
    assert all(isinstance(x, int) for x in allowed)
