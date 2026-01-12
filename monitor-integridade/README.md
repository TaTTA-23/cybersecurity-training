# Monitor de Integridade de Ficheiros

Este pequeno projeto inclui um script Python para monitorização de integridade de ficheiros baseado em hashes SHA-256.

Características
- Gera um baseline de hashes para um diretório (recursivo).
- Compara o estado atual com o baseline e deteta ficheiros novos, removidos ou alterados.
- Suporta modo one-shot (verificação única) e modo watch (verificação periódica).

Uso rápido

1. Criar baseline:

```bash
python3 monitor-integridade-ficheiros.py --path /caminho/para/diretorio --init
```

2. Verificar uma vez (usa o baseline existente):

```bash
python3 monitor-integridade-ficheiros.py --path /caminho/para/diretorio
```

3. Executar em watch mode (ex.: intervalo 10s):

```bash
python3 monitor-integridade-ficheiros.py --path /caminho/para/diretorio --watch --interval 10
```


Execução em testes

Os testes automáticos usam `pytest`. A partir da raiz do repositório execute:

```bash
pytest -q
```

Instalar pre-commit (hooks locais)

Recomendado para manter o código consistente antes de fazer commits. A partir da raiz do repositório:

```bash
python3 -m pip install -r requirements.txt
pre-commit install
# opcional: aplicar hooks a todos os ficheiros (formatar/lint)
pre-commit run --all-files
```

Notas
- O ficheiro de database de hashes é criado dentro do diretório monitorizado (por omissão: `.integrity_hashes.json`).
- Pode alterar o nome do ficheiro de DB com `--db-file`.
- O script foi escrito para fins educativos demonstrando detecção básica de alterações de ficheiros.

