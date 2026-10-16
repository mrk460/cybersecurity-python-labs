# Лабораторна робота №2 — варіант 2: File Integrity Monitor

## Встановлення
```bash
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Структура
```
labs/lab02/
├── main.py     # команди demo та analyze
├── task1.py    # User, Admin, Session, AuditLog, UserAccount
├── task2.py    # FIM: scan, baseline, compare, logging
├── README.md
└── data/       # каталог data_v02/ з архіву lab2_data.zip
```
Вхідні дані: каталог для моніторингу (`labs/lab02/data/data_v02/...`).
Фактичні назви файлів з архіву підставте у команди нижче.

## Запуск
```bash
# Завдання 1
python -m labs.lab02.main demo

# Завдання 2: створити еталон
python -m labs.lab02.main analyze --mode generate \
  --dir labs/lab02/data/data_v02/<каталог> \
  --baseline labs/lab02/out/baseline.json

# Завдання 2: перевірка цілісності
python -m labs.lab02.main analyze --mode check \
  --dir labs/lab02/data/data_v02/<каталог> \
  --baseline labs/lab02/out/baseline.json \
  --log-file labs/lab02/out/fim_audit.log
```

## Параметри analyze
| Параметр | Опис |
|---|---|
| `--dir` | директорія для сканування (обов'язковий) |
| `--baseline` | шлях до baseline.json (обов'язковий) |
| `--mode` | `generate` або `check` (обов'язковий) |
| `--log-file` | файл журналу; сюди пишуться `logging.warning` про зміни |

## Поведінка при помилках
- Немає директорії / baseline або baseline пошкоджений → `[ERROR]`, код виходу 2.
- Файл неможливо прочитати → попередження в лог, файл пропускається.
- Знайдено зміни (modified/created/deleted) → код виходу 1; без змін → 0.
- baseline та log-файл виключаються зі сканування.
