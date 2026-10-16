"""Завдання 2 (варіант 2): детектор цілісності файлів (File Integrity Monitor).

Режими:
    generate - сканує каталог і створює еталонний файл baseline.json;
    check    - порівнює поточний стан з еталоном.

Формат baseline.json (список об'єктів, шляхи відносні):
    {"path": "config/app.conf", "sha256": "...", "size": 47,
     "modified": "2026-09-20T12:00:00"}
Також приймається об'єкт {"files": [...]}.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

CHUNK_SIZE = 64 * 1024
IGNORED_NAMES = frozenset({".DS_Store"})
EXIT_OK = 0
EXIT_ANOMALIES = 1
EXIT_ERROR = 2

logger = logging.getLogger("fim")


class FimError(Exception):
    """Помилка роботи утиліти (некоректні вхідні дані, недоступні файли)."""


@dataclass(frozen=True)
class FileRecord:
    """Інформація про файл: шлях (відносний), SHA-256, розмір, дата зміни."""

    path: str
    sha256: str
    size: int
    modified: str  # ISO 8601, як у baseline.json: 2026-09-20T12:00:00

    @classmethod
    def from_dict(cls, raw: object) -> FileRecord:
        """Створює запис зі словника; TypeError - хибний тип, ValueError - немає поля."""
        if not isinstance(raw, dict):
            raise TypeError("запис має бути об'єктом")
        try:
            path, digest = raw["path"], raw["sha256"]
            size, modified = raw["size"], raw["modified"]
        except KeyError as exc:
            raise ValueError(f"немає поля {exc}") from exc
        if not isinstance(path, str) or not isinstance(digest, str):
            raise TypeError("'path' і 'sha256' мають бути рядками")
        if not isinstance(size, int) or isinstance(size, bool):
            raise TypeError("'size' має бути цілим числом")
        if not isinstance(modified, str):
            raise TypeError("'modified' має бути рядком")
        return cls(path, digest.lower(), size, modified)


@dataclass
class CheckResult:
    unchanged: int = 0
    modified: list[tuple[FileRecord, FileRecord]] = field(default_factory=list)
    created: list[FileRecord] = field(default_factory=list)
    deleted: list[FileRecord] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (
            self.unchanged + len(self.modified) + len(self.created) + len(self.deleted)
        )

    @property
    def has_anomalies(self) -> bool:
        return bool(self.modified or self.created or self.deleted)


def _hide_file_only(record: logging.LogRecord) -> bool:
    """Тривожні події йдуть лише у файл: на екран їх виводить звіт."""
    return not getattr(record, "file_only", False)


def configure_logging(log_file: Path | None) -> None:
    logger.setLevel(logging.DEBUG)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    console.addFilter(_hide_file_only)
    logger.addHandler(console)
    if log_file is None:
        return
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
    except OSError as exc:
        raise FimError(f"Не вдалося відкрити лог-файл {log_file}: {exc}") from exc
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    logger.addHandler(file_handler)


def sha256_file(path: Path) -> str:
    """SHA-256 файлу, що читається порціями (працює і для великих файлів)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def scan_directory(
    root: Path, exclude: set[Path] | None = None
) -> dict[str, FileRecord]:
    """Рекурсивно сканує каталог; повертає {відносний_шлях: FileRecord}."""
    if not root.is_dir():
        raise FimError(f"Директорія не існує: {root}")
    exclude = exclude or set()
    records: dict[str, FileRecord] = {}
    for path in sorted(root.rglob("*")):
        if path.name in IGNORED_NAMES or path.is_symlink() or not path.is_file():
            continue
        if path.resolve() in exclude:
            continue
        rel = path.relative_to(root).as_posix()
        try:
            stat = path.stat()
            digest = sha256_file(path)
        except OSError as exc:
            logger.warning("Пропущено %s: %s", path, exc)
            continue
        modified = datetime.fromtimestamp(stat.st_mtime).replace(microsecond=0)
        records[rel] = FileRecord(rel, digest, stat.st_size, modified.isoformat())
    return records


def save_baseline(records: dict[str, FileRecord], baseline: Path) -> None:
    payload = [asdict(records[rel]) for rel in sorted(records)]
    try:
        baseline.parent.mkdir(parents=True, exist_ok=True)
        baseline.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", "utf-8"
        )
    except OSError as exc:
        raise FimError(f"Не вдалося записати baseline {baseline}: {exc}") from exc


def load_baseline(baseline: Path) -> dict[str, FileRecord]:
    try:
        data = json.loads(baseline.read_text("utf-8"))
    except FileNotFoundError as exc:
        raise FimError(f"Файл baseline не знайдено: {baseline}") from exc
    except OSError as exc:
        raise FimError(f"Не вдалося прочитати baseline {baseline}: {exc}") from exc
    except ValueError as exc:  # JSONDecodeError і UnicodeDecodeError
        raise FimError(f"Пошкоджений baseline {baseline}: {exc}") from exc

    items = data.get("files") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise FimError(f"Baseline {baseline} має бути списком записів")
    records: dict[str, FileRecord] = {}
    for index, item in enumerate(items):
        try:
            record = FileRecord.from_dict(item)
        except (TypeError, ValueError) as exc:
            raise FimError(f"Baseline, запис №{index}: {exc}") from exc
        if record.path in records:
            raise FimError(f"Baseline містить дублікат шляху: {record.path}")
        records[record.path] = record
    return records


def compare(
    baseline: dict[str, FileRecord], current: dict[str, FileRecord]
) -> CheckResult:
    result = CheckResult()
    for rel in sorted(baseline):
        old, new = baseline[rel], current.get(rel)
        if new is None:
            result.deleted.append(old)
        elif new.sha256 != old.sha256:
            result.modified.append((old, new))
        else:
            result.unchanged += 1
    result.created = [current[rel] for rel in sorted(current) if rel not in baseline]
    return result


def print_report(result: CheckResult, root: Path, log_file: Path | None) -> None:
    print("\n=== File Integrity Inspection Summary ===")
    print(f"Total monitored files : {result.total}")
    print(f"Unchanged files       : {result.unchanged}")
    print(f"Modified files        : {len(result.modified)}")
    print(f"Created files         : {len(result.created)}")
    print(f"Deleted files         : {len(result.deleted)}")
    if not result.has_anomalies:
        print("\n[INFO] No anomalies detected.")
        return
    print("\n=== Detected Anomalies ===")
    for old, new in result.modified:
        print(f"[MODIFIED] {root / old.path}")
        print(f"  Expected SHA-256 : {old.sha256}")
        print(f"  Actual SHA-256   : {new.sha256}")
    for rec in result.created:
        print(f"[CREATED] {root / rec.path} (Size: {rec.size} B)")
    for rec in result.deleted:
        print(f"[DELETED] {root / rec.path}")
    where = f" Check audit log at {log_file}" if log_file else ""
    print(f"\n[WARNING] Security alerts detected!{where}")


def log_anomalies(result: CheckResult, root: Path) -> None:
    extra = {"file_only": True}
    for old, new in result.modified:
        logger.warning(
            "MODIFIED %s expected=%s actual=%s",
            root / old.path,
            old.sha256,
            new.sha256,
            extra=extra,
        )
    for rec in result.created:
        logger.warning(
            "CREATED %s size=%d sha256=%s",
            root / rec.path,
            rec.size,
            rec.sha256,
            extra=extra,
        )
    for rec in result.deleted:
        logger.warning("DELETED %s", root / rec.path, extra=extra)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--dir", type=Path, required=True, help="Директорія для моніторингу"
    )
    parser.add_argument(
        "--baseline", type=Path, required=True, help="Шлях до baseline.json"
    )
    parser.add_argument("--mode", choices=["generate", "check"], required=True)
    parser.add_argument(
        "--log-file", type=Path, default=None, help="Файл журналу подій"
    )


def run(args: argparse.Namespace) -> int:
    root: Path = args.dir
    try:
        configure_logging(args.log_file)
        exclude = {args.baseline.resolve()}
        if args.log_file:
            exclude.add(args.log_file.resolve())

        if args.mode == "generate":
            if args.baseline.exists():
                logger.warning("Baseline %s буде перезаписано", args.baseline)
            logger.info("Scanning directory: %s", root)
            records = scan_directory(root, exclude)
            save_baseline(records, args.baseline)
            logger.info("Baseline created: %s (%d files)", args.baseline, len(records))
            return EXIT_OK

        logger.info("Loading baseline file: %s", args.baseline)
        baseline = load_baseline(args.baseline)
        logger.info("Scanning directory: %s", root)
        current = scan_directory(root, exclude)
        result = compare(baseline, current)
        log_anomalies(result, root)
        print_report(result, root, args.log_file)
        return EXIT_ANOMALIES if result.has_anomalies else EXIT_OK
    except FimError as exc:
        logger.error("%s", exc)
        return EXIT_ERROR
