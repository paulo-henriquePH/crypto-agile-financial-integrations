"""Valida metaschema e eventos; --invalid deve falhar com saída não zero."""
import argparse
import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument("--invalid", action="store_true")
args = parser.parse_args()
schema = json.loads((root / "contracts/schemas/event.schema.json").read_text(encoding="utf-8"))
Draft202012Validator.check_schema(schema)
checker = FormatChecker()
if "date-time" not in checker.checkers:
    raise RuntimeError("verificador de formato date-time indisponível")
validator = Draft202012Validator(schema, format_checker=checker)
count = 0
for path in sorted((root / "fixtures/events").glob("*.json")):
    case = json.loads(path.read_text(encoding="utf-8"))
    if case["valid"]:
        for event in case["events"]:
            validator.validate(event)
            count += 1
if not count:
    raise ValueError("nenhum evento válido encontrado")
initial = json.loads((root / "fixtures/events/settled.json").read_text(encoding="utf-8"))["events"][0]
invalids = []
for field, value in (("sequence", 0), ("eventId", "não-uuid"),
                     ("occurredAt", "2026-11-19T12:00:00+00:00"),
                     ("occurredAt", "2026-02-30T12:00:00Z"),
                     ("unknown", 1), ("reason", "inesperado"),
                     ("previousState", "SENT")):
    bad = copy.deepcopy(initial)
    bad[field] = value
    invalids.append(bad)
for bad in invalids:
    if validator.is_valid(bad):
        raise ValueError("schema aceitou evento estrutural inválido")
if args.invalid:
    validator.validate(invalids[0])
print(f"metaschema e {count} eventos válidos aceitos; {len(invalids)} inválidos rejeitados")
