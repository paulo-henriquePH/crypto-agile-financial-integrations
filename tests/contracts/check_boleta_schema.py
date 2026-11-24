"""Valida o schema e a fixture; --invalid demonstra falha não capturada."""
import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument("--invalid", action="store_true")
args = parser.parse_args()
schema = json.loads((root / "contracts/schemas/boleta.schema.json").read_text(encoding="utf-8"))
boleta = json.loads((root / "fixtures/boletas/valid.json").read_text(encoding="utf-8"))
Draft202012Validator.check_schema(schema)
if args.invalid:
    boleta["quantity"] = 0
Draft202012Validator(schema, format_checker=FormatChecker()).validate(boleta)
print("schema e boleta válidos")
