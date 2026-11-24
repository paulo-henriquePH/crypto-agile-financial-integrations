"""Check every example with the pinned JSON Schema engine and offline references."""
import argparse
import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--invalid", action="store_true")
    args = parser.parse_args()
    schemas = [load(p) for p in ("contracts/messages/envelope.schema.json",
                                  "contracts/schemas/boleta.schema.json",
                                  "contracts/schemas/event.schema.json")]
    for schema in schemas:
        Draft202012Validator.check_schema(schema)
    checker = FormatChecker()
    for fmt in ("date-time", "date", "uuid"):
        if fmt not in checker.checkers:
            raise RuntimeError(f"verificador de formato {fmt} indisponível")
    if checker.conforms("2026-02-30T12:00:00Z", "date-time"):
        raise RuntimeError("verificador date-time não rejeita data impossível")
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas
    )
    validator = Draft202012Validator(schemas[0], registry=registry, format_checker=checker)
    corpus = load("contracts/messages/examples.json")
    # These negatives require cross-field, local policy or clock validation, not schema.
    semantic_only = {"signer_mismatch", "expired", "dual_signature_removed"}
    names = set()
    for case in corpus["cases"]:
        name = case["name"]
        if name in names:
            raise ValueError("nome de caso duplicado")
        names.add(name)
        expected = case["valid"] or name in semantic_only
        errors = list(validator.iter_errors(case["message"]))
        if bool(errors) == expected:
            raise ValueError(f"{name}: resultado inesperado no schema: {errors[:1]}")
        if "request" in case:
            validator.validate(case["request"])
    if not names or not semantic_only <= names:
        raise ValueError("corpus incompleto")
    base = corpus["cases"][0]["message"]
    bad = copy.deepcopy(base)
    bad["protected"]["issuedAt"] = "2026-02-30T12:00:00Z"
    if validator.is_valid(bad):
        raise ValueError("data impossível aceita")
    if args.invalid:
        validator.validate(bad)
    print(f"3 metaschemas; {len(names)} mensagens e requisições associadas verificadas; data impossível rejeitada")


if __name__ == "__main__":
    main()
