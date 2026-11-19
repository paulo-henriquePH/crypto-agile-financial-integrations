"""Validação isolada da boleta v1; não cria operação nem consulta serviços."""

import argparse
import datetime as dt
import json
import re
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "contracts/schemas/boleta.schema.json").read_text(encoding="utf-8"))
REFERENCES = json.loads((ROOT / "fixtures/boletas/references.json").read_text(encoding="utf-8"))
PATTERNS = {
    "id": re.compile(r"[A-Za-z0-9_-]{1,64}\Z", re.ASCII),
    "rate": re.compile(r"(?:100\.000000|(?:0|[1-9][0-9]?)\.[0-9]{6})\Z", re.ASCII),
    "quantity": re.compile(r"[1-9][0-9]{0,8}\Z", re.ASCII),
    "unitPrice": re.compile(r"(?:0|[1-9][0-9]{0,13})\.[0-9]{6}\Z", re.ASCII),
    "grossAmount": re.compile(r"(?:0|[1-9][0-9]{0,17})\.[0-9]{2}\Z", re.ASCII),
}
ID_FIELDS = {"clientOrderId", "portfolioId", "assetId", "issuerId", "counterpartyId", "custodianId", "administratorId"}
CONSTANTS = {"operationType": "BUY", "assetType": "DEBENTURE", "indexer": "IPCA", "currency": "BRL"}


def parse_json(text: str) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"propriedade duplicada: {key}")
            result[key] = value
        return result

    value = json.loads(text, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("boleta deve ser objeto")
    return value


def validate(boleta: dict, manager_id: str, references: dict = REFERENCES) -> None:
    fields = set(SCHEMA["required"])
    if set(boleta) != fields:
        raise ValueError(f"campos ausentes ou desconhecidos: {sorted(fields ^ set(boleta))}")
    if not isinstance(manager_id, str) or not PATTERNS["id"].fullmatch(manager_id):
        raise ValueError("managerId inválido")
    for field in ID_FIELDS:
        if not isinstance(boleta[field], str) or not PATTERNS["id"].fullmatch(boleta[field]):
            raise ValueError(f"{field} inválido")
    for field, expected in CONSTANTS.items():
        if boleta[field] != expected or not isinstance(boleta[field], str):
            raise ValueError(f"{field} não suportado")
    for field in ("issueRate", "negotiatedRate", "quantity", "unitPrice", "grossAmount"):
        if not isinstance(boleta[field], str) or not PATTERNS[field if field in PATTERNS else "rate"].fullmatch(boleta[field]):
            raise ValueError(f"{field} fora de formato ou limite")
    try:
        trade = dt.date.fromisoformat(boleta["tradeDate"])
        settlement = dt.date.fromisoformat(boleta["settlementDate"])
        if trade.isoformat() != boleta["tradeDate"] or settlement.isoformat() != boleta["settlementDate"]:
            raise ValueError("data fora de ISO YYYY-MM-DD")
    except (TypeError, ValueError) as exc:
        raise ValueError("data inválida") from exc
    if settlement < trade:
        raise ValueError("liquidação anterior à negociação")
    manager = references["managers"].get(manager_id)
    portfolio = references["portfolios"].get(boleta["portfolioId"])
    asset = references["assets"].get(boleta["assetId"])
    if manager is None or portfolio is None or boleta["portfolioId"] not in manager["portfolios"]:
        raise ValueError("carteira não autorizada")
    if asset is None or asset["issuerId"] != boleta["issuerId"] or asset["assetType"] != boleta["assetType"]:
        raise ValueError("ativo/emissor incompatível")
    if boleta["counterpartyId"] not in references["counterparties"]:
        raise ValueError("contraparte desconhecida")
    for field in ("custodianId", "administratorId"):
        if portfolio[field] != boleta[field]:
            raise ValueError(f"{field} incompatível com carteira")
    try:
        quantity = int(boleta["quantity"])
        price = Decimal(boleta["unitPrice"])
        amount = Decimal(boleta["grossAmount"])
        calculated = (quantity * price).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, OverflowError) as exc:
        raise ValueError("financeiro inválido") from exc
    if price <= 0 or amount <= 0 or calculated != amount or calculated >= Decimal("1e18"):
        raise ValueError("financeiro inconsistente ou overflow")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("boleta", type=Path)
    parser.add_argument("--manager-id", default="GESTORA-ALFA")
    args = parser.parse_args()
    validate(parse_json(args.boleta.read_text(encoding="utf-8")), args.manager_id)
    print("boleta válida")
