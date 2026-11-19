import copy
import re
import unittest

from validate_boleta import ROOT, parse_json, validate


class BoletaTests(unittest.TestCase):
    def setUp(self):
        self.valid = parse_json((ROOT / "fixtures/boletas/valid.json").read_text(encoding="utf-8"))

    def test_valid(self):
        validate(self.valid, "GESTORA-ALFA")

    def test_invalid_cases(self):
        cases = [
            ("quantity", "0"), ("quantity", "1000000000"), ("quantity", 100),
            ("unitPrice", "980.50000"), ("unitPrice", "999999999999999.000000"),
            ("grossAmount", "98050.01"), ("grossAmount", "999999999999999999.99"),
            ("issueRate", "100.000001"), ("tradeDate", "2026-02-30"),
            ("settlementDate", "2026-11-18"), ("issuerId", "OUTRO"),
            ("custodianId", "OUTRO"), ("portfolioId", "OUTRO"),
            ("assetType", "STOCK"), ("operationId", "premature")
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                boleta = copy.deepcopy(self.valid)
                boleta[field] = value
                with self.assertRaises(ValueError):
                    validate(boleta, "GESTORA-ALFA")

    def test_half_up(self):
        self.valid.update(quantity="1", unitPrice="0.005000", grossAmount="0.01")
        validate(self.valid, "GESTORA-ALFA")

    def test_duplicate_property(self):
        with self.assertRaisesRegex(ValueError, "duplicada"):
            parse_json('{"clientOrderId":"A","clientOrderId":"B"}')

    def test_schema_patterns_reject_trailing_newline(self):
        from validate_boleta import SCHEMA
        for field, value in (("quantity", "100\n"), ("unitPrice", "980.500000\n"), ("clientOrderId", "OP-1\n"), ("issueRate", "6.000000\n")):
            with self.subTest(field=field):
                definition = SCHEMA["properties"][field]
                pattern = SCHEMA["$defs"][definition["$ref"].split("/")[-1]]["pattern"] if "$ref" in definition else definition["pattern"]
                self.assertIsNone(re.search(pattern, value))
                boleta = copy.deepcopy(self.valid)
                boleta[field] = value
                with self.assertRaises(ValueError):
                    validate(boleta, "GESTORA-ALFA")

    def test_product_overflow_and_near_limit(self):
        self.valid.update(quantity="999999999", unitPrice="1000000000.000000", grossAmount="999999999000000000.00")
        validate(self.valid, "GESTORA-ALFA")
        self.valid["unitPrice"] = "99999999999999.999999"
        with self.assertRaisesRegex(ValueError, "overflow"):
            validate(self.valid, "GESTORA-ALFA")

    def test_unauthorized_manager(self):
        with self.assertRaises(ValueError):
            validate(self.valid, "OUTRA-GESTORA")


if __name__ == "__main__":
    unittest.main()
