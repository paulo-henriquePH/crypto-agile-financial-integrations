import unittest
from lxml import etree
import check_administrator_soap as soap


class AdministratorSoapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema, _ = soap.schema_and_client()
        cls.example = soap.SOAPDIR / 'examples'
        cls.query_data = (cls.example / 'get-operation.xml').read_bytes()
        cls.query, _ = soap.check(cls.query_data, cls.schema, soap.ACTION + 'GetOperation', 'QUERY_ADMIN_RECORD')

    def test_examples(self):
        soap.main()

    def test_official_wsdl_and_soap_schema_reject_invalid(self):
        parser = etree.XMLParser(load_dtd=False, resolve_entities=False, no_network=True)
        parser.resolvers.add(soap.LocalResolver())
        validator = etree.XMLSchema(etree.parse(str(soap.VALIDATION_SCHEMA), parser))
        good = soap.WSDL.read_bytes()
        self.assertTrue(validator.validate(etree.fromstring(good)))
        for bad in (good.replace(b'name="AdministratorPortType"', b''),
                    good.replace(b'style="document"', b'style="invalid"')):
            self.assertFalse(validator.validate(etree.fromstring(bad)))
            with self.assertRaisesRegex(ValueError, 'invalid WSDL structure'):
                soap.wsdl_structure(bad, parser)

    def test_binding_profile_rejects_wrong_soap(self):
        parser = etree.XMLParser(load_dtd=False, resolve_entities=False, no_network=True)
        parser.resolvers.add(soap.LocalResolver())
        good = soap.WSDL.read_bytes()
        for bad in (good.replace(b'style="document"', b'style="rpc"'),
                    good.replace(b'use="literal"', b'use="encoded"'),
                    good.replace(b'urn:cafi:administrator:v1:GetOperation', b'urn:wrong')):
            with self.assertRaises(ValueError):
                soap.wsdl_structure(bad, parser)

    def test_zeep_rejects_remote_import(self):
        bad = soap.WSDL.read_bytes().replace(
            b'schemaLocation="administrator.xsd"',
            b'schemaLocation="https://example.invalid/administrator.xsd"')
        class ModifiedWsdl(soap.LocalTransport):
            def load(self, url):
                if soap.allowed_path(url) == soap.WSDL.resolve():
                    return bad
                return super().load(url)
        with self.assertRaisesRegex(ValueError, 'remote import'):
            soap.Client(str(soap.WSDL), transport=ModifiedWsdl(),
                        settings=soap.Settings(forbid_dtd=True, forbid_entities=True, forbid_external=True))

    def test_action_and_correlation(self):
        with self.assertRaises(ValueError):
            soap.check(self.query_data, self.schema, soap.ACTION + 'RegisterOperation', 'QUERY_ADMIN_RECORD')
        data = (self.example / 'get-result.xml').read_bytes().replace(
            b'73333333-3333-4333-8333-333333333333', b'83333333-3333-4333-8333-333333333333')
        with self.assertRaises(ValueError):
            soap.check(data, self.schema, soap.ACTION + 'GetOperation', 'QUERY_ADMIN_RECORD_RESULT', self.query)

    def test_fault_rejects_mismatch(self):
        data = (self.example / 'fault.xml').read_bytes().replace(b'NOT_FOUND', b'NOT FOUND')
        with self.assertRaises(ValueError):
            soap.check(data, self.schema, soap.ACTION + 'GetOperation', 'ERROR', self.query)

    def test_duplicate_and_external(self):
        bad = self.query_data.replace(b'<c:Payload/>', b'<c:Payload/><c:Payload/>')
        with self.assertRaises(ValueError):
            soap.check(bad, self.schema, soap.ACTION + 'GetOperation', 'QUERY_ADMIN_RECORD')
        for data in (b'<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>',
                     self.query_data.replace(b'<c:Payload/>', b'<c:Payload xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></c:Payload>'),
                     self.query_data.replace(b'<c:Payload/>', b'<c:Payload xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:cafi:v1 https://example.test/x"/>')):
            with self.assertRaises((ValueError, etree.XMLSyntaxError)):
                soap.check(data, self.schema, soap.ACTION + 'GetOperation', 'QUERY_ADMIN_RECORD')
        for location in ('https://example.test/x.xsd', '/etc/passwd'):
            with self.assertRaises(ValueError):
                soap.allowed_path(location)

    def test_same_node(self):
        node, canonical = soap.check(self.query_data, self.schema, soap.ACTION + 'GetOperation', 'QUERY_ADMIN_RECORD')
        self.assertEqual(canonical, etree.tostring(node, method='c14n', exclusive=True, with_comments=False))
        self.assertEqual(soap.x._value(node[0], 'MessageType'), 'QUERY_ADMIN_RECORD')


if __name__ == '__main__':
    unittest.main()
