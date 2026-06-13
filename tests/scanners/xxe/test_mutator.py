from pwnproxy.plugins.scanners.xxe.mutator import json_to_xml


class TestJsonToXml:
    def test_simple_dict(self):
        result = json_to_xml('{"user": "admin"}')
        assert '<?xml version="1.0" encoding="UTF-8"?>' in result
        assert "<root>" in result
        assert "<user>admin</user>" in result

    def test_nested_dict(self):
        result = json_to_xml('{"user": {"name": "admin", "role": "user"}}')
        assert "<user>" in result
        assert "<name>admin</name>" in result
        assert "<role>user</role>" in result

    def test_list(self):
        result = json_to_xml('{"items": [1, 2, 3]}')
        assert "<items>" in result
        assert "<item>1</item>" in result
        assert "<item>2</item>" in result

    def test_invalid_json_returns_none(self):
        result = json_to_xml("not json")
        assert result is None

    def test_xml_escaping(self):
        result = json_to_xml('{"data": "a<b&c>d"}')
        assert "&lt;" in result
        assert "&amp;" in result
        assert "&gt;" in result
