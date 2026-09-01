import pytest

from pwnproxy.shared.scan.response_compare import (
    normalize_body,
    Fingerprint,
    similarity,
    is_boolean_differentiable,
    bool_pair_similarity,
)


def _fp(status, body, block=512):
    return Fingerprint.build(status, body, block=block)


class TestNormalizeBody:
    def test_uuid_is_normalized(self):
        body = "csrf=0f8fad5b-d9cb-469f-a165-70867728950e&next=/home"
        assert "0f8fad5b-d9cb-469f-a165-70867728950e" not in normalize_body(body)
        assert "TOKEN" in normalize_body(body)

    def test_timestamp_is_normalized(self):
        body = "Welcome! Last login 1785600000000 seconds ago"
        assert "1785600000000" not in normalize_body(body)
        assert "TOKEN" in normalize_body(body)

    def test_short_numbers_not_treated_as_timestamp(self):
        body = "count=42 total=1337"
        normalized = normalize_body(body)
        assert "42" in normalized
        assert "1337" in normalized

    def test_session_id_is_normalized(self):
        body = 'Set-Cookie: PHPSESSID=abcdef0123456789; path=/'
        assert "abcdef0123456789" not in normalize_body(body)

    def test_whitespace_removed(self):
        assert normalize_body("a\n\n  b\t\tc") == "abc"

    def test_none_becomes_empty(self):
        assert normalize_body(None) == ""


class TestSimilarity:
    def test_same_status_same_body_is_similar(self):
        a = _fp(200, "<html>identical</html>")
        b = _fp(200, "<html>identical</html>")
        assert similarity(a, b) >= 0.99

    def test_different_status_is_zero(self):
        a = _fp(200, "ok")
        b = _fp(500, "error")
        assert similarity(a, b) == 0.0

    def test_dynamic_noise_only_is_high_similarity(self):
        a = _fp(
            200,
            "<div>token=0f8fad5b-d9cb-469f-a165-70867728950e ts=1785600000000</div>",
        )
        b = _fp(
            200,
            "<div>token=9f8fad5b-d9cb-469f-a165-70867728950e ts=1785600000001</div>",
        )
        assert similarity(a, b) >= 0.99

    def test_structural_difference_lowers_similarity(self):
        a = _fp(200, "<html><body>Welcome user</body></html>")
        b = _fp(200, "<html><body>User not found</body></html>")
        assert similarity(a, b) < 0.9

    def test_raw_length_ignored_in_normalization(self):
        # Same structure but wildly different raw lengths from dynamic padding
        a = _fp(200, "<html>" + (" " * 2000) + "<body>x</body></html>")
        b = _fp(200, "<html><body>x</body></html>")
        # normalizing collapses whitespace, so structure matches
        assert similarity(a, b) >= 0.99


class TestIsBooleanDifferentiable:
    def test_identical_responses_not_differentiable(self):
        fp_t = _fp(200, "<html>Same</html>")
        fp_f = _fp(200, "<html>Same</html>")
        assert not is_boolean_differentiable(fp_t, fp_f)

    def test_status_difference_always_differentiable(self):
        fp_t = _fp(200, "page")
        fp_f = _fp(500, "error page")
        assert is_boolean_differentiable(fp_t, fp_f)

    def test_clear_structural_difference_is_differentiable(self):
        fp_t = _fp(200, "<html><body>Query returned 42 rows</body></html>")
        fp_f = _fp(200, "<html><body>No results found</body></html>")
        assert is_boolean_differentiable(fp_t, fp_f)

    def test_dynamic_noise_only_not_differentiable(self):
        fp_t = _fp(200, "csrf=0f8fad5b-d9cb-469f-a165-70867728950e ok")
        fp_f = _fp(200, "csrf=9f8fad5b-d9cb-469f-a165-70867728950e ok")
        assert not is_boolean_differentiable(fp_t, fp_f)

    def test_does_not_use_raw_length_alone(self):
        # True has a different raw length but identical structure after normalize
        fp_t = _fp(200, "<html><body>x" + (" " * 5000) + "</body></html>")
        fp_f = _fp(200, "<html><body>x</body></html>")
        assert not is_boolean_differentiable(fp_t, fp_f)


class TestBoolPairSimilarity:
    def test_baseline_before_after_similar(self):
        a = "Welcome<br>ts=1785600000000 session=abc12345"
        b = "Welcome<br>ts=1785600000003 session=xyz98765"
        assert bool_pair_similarity(a, b) >= 0.90
