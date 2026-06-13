import time

from pwnproxy.services.session.validator import jwt_decode


class TestJwtDecode:
    def test_decode_valid_jwt(self):
        result = jwt_decode(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.a1b2c3"
        )
        assert result["header"] == {"alg": "HS256"}
        assert result["payload"] == {"sub": "1234"}
        assert result["status"] == "valid"

    def test_decode_expired_jwt(self):
        import jwt as pyjwt
        import time
        expired = pyjwt.encode(
            {"sub": "test", "exp": int(time.time()) - 3600},
            "secret",
            algorithm="HS256",
        )
        result = jwt_decode(expired)
        assert result["status"] == "expired"

    def test_decode_invalid_token(self):
        result = jwt_decode("not-a-jwt")
        assert result["status"] == "invalid_signature"

    def test_decode_future_jwt_is_valid(self):
        import jwt as pyjwt
        valid = pyjwt.encode(
            {"sub": "test", "exp": int(time.time()) + 3600},
            "secret",
            algorithm="HS256",
        )
        result = jwt_decode(valid)
        assert result["status"] == "valid"
