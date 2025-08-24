import pytest
from src.payload_analyzer import detect_malicious_payload

# Test cases for malicious payloads
@pytest.mark.parametrize("payload, expected_pattern", [
    (b"SELECT * FROM users", "SELECT"),
    (b"UNION SELECT password FROM admins", "UNION SELECT"),
    (b"'; DROP TABLE students; --", "DROP"),
    (b"<script>alert('XSS')</script>", "<script>"),
    (b"/bin/bash -c 'rm -rf /'", "/bin/bash"),
    (b"eval(base64_decode('...'))", "eval("),
    (b"cat /etc/passwd", "/etc/passwd"),
])
def test_detect_malicious_payload_malicious(payload, expected_pattern):
    """
    Tests that the detect_malicious_payload function correctly identifies various malicious patterns.
    """
    is_malicious, pattern = detect_malicious_payload(payload)
    assert is_malicious is True
    assert pattern == expected_pattern

# Test cases for benign payloads
@pytest.mark.parametrize("payload", [
    (b"Hello, this is a normal message."),
    (b"Here is a file transfer with no malicious content."),
    (b"Just a regular HTTP request."),
    (b"SELECTion of products is great"), # Benign case that contains a keyword
])
def test_detect_malicious_payload_benign(payload):
    """
    Tests that the detect_malicious_payload function does not flag benign payloads.
    """
    is_malicious, pattern = detect_malicious_payload(payload)
    assert is_malicious is False
    assert pattern is None

# Test with empty payload
def test_detect_malicious_payload_empty():
    """
    Tests that an empty payload is correctly identified as not malicious.
    """
    is_malicious, pattern = detect_malicious_payload(b"")
    assert is_malicious is False
    assert pattern is None
