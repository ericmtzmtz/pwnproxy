"""Unit tests for the command-output signatures.

The signatures must be specific enough that page text or a binary document
decoded as text cannot match them, and a pattern that already matches the
baseline response is never evidence of injection.
"""

from pwnproxy.plugins.scanners.command_injection.signatures import (
    get_evidence,
    has_command_output,
)

# Body of a PDF decoded as text: bare lowercase keywords on their own lines.
PDF_TEXT = (
    "%PDF-1.4\n"
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    "6 0 obj\n<< /ProcSet [/PDF /Text] >>\nendobj\n"
    "stream\nendstream\ntrailer\nstartxref\n0\n%%EOF\n"
)

UID_LINE = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
PASSWD_LINE = "root:x:0:0:root:/root:/bin/bash"
LS_LINE = "drwxr-xr-x  2 root root  4096 Nov 24 10:00 app"


class TestNoFalsePositives:
    def test_pdf_keywords_are_not_command_output(self):
        assert has_command_output(PDF_TEXT) == (False, "")

    def test_isolated_short_lowercase_token_is_not_whoami(self):
        assert has_command_output("endobj") == (False, "")
        assert has_command_output("stream\n") == (False, "")

    def test_username_inside_a_page_is_not_whoami(self):
        assert has_command_output("<html><body>Welcome back, root!</body></html>") == (False, "")

    def test_username_on_a_line_of_a_longer_body_is_not_whoami(self):
        assert has_command_output("home\nwww-data\nlogout\n") == (False, "")

    def test_uid_without_gid_is_not_specific_enough(self):
        assert has_command_output("your uid=33(www-data), welcome") == (False, "")

    def test_prose_command_not_found_is_not_a_shell_diagnostic(self):
        assert has_command_output("Troubleshooting: command not found in PATH") == (False, "")

    def test_windows_prose_is_not_a_shell_diagnostic(self):
        assert has_command_output("If the tool is missing you get not recognized errors") == (False, "")


class TestPositiveSignatures:
    def test_id_output(self):
        assert has_command_output(UID_LINE) == (True, "uid")

    def test_passwd_file(self):
        assert has_command_output(PASSWD_LINE) == (True, "passwd")

    def test_ls_listing(self):
        assert has_command_output(f"total 8\n{LS_LINE}\n") == (True, "directory")

    def test_uname_output(self):
        body = "Linux box 6.1.0-18-amd64 #1 SMP x86_64 GNU/Linux"
        assert has_command_output(body) == (True, "uname")

    def test_shell_command_not_found(self):
        body = "/bin/sh: 1: idontexist: not found\n"
        assert has_command_output(body) == (True, "error")

    def test_bare_username_is_whoami(self):
        assert has_command_output("www-data\n") == (True, "whoami")
        assert has_command_output("root") == (True, "whoami")


class TestBaselineComparison:
    def test_same_signature_in_baseline_is_not_evidence(self):
        assert has_command_output(UID_LINE, baseline=f"<pre>{UID_LINE}</pre>") == (False, "")

    def test_whoami_name_already_in_baseline_is_not_evidence(self):
        assert has_command_output("root\n", baseline="root\n") == (False, "")

    def test_different_technique_in_baseline_still_counts(self):
        assert has_command_output(PASSWD_LINE, baseline=UID_LINE) == (True, "passwd")


class TestEvidence:
    def test_uid_evidence_names_the_technique(self):
        evidence = get_evidence(UID_LINE, "uid")
        assert evidence.startswith("Command output detected (uid):")
        assert "uid=33(www-data)" in evidence

    def test_whoami_evidence_is_the_bare_line(self):
        assert get_evidence("www-data\n", "whoami") == "Command output detected (whoami): www-data"
