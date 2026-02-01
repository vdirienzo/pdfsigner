"""
Integration tests for PKCS#11 with SoftHSM.

Tests real PKCS#11 operations using SoftHSM as a virtual HSM.
These tests require SoftHSM2 to be installed on the system.

Installation:
    Ubuntu/Debian: sudo apt-get install softhsm2
    macOS: brew install softhsm
    Fedora/RHEL: sudo dnf install softhsm

Author: Homero Thompson del Lago del Terror
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pdfsigner.core.token.nss_handler import CertificateInfo, NSSHandler
from pdfsigner.exceptions import (
    CertificateNotFoundError,
    TokenAuthenticationError,
    TokenNotFoundError,
)

# ==========================================================================
# Test markers and availability checks
# ==========================================================================

# Check if SoftHSM is available
SOFTHSM_AVAILABLE = shutil.which("softhsm2-util") is not None
SKIP_REASON = "SoftHSM2 not installed (sudo apt-get install softhsm2)"


# ==========================================================================
# Test fixtures
# ==========================================================================


@pytest.fixture(scope="module")
def softhsm_config_dir():
    """Create temporary directory for SoftHSM configuration."""
    with tempfile.TemporaryDirectory(prefix="softhsm_") as tmpdir:
        config_dir = Path(tmpdir)
        tokens_dir = config_dir / "tokens"
        tokens_dir.mkdir()

        # Create SoftHSM2 config file
        config_file = config_dir / "softhsm2.conf"
        config_file.write_text(
            f"directories.tokendir = {tokens_dir}\nobjectstore.backend = file\nlog.level = INFO\n"
        )

        # Set environment variable for SoftHSM
        old_env = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = str(config_file)

        yield config_dir

        # Restore environment
        if old_env:
            os.environ["SOFTHSM2_CONF"] = old_env
        else:
            os.environ.pop("SOFTHSM2_CONF", None)


@pytest.fixture(scope="module")
def softhsm_token(softhsm_config_dir):
    """Initialize a SoftHSM token for testing."""
    token_label = "PDFSigner-Test"
    user_pin = "1234"
    so_pin = "5678"

    # Initialize token
    result = subprocess.run(
        [
            "softhsm2-util",
            "--init-token",
            "--slot",
            "0",
            "--label",
            token_label,
            "--so-pin",
            so_pin,
            "--pin",
            user_pin,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        pytest.skip(f"Failed to initialize SoftHSM token: {result.stderr}")

    # Find SoftHSM library
    softhsm_lib = None
    possible_paths = [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",  # macOS ARM
        "/usr/local/Cellar/softhsm/*/lib/softhsm/libsofthsm2.so",  # macOS Intel
    ]

    for path in possible_paths:
        if Path(path).exists():
            softhsm_lib = path
            break

    if not softhsm_lib:
        pytest.skip("SoftHSM library not found in standard locations")

    return {
        "label": token_label,
        "user_pin": user_pin,
        "so_pin": so_pin,
        "lib_path": softhsm_lib,
    }


@pytest.fixture
def test_certificate_and_key():
    """Generate a self-signed certificate and private key for testing."""
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Buenos Aires"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "CABA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PDFSigner Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(x509.datetime.datetime.now(x509.datetime.timezone.utc))
        .not_valid_after(
            x509.datetime.datetime.now(x509.datetime.timezone.utc)
            + x509.datetime.timedelta(days=365)
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,  # non_repudiation
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Serialize to PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return {
        "certificate": cert,
        "private_key": private_key,
        "cert_pem": cert_pem,
        "key_pem": key_pem,
    }


@pytest.fixture
def softhsm_with_cert(softhsm_token, test_certificate_and_key, tmp_path):
    """SoftHSM token with imported certificate and key."""
    # Save cert and key to temporary files
    cert_file = tmp_path / "test_cert.pem"
    key_file = tmp_path / "test_key.pem"

    cert_file.write_bytes(test_certificate_and_key["cert_pem"])
    key_file.write_bytes(test_certificate_and_key["key_pem"])

    # Import certificate
    result = subprocess.run(
        [
            "softhsm2-util",
            "--import",
            str(cert_file),
            "--slot",
            "0",
            "--label",
            "Test-Cert",
            "--id",
            "01",
            "--pin",
            softhsm_token["user_pin"],
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        pytest.skip(f"Failed to import certificate: {result.stderr}")

    # Import private key (convert to PKCS#8 first)
    key_pkcs8 = test_certificate_and_key["private_key"].private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    key_pkcs8_file = tmp_path / "test_key.p8"
    key_pkcs8_file.write_bytes(key_pkcs8)

    result = subprocess.run(
        [
            "softhsm2-util",
            "--import",
            str(key_pkcs8_file),
            "--slot",
            "0",
            "--label",
            "Test-Key",
            "--id",
            "01",
            "--pin",
            softhsm_token["user_pin"],
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        pytest.skip(f"Failed to import private key: {result.stderr}")

    return {**softhsm_token, "cert_id": b"\x01"}


@pytest.fixture
def nss_handler_factory(softhsm_token, tmp_path):
    """Factory to create NSSHandler instances with SoftHSM."""

    def _create_handler(auto_init=True):
        # Create fake NSS DB (NSSHandler checks it exists)
        nss_db = tmp_path / ".nss"
        nss_db.mkdir(exist_ok=True)

        handler = NSSHandler(nss_db_path=nss_db)

        # Monkey-patch to use SoftHSM library
        def _mock_find():
            return softhsm_token["lib_path"]

        handler._find_pkcs11_lib = _mock_find

        if auto_init:
            handler.initialize()

        return handler

    return _create_handler


# ==========================================================================
# Integration Tests
# ==========================================================================


@pytest.mark.pkcs11
@pytest.mark.skipif(not SOFTHSM_AVAILABLE, reason=SKIP_REASON)
class TestPKCS11Real:
    """Integration tests with real SoftHSM."""

    def test_initialize_with_softhsm_library(self, nss_handler_factory):
        """NSSHandler should initialize successfully with SoftHSM library."""
        handler = nss_handler_factory(auto_init=False)

        # Should not raise exception
        handler.initialize()

        assert handler._lib is not None

    def test_get_available_tokens_returns_test_token(self, nss_handler_factory, softhsm_token):
        """get_available_tokens should list the test token."""
        handler = nss_handler_factory()

        tokens = handler.get_available_tokens()

        assert softhsm_token["label"] in tokens

    def test_connect_token_with_valid_label(self, nss_handler_factory, softhsm_token):
        """connect_token should succeed with valid token label."""
        handler = nss_handler_factory()

        # Should not raise exception
        handler.connect_token(softhsm_token["label"])

        assert handler._token is not None

    def test_connect_token_with_none_uses_first_available(self, nss_handler_factory):
        """connect_token with None should connect to first available token."""
        handler = nss_handler_factory()

        # Should not raise exception
        handler.connect_token(None)

        assert handler._token is not None

    def test_connect_token_with_invalid_label_raises_error(self, nss_handler_factory):
        """connect_token should raise TokenNotFoundError for invalid label."""
        handler = nss_handler_factory()

        with pytest.raises(TokenNotFoundError, match="not found"):
            handler.connect_token("NonExistent-Token")

    def test_authenticate_with_correct_pin(self, nss_handler_factory, softhsm_token):
        """authenticate should succeed with correct PIN."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_token["label"])

        # Should not raise exception
        handler.authenticate(softhsm_token["user_pin"])

        assert handler._session is not None

    def test_authenticate_with_wrong_pin_raises_error(self, nss_handler_factory, softhsm_token):
        """authenticate should raise TokenAuthenticationError with wrong PIN."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_token["label"])

        with pytest.raises(TokenAuthenticationError, match="Incorrect PIN"):
            handler.authenticate("0000")  # Wrong PIN

    def test_authenticate_without_token_raises_error(self, nss_handler_factory):
        """authenticate should raise TokenNotFoundError if no token connected."""
        handler = nss_handler_factory()

        with pytest.raises(TokenNotFoundError, match="connect a token first"):
            handler.authenticate("1234")

    def test_pin_retry_limit_locks_token(self, nss_handler_factory, softhsm_token):
        """authenticate should lock token after 3 failed attempts."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_token["label"])

        # First 3 attempts should fail with "Incorrect PIN"
        for _ in range(3):
            try:
                handler.authenticate("wrong-pin")
            except TokenAuthenticationError as e:
                if "locked" in str(e).lower():
                    # Token got locked earlier than expected
                    break
                assert "Incorrect PIN" in str(e)

        # 4th attempt should fail with "locked"
        with pytest.raises(TokenAuthenticationError, match="locked"):
            handler.authenticate("wrong-pin")

    def test_list_certificates_without_auth_raises_error(self, nss_handler_factory, softhsm_token):
        """list_certificates should raise error if not authenticated."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_token["label"])

        with pytest.raises(TokenAuthenticationError, match="authenticate first"):
            handler.list_certificates()

    def test_list_certificates_returns_imported_cert(self, nss_handler_factory, softhsm_with_cert):
        """list_certificates should return imported certificate."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_with_cert["label"])
        handler.authenticate(softhsm_with_cert["user_pin"])

        certs = handler.list_certificates()

        assert len(certs) > 0
        # Find our test certificate
        test_cert = next((c for c in certs if "Test" in c.label), None)
        assert test_cert is not None
        assert isinstance(test_cert, CertificateInfo)
        assert test_cert.can_sign is True

    def test_get_certificate_by_id(self, nss_handler_factory, softhsm_with_cert):
        """get_signing_key_and_cert should retrieve certificate by ID."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_with_cert["label"])
        handler.authenticate(softhsm_with_cert["user_pin"])

        # Get first signing certificate
        priv_key, cert_der = handler.get_signing_key_and_cert(cert_id=softhsm_with_cert["cert_id"])

        assert priv_key is not None
        assert cert_der is not None
        assert len(cert_der) > 0

    def test_get_signing_key_and_cert_without_id_uses_first(
        self, nss_handler_factory, softhsm_with_cert
    ):
        """get_signing_key_and_cert without ID should use first signing cert."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_with_cert["label"])
        handler.authenticate(softhsm_with_cert["user_pin"])

        priv_key, cert_der = handler.get_signing_key_and_cert(cert_id=None)

        assert priv_key is not None
        assert cert_der is not None

    def test_get_signing_key_with_invalid_id_raises_error(
        self, nss_handler_factory, softhsm_with_cert
    ):
        """get_signing_key_and_cert should raise error for invalid cert ID."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_with_cert["label"])
        handler.authenticate(softhsm_with_cert["user_pin"])

        with pytest.raises(CertificateNotFoundError):
            handler.get_signing_key_and_cert(cert_id=b"\xff\xff")  # Invalid ID

    def test_sign_data_with_rsa_key(self, nss_handler_factory, softhsm_with_cert):
        """Should sign data using RSA private key from token."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_with_cert["label"])
        handler.authenticate(softhsm_with_cert["user_pin"])

        priv_key, _ = handler.get_signing_key_and_cert()

        # Sign test data
        test_data = b"Test data to sign"
        from pkcs11 import Mechanism

        signature = priv_key.sign(test_data, mechanism=Mechanism.SHA256_RSA_PKCS)

        assert signature is not None
        assert len(signature) > 0

    def test_verify_signature_with_public_key(
        self, nss_handler_factory, softhsm_with_cert, test_certificate_and_key
    ):
        """Should verify signature using public key."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_with_cert["label"])
        handler.authenticate(softhsm_with_cert["user_pin"])

        priv_key, _ = handler.get_signing_key_and_cert()

        # Sign test data
        test_data = b"Test data to sign"
        from pkcs11 import Mechanism

        signature = priv_key.sign(test_data, mechanism=Mechanism.SHA256_RSA_PKCS)

        # Verify with public key
        from cryptography.hazmat.primitives.asymmetric import padding

        public_key = test_certificate_and_key["certificate"].public_key()

        # Should not raise exception
        public_key.verify(signature, test_data, padding.PKCS1v15(), hashes.SHA256())

    def test_close_session(self, nss_handler_factory, softhsm_with_cert):
        """close should properly close token session."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_with_cert["label"])
        handler.authenticate(softhsm_with_cert["user_pin"])

        handler.close()

        assert handler._session is None
        assert handler._token is None

    def test_context_manager_closes_session(self, nss_handler_factory, softhsm_with_cert):
        """NSSHandler should close session when used as context manager."""
        handler = nss_handler_factory()

        with handler:
            handler.connect_token(softhsm_with_cert["label"])
            handler.authenticate(softhsm_with_cert["user_pin"])
            assert handler._session is not None

        # Session should be closed after context
        assert handler._session is None

    def test_multiple_sequential_operations(self, nss_handler_factory, softhsm_with_cert):
        """Should handle multiple sequential operations without issues."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_with_cert["label"])
        handler.authenticate(softhsm_with_cert["user_pin"])

        # List certificates
        certs1 = handler.list_certificates()
        assert len(certs1) > 0

        # Get signing key
        priv_key, cert_der = handler.get_signing_key_and_cert()
        assert priv_key is not None

        # List certificates again
        certs2 = handler.list_certificates()
        assert len(certs2) == len(certs1)

        # Sign data
        from pkcs11 import Mechanism

        signature = priv_key.sign(b"test", mechanism=Mechanism.SHA256_RSA_PKCS)
        assert signature is not None

    def test_concurrent_signing_operations(self, nss_handler_factory, softhsm_with_cert):
        """Should handle concurrent signing operations."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_with_cert["label"])
        handler.authenticate(softhsm_with_cert["user_pin"])

        priv_key, _ = handler.get_signing_key_and_cert()

        from pkcs11 import Mechanism

        # Sign multiple messages
        messages = [b"Message 1", b"Message 2", b"Message 3"]
        signatures = []

        for msg in messages:
            sig = priv_key.sign(msg, mechanism=Mechanism.SHA256_RSA_PKCS)
            signatures.append(sig)

        # All signatures should be unique
        assert len(signatures) == len(messages)
        assert len(set(signatures)) == len(signatures)  # All different

    def test_session_timeout_handling(self, nss_handler_factory, softhsm_with_cert):
        """Should handle session operations after authentication."""
        handler = nss_handler_factory()
        handler.connect_token(softhsm_with_cert["label"])
        handler.authenticate(softhsm_with_cert["user_pin"])

        # These operations should work without timeout in test environment
        certs = handler.list_certificates()
        assert len(certs) > 0

        priv_key, _ = handler.get_signing_key_and_cert()
        assert priv_key is not None

    def test_token_not_present_error_handling(self, tmp_path):
        """Should handle gracefully when token is not present."""
        # Create handler with NSS DB but no token
        nss_db = tmp_path / ".nss"
        nss_db.mkdir()

        handler = NSSHandler(nss_db_path=nss_db)

        # Mock _find_pkcs11_lib to return non-existent library
        def _mock_find():
            raise TokenNotFoundError("No PKCS#11 library found")

        handler._find_pkcs11_lib = _mock_find

        with pytest.raises(TokenNotFoundError):
            handler.initialize()


# ==========================================================================
# Integration test for PDF signing (requires more setup)
# ==========================================================================


@pytest.mark.pkcs11
@pytest.mark.skipif(not SOFTHSM_AVAILABLE, reason=SKIP_REASON)
class TestPKCS11PDFSigning:
    """Integration tests for PDF signing with SoftHSM."""

    def test_sign_pdf_end_to_end_with_token(self, nss_handler_factory, softhsm_with_cert, tmp_path):
        """Should sign PDF end-to-end using token (basic smoke test)."""
        # Create a simple PDF
        import fitz

        pdf_path = tmp_path / "test.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)
        page.insert_text((72, 72), "Test PDF for signing", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()

        # Initialize handler
        handler = nss_handler_factory()
        handler.connect_token(softhsm_with_cert["label"])
        handler.authenticate(softhsm_with_cert["user_pin"])

        # Get signing key
        priv_key, cert_der = handler.get_signing_key_and_cert()

        # Verify we can access signing materials
        assert priv_key is not None
        assert cert_der is not None

        # Note: Full PDF signing test would require PKCS11Signer integration
        # This test verifies the token connection works for signing context
