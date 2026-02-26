"""Archive Timestamp manager for PAdES-LTA signatures."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from loguru import logger
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import PdfTimeStamper
from pyhanko.sign.timestamps import HTTPTimeStamper

from pdfsigner.exceptions import TSAConnectionError


@dataclass
class ArchiveTimestampInfo:
    """Information about an archive timestamp in a PDF."""

    timestamp: datetime
    tsa_url: str | None
    hash_algorithm: str
    covers_dss: bool  # True if timestamp covers DSS dictionary


class ArchiveTimestampManager:
    """Manages archive timestamps for PAdES-LTA compliance."""

    def __init__(
        self,
        tsa_urls: list[str],
        timeout: int = 30,
    ):
        """
        Initialize with list of TSA URLs (fallback order).

        Args:
            tsa_urls: List of TSA URLs to try in order
            timeout: Timeout per TSA request in seconds
        """
        self.timestampers = [HTTPTimeStamper(url=url, timeout=timeout) for url in tsa_urls if url]
        self.timeout = timeout

        if not self.timestampers:
            logger.warning("ArchiveTimestampManager initialized without TSA URLs")

    def add_archive_timestamp(
        self,
        pdf_path: Path,
        output_path: Path | None = None,
    ) -> Path:
        """
        Add an archive timestamp to a signed PDF.

        The archive timestamp covers the entire document including
        previous signatures and the DSS dictionary.

        Args:
            pdf_path: Path to signed PDF
            output_path: Output path (defaults to overwrite input)

        Returns:
            Path to timestamped PDF

        Raises:
            TSAConnectionError: If all TSA servers fail
        """
        if not self.timestampers:
            raise TSAConnectionError("No TSA URLs configured")

        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        output = output_path or pdf_path

        # Try each TSA in order until one succeeds
        last_error: Exception | None = None

        for timestamper in self.timestampers:
            try:
                logger.debug(f"Attempting archive timestamp with {timestamper.url}")

                pdf_timestamper = PdfTimeStamper(timestamper)

                # Read and timestamp the PDF
                with open(pdf_path, "rb") as inf:
                    with open(output, "wb") as outf:
                        reader = PdfFileReader(inf, strict=False)
                        writer = IncrementalPdfFileWriter(outf, reader)

                        pdf_timestamper.timestamp_pdf(
                            writer,
                            # md_algorithm='sha256'  # Optional: specify hash algorithm
                        )

                logger.info(f"Archive timestamp added using {timestamper.url}")
                return output

            except Exception as e:
                logger.warning(f"TSA {timestamper.url} failed: {e}")
                last_error = e
                continue

        # All TSAs failed
        error_msg = "All TSA servers failed"
        if last_error:
            error_msg = f"{error_msg}: {last_error}"

        raise TSAConnectionError(error_msg)

    def get_archive_timestamps(
        self,
        pdf_path: Path,
    ) -> list[ArchiveTimestampInfo]:
        """
        Get list of archive timestamps in a PDF.

        Returns:
            List of ArchiveTimestampInfo for each archive TS found
        """
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        timestamps: list[ArchiveTimestampInfo] = []

        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f, strict=False)

                # Check for DSS dictionary (indicates LTV)
                dss_dict = reader.root.get("/DSS")
                has_dss = dss_dict is not None

                # Iterate through signature fields to find document timestamps
                if "/AcroForm" not in reader.root:
                    return timestamps

                acro_form = reader.root["/AcroForm"]
                if "/Fields" not in acro_form:
                    return timestamps

                fields = acro_form["/Fields"]

                for field_ref in fields:
                    field = field_ref.get_object()

                    # Check if it's a signature field
                    if field.get("/FT") != "/Sig":
                        continue

                    sig_value = field.get("/V")
                    if sig_value is None:
                        continue

                    sig_dict = (
                        sig_value.get_object() if hasattr(sig_value, "get_object") else sig_value
                    )

                    # Check if it's a document timestamp (not a signature)
                    subfilter = sig_dict.get("/SubFilter")
                    if subfilter not in ("/ETSI.RFC3161", "/adbe.x509.rfc3161"):
                        continue

                    # Extract timestamp info
                    try:
                        # Get timestamp token
                        contents = sig_dict.get("/Contents")
                        if contents:
                            ts_info = self._parse_timestamp_token(contents)
                            ts_info = ArchiveTimestampInfo(
                                timestamp=ts_info.timestamp,
                                tsa_url=ts_info.tsa_url,
                                hash_algorithm=ts_info.hash_algorithm,
                                covers_dss=has_dss,
                            )
                            timestamps.append(ts_info)

                    except Exception as e:
                        logger.warning(f"Failed to parse timestamp: {e}")
                        continue

        except Exception as e:
            logger.error(f"Error reading archive timestamps from {pdf_path}: {e}")

        return timestamps

    def needs_archive_timestamp(
        self,
        pdf_path: Path,
        algorithm_threshold_years: int = 10,
    ) -> bool:
        """
        Check if PDF needs a new archive timestamp.

        Returns True if:
        - No archive timestamps exist
        - Last archive TS is older than threshold
        - Signature algorithms are near end-of-life

        Args:
            pdf_path: Path to PDF
            algorithm_threshold_years: Years before algorithm renewal needed

        Returns:
            True if a new archive timestamp is needed
        """
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        try:
            # Get existing archive timestamps
            timestamps = self.get_archive_timestamps(pdf_path)

            # If no archive timestamps exist, one is needed
            if not timestamps:
                logger.debug(f"No archive timestamps found in {pdf_path.name}")
                return True

            # Check if the last timestamp is too old
            latest_timestamp = max(ts.timestamp for ts in timestamps)
            # Ensure both are aware for comparison (pyHanko may return naive)
            now = datetime.now(UTC)
            if latest_timestamp.tzinfo is None:
                latest_timestamp = latest_timestamp.replace(tzinfo=UTC)
            age = now - latest_timestamp

            threshold = timedelta(days=algorithm_threshold_years * 365)

            if age > threshold:
                logger.info(
                    f"Last archive timestamp is {age.days} days old, "
                    f"threshold is {threshold.days} days"
                )
                return True

            # Check for weak algorithms (SHA-1, MD5)
            weak_algorithms = {"sha1", "md5", "md2"}
            for ts in timestamps:
                if ts.hash_algorithm.lower() in weak_algorithms:
                    logger.warning(f"Weak hash algorithm detected: {ts.hash_algorithm}")
                    return True

            logger.debug(f"Archive timestamp in {pdf_path.name} is still valid")
            return False

        except Exception as e:
            logger.error(f"Error checking archive timestamp status: {e}")
            # Conservative: assume timestamp is needed if we can't determine status
            return True

    def _parse_timestamp_token(self, token_bytes: bytes) -> ArchiveTimestampInfo:
        """Parse RFC 3161 timestamp token from DER bytes.

        Extracts timestamp, hash algorithm, and TSA name from a
        TimeStampToken per RFC 3161 / IETF RFC 5652 (CMS).

        Uses ``asn1crypto`` for inner ASN.1 parsing of the TSTInfo
        structure, since the ``cryptography`` library does not expose
        TSTInfo fields directly.

        Args:
            token_bytes: Raw DER-encoded timestamp token bytes.

        Returns:
            ArchiveTimestampInfo with parsed data.
        """
        from datetime import UTC

        from asn1crypto import cms, tsp

        try:
            # The token is a CMS ContentInfo wrapping a SignedData
            content_info = cms.ContentInfo.load(token_bytes)
            signed_data = content_info["content"]

            # The TSTInfo is inside the encapsulated content
            encap_content = signed_data["encap_content_info"]
            tst_info = tsp.TSTInfo.load(encap_content["content"].native)

            # Extract generation time
            gen_time: datetime = tst_info["gen_time"].native
            if gen_time.tzinfo is None:
                gen_time = gen_time.replace(tzinfo=UTC)

            # Extract hash algorithm from MessageImprint
            msg_imprint = tst_info["message_imprint"]
            hash_oid = msg_imprint["hash_algorithm"]["algorithm"].native
            # asn1crypto returns human-readable names like 'sha256'
            hash_algorithm = str(hash_oid) if hash_oid else "unknown"

            # Try to extract TSA name from signer certificate
            tsa_name: str | None = None
            try:
                signer_infos = signed_data["signer_infos"]
                if signer_infos and len(signer_infos) > 0:
                    # Try to get TSA name from the signer's issuer
                    sid = signer_infos[0]["sid"]
                    if sid.name == "issuer_and_serial_number":
                        issuer = sid.chosen["issuer"]
                        tsa_name = issuer.human_friendly
            except Exception:
                # TSA name extraction is best-effort
                pass

            return ArchiveTimestampInfo(
                timestamp=gen_time,
                tsa_url=tsa_name,
                hash_algorithm=hash_algorithm,
                covers_dss=False,
            )

        except Exception as e:
            logger.warning("Failed to parse timestamp token: %s", e)
            return ArchiveTimestampInfo(
                timestamp=datetime.now(UTC),
                hash_algorithm="unknown",
                tsa_url="",
                covers_dss=False,
            )
