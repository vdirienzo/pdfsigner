"""
test_signature_metadata.py - Test signature metadata fields (reason/location/contact)

Author: Homero Thompson del Lago del Terror

Tests the extended signature metadata fields in PDF signing.
"""

from unittest.mock import MagicMock, Mock, patch

from pdfsigner.core.signer.pdf_signer import PDFSigner, SignatureAppearance


class TestSignatureMetadata:
    """Test suite for signature metadata fields."""

    def test_sign_pdf_accepts_reason_parameter(
        self, mock_nss_handler, mock_lta_handler, sample_pdf
    ):
        """Test that sign_pdf accepts reason parameter."""
        signer = PDFSigner(mock_nss_handler, mock_lta_handler)

        # Mock the internal methods to avoid actual signing
        with (
            patch.object(signer, "_prepare_signing_context") as mock_prepare,
            patch.object(signer, "_preprocess_pdf_with_stamps") as mock_preprocess,
            patch.object(signer, "_execute_signing") as mock_execute,
            patch(
                "pdfsigner.core.signer.signature_field.create_signature_field_with_stamps"
            ) as mock_field,
        ):
            # Setup mocks
            mock_prepare.return_value = (Mock(), None, "Test Signer", "Test Org", 0)
            mock_field.return_value = Mock(field_spec=None, visual_stamps=[])
            mock_preprocess.return_value = (sample_pdf, None)

            # Call sign_pdf with reason
            signer.sign_pdf(
                input_path=sample_pdf,
                appearance=SignatureAppearance(visible=False),
                reason="I approve this document",
            )

            # Verify execute_signing was called with reason parameter
            assert mock_execute.called
            call_kwargs = mock_execute.call_args[1]
            assert call_kwargs["reason"] == "I approve this document"

    def test_sign_pdf_accepts_location_parameter(
        self, mock_nss_handler, mock_lta_handler, sample_pdf
    ):
        """Test that sign_pdf accepts location parameter."""
        signer = PDFSigner(mock_nss_handler, mock_lta_handler)

        with (
            patch.object(signer, "_prepare_signing_context") as mock_prepare,
            patch.object(signer, "_preprocess_pdf_with_stamps") as mock_preprocess,
            patch.object(signer, "_execute_signing") as mock_execute,
            patch(
                "pdfsigner.core.signer.signature_field.create_signature_field_with_stamps"
            ) as mock_field,
        ):
            mock_prepare.return_value = (Mock(), None, "Test Signer", "Test Org", 0)
            mock_field.return_value = Mock(field_spec=None, visual_stamps=[])
            mock_preprocess.return_value = (sample_pdf, None)

            signer.sign_pdf(
                input_path=sample_pdf,
                appearance=SignatureAppearance(visible=False),
                location="New York, NY",
            )

            assert mock_execute.called
            call_kwargs = mock_execute.call_args[1]
            assert call_kwargs["location"] == "New York, NY"

    def test_sign_pdf_accepts_contact_info_parameter(
        self, mock_nss_handler, mock_lta_handler, sample_pdf
    ):
        """Test that sign_pdf accepts contact_info parameter."""
        signer = PDFSigner(mock_nss_handler, mock_lta_handler)

        with (
            patch.object(signer, "_prepare_signing_context") as mock_prepare,
            patch.object(signer, "_preprocess_pdf_with_stamps") as mock_preprocess,
            patch.object(signer, "_execute_signing") as mock_execute,
            patch(
                "pdfsigner.core.signer.signature_field.create_signature_field_with_stamps"
            ) as mock_field,
        ):
            mock_prepare.return_value = (Mock(), None, "Test Signer", "Test Org", 0)
            mock_field.return_value = Mock(field_spec=None, visual_stamps=[])
            mock_preprocess.return_value = (sample_pdf, None)

            signer.sign_pdf(
                input_path=sample_pdf,
                appearance=SignatureAppearance(visible=False),
                contact_info="email@company.com",
            )

            assert mock_execute.called
            call_kwargs = mock_execute.call_args[1]
            assert call_kwargs["contact_info"] == "email@company.com"

    def test_sign_pdf_accepts_all_metadata_parameters(
        self, mock_nss_handler, mock_lta_handler, sample_pdf
    ):
        """Test that sign_pdf accepts all metadata parameters."""
        signer = PDFSigner(mock_nss_handler, mock_lta_handler)

        with (
            patch.object(signer, "_prepare_signing_context") as mock_prepare,
            patch.object(signer, "_preprocess_pdf_with_stamps") as mock_preprocess,
            patch.object(signer, "_execute_signing") as mock_execute,
            patch(
                "pdfsigner.core.signer.signature_field.create_signature_field_with_stamps"
            ) as mock_field,
        ):
            mock_prepare.return_value = (Mock(), None, "Test Signer", "Test Org", 0)
            mock_field.return_value = Mock(field_spec=None, visual_stamps=[])
            mock_preprocess.return_value = (sample_pdf, None)

            signer.sign_pdf(
                input_path=sample_pdf,
                appearance=SignatureAppearance(visible=False),
                reason="I approve this document",
                location="New York, NY",
                contact_info="email@company.com",
            )

            assert mock_execute.called
            call_kwargs = mock_execute.call_args[1]
            assert call_kwargs["reason"] == "I approve this document"
            assert call_kwargs["location"] == "New York, NY"
            assert call_kwargs["contact_info"] == "email@company.com"

    def test_execute_signing_passes_metadata_to_pyhanko(
        self, mock_nss_handler, mock_lta_handler, sample_pdf
    ):
        """Test that _execute_signing passes metadata to PdfSignatureMetadata."""
        signer = PDFSigner(mock_nss_handler, mock_lta_handler)

        with (
            patch("pdfsigner.core.signer.pdf_signer.IncrementalPdfFileWriter") as mock_writer,
            patch("pdfsigner.core.signer.pdf_signer.signers.PdfSignatureMetadata") as mock_metadata,
            patch("pdfsigner.core.signer.pdf_signer.signers.PdfSigner") as mock_pdf_signer,
            patch.object(signer, "_build_stamp_style", return_value=None),
        ):
            # Setup mocks
            mock_writer_instance = MagicMock()
            mock_writer.return_value = mock_writer_instance
            mock_pdf_signer_instance = MagicMock()
            mock_pdf_signer.return_value = mock_pdf_signer_instance

            mock_signer = MagicMock()
            mock_field_result = Mock(field_spec=None, visual_stamps=[])

            # Call _execute_signing with metadata
            signer._execute_signing(
                pdf_to_sign=sample_pdf,
                output_path=sample_pdf.with_stem(f"{sample_pdf.stem}_signed"),
                input_path=sample_pdf,
                field_result=mock_field_result,
                signer=mock_signer,
                timestamper=None,
                appearance=SignatureAppearance(visible=False),
                signer_name="Test Signer",
                organization="Test Org",
                existing_sig_count=0,
                template_override=None,
                reason="I approve this document",
                location="New York, NY",
                contact_info="email@company.com",
            )

            # Verify PdfSignatureMetadata was called with metadata
            assert mock_metadata.called
            call_kwargs = mock_metadata.call_args[1]
            assert call_kwargs["reason"] == "I approve this document"
            assert call_kwargs["location"] == "New York, NY"
            assert call_kwargs["contact_info"] == "email@company.com"

    def test_execute_signing_converts_empty_strings_to_none(
        self, mock_nss_handler, mock_lta_handler, sample_pdf
    ):
        """Test that _execute_signing converts empty strings to None for pyHanko."""
        signer = PDFSigner(mock_nss_handler, mock_lta_handler)

        with (
            patch("pdfsigner.core.signer.pdf_signer.IncrementalPdfFileWriter") as mock_writer,
            patch("pdfsigner.core.signer.pdf_signer.signers.PdfSignatureMetadata") as mock_metadata,
            patch("pdfsigner.core.signer.pdf_signer.signers.PdfSigner") as mock_pdf_signer,
            patch.object(signer, "_build_stamp_style", return_value=None),
        ):
            mock_writer_instance = MagicMock()
            mock_writer.return_value = mock_writer_instance
            mock_pdf_signer_instance = MagicMock()
            mock_pdf_signer.return_value = mock_pdf_signer_instance

            mock_signer = MagicMock()
            mock_field_result = Mock(field_spec=None, visual_stamps=[])

            # Call with empty strings
            signer._execute_signing(
                pdf_to_sign=sample_pdf,
                output_path=sample_pdf.with_stem(f"{sample_pdf.stem}_signed"),
                input_path=sample_pdf,
                field_result=mock_field_result,
                signer=mock_signer,
                timestamper=None,
                appearance=SignatureAppearance(visible=False),
                signer_name="Test Signer",
                organization="Test Org",
                existing_sig_count=0,
                template_override=None,
                reason="",
                location="",
                contact_info="",
            )

            # Verify empty strings were converted to None
            assert mock_metadata.called
            call_kwargs = mock_metadata.call_args[1]
            assert call_kwargs["reason"] is None
            assert call_kwargs["location"] is None
            assert call_kwargs["contact_info"] is None

    def test_batch_manager_accepts_metadata_parameters(
        self, mock_nss_handler, mock_lta_handler, sample_pdf
    ):
        """Test that BatchManager accepts and passes metadata parameters."""
        from pdfsigner.core.signer.batch_manager import BatchManager

        batch_manager = BatchManager(mock_nss_handler, mock_lta_handler)

        with patch.object(batch_manager, "_get_signer") as mock_get_signer:
            mock_signer = MagicMock()
            mock_get_signer.return_value = mock_signer
            mock_signer.sign_pdf.return_value = Mock(success=True)

            batch_manager.sign_batch(
                pdf_files=[sample_pdf],
                appearance=SignatureAppearance(visible=False),
                reason="I approve this document",
                location="New York, NY",
                contact_info="email@company.com",
            )

            # Verify sign_pdf was called with metadata
            assert mock_signer.sign_pdf.called
            call_kwargs = mock_signer.sign_pdf.call_args[1]
            assert call_kwargs["reason"] == "I approve this document"
            assert call_kwargs["location"] == "New York, NY"
            assert call_kwargs["contact_info"] == "email@company.com"

    def test_options_dialog_has_metadata_getters(self):
        """Test that SignatureOptionsDialog has get_signature_metadata method."""
        from pdfsigner.ui.dialogs.options_dialog import SignatureOptionsDialog

        # Verify the method exists
        assert hasattr(SignatureOptionsDialog, "get_signature_metadata")

        # Verify the method signature
        import inspect

        sig = inspect.signature(SignatureOptionsDialog.get_signature_metadata)
        # Should return dict[str, str]
        assert sig.return_annotation == dict[str, str]

    def test_settings_has_metadata_fields(self):
        """Test that Settings has default metadata fields."""
        from pdfsigner.config.settings import Settings

        settings = Settings()

        # Verify fields exist
        assert hasattr(settings, "default_signature_reason")
        assert hasattr(settings, "default_signature_location")
        assert hasattr(settings, "default_signature_contact")

        # Verify default values
        assert settings.default_signature_reason == ""
        assert settings.default_signature_location == ""
        assert settings.default_signature_contact == ""
