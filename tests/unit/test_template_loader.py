"""
test_template_loader.py - Tests for template loading and saving

Tests template discovery, loading, saving, and path traversal prevention.
"""

import json
from pathlib import Path

import pytest

from pdfsigner.core.security.path_sanitizer import PathTraversalError
from pdfsigner.core.signature.template import Layer, Template
from pdfsigner.core.signature.template_loader import (
    delete_user_template,
    get_builtin_templates_dir,
    get_template_info,
    get_user_templates_dir,
    list_all_templates,
    list_builtin_templates,
    list_user_templates,
    load_template,
    load_template_from_path,
    save_user_template,
)


class TestListBuiltinTemplates:
    """Tests for list_builtin_templates function."""

    def test_list_builtin_templates_returns_expected(self):
        """Builtin templates should include known templates."""
        templates = list_builtin_templates()

        assert isinstance(templates, list)
        assert "default" in templates
        assert "corporate" in templates
        assert "minimal" in templates
        assert "with_qr" in templates

    def test_list_builtin_templates_sorted(self):
        """Templates should be returned in sorted order."""
        templates = list_builtin_templates()
        assert templates == sorted(templates)

    def test_list_builtin_templates_no_json_extension(self):
        """Template names should not include .json extension."""
        templates = list_builtin_templates()

        for name in templates:
            assert not name.endswith(".json")


class TestListUserTemplates:
    """Tests for list_user_templates function."""

    def test_list_user_templates_empty_when_no_dir(self, tmp_path: Path, monkeypatch):
        """Should return empty list when user templates dir doesn't exist."""
        nonexistent = tmp_path / "nonexistent"
        monkeypatch.setattr(
            "pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR",
            nonexistent,
        )

        templates = list_user_templates()
        assert templates == []

    def test_list_user_templates_finds_json_files(self, tmp_path: Path, monkeypatch):
        """Should find JSON files in user templates directory."""
        monkeypatch.setattr(
            "pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR",
            tmp_path,
        )

        # Create test JSON files
        (tmp_path / "custom1.json").write_text('{"name": "custom1", "layers": []}')
        (tmp_path / "custom2.json").write_text('{"name": "custom2", "layers": []}')
        (tmp_path / "readme.txt").write_text("ignored")

        templates = list_user_templates()

        assert "custom1" in templates
        assert "custom2" in templates
        assert "readme" not in templates


class TestListAllTemplates:
    """Tests for list_all_templates function."""

    def test_list_all_templates_includes_builtin(self):
        """Should include builtin templates."""
        templates = list_all_templates()
        names = [t[0] for t in templates]
        sources = [t[1] for t in templates]

        assert "default" in names
        assert "builtin" in sources

    def test_list_all_templates_sorted(self):
        """Templates should be sorted by name."""
        templates = list_all_templates()
        names = [t[0] for t in templates]
        assert names == sorted(names)


class TestLoadTemplate:
    """Tests for load_template function."""

    def test_load_template_builtin_success(self):
        """Should successfully load builtin template."""
        template = load_template("default")

        assert template is not None
        assert template.name == "default"
        assert len(template.layers) > 0

    def test_load_template_nonexistent_returns_none(self):
        """Non-existent template should return None."""
        template = load_template("this_template_does_not_exist_xyz123")
        assert template is None

    def test_load_template_path_traversal_blocked(self):
        """Path traversal attempts should raise PathTraversalError."""
        with pytest.raises(PathTraversalError, match="Parent directory"):
            load_template("../../../etc/passwd")

    def test_load_template_path_traversal_double_dot(self):
        """Double dot sequences should be blocked."""
        with pytest.raises(PathTraversalError, match="Parent directory"):
            load_template("..%2f..%2f/etc/passwd")

    def test_load_template_path_traversal_absolute(self):
        """Absolute paths should be blocked."""
        with pytest.raises(PathTraversalError, match="Absolute paths"):
            load_template("/etc/passwd")

    def test_load_template_null_byte_blocked(self):
        """Null byte injection should be blocked."""
        with pytest.raises(PathTraversalError, match="Null bytes"):
            load_template("template\x00.json")

    def test_load_template_user_overrides_builtin(self, tmp_path: Path, monkeypatch):
        """User template with same name should override builtin."""
        monkeypatch.setattr(
            "pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR",
            tmp_path,
        )

        # Create user template with builtin name
        user_template = {
            "name": "default",
            "description": "User override",
            "width_mm": 70,
            "height_mm": 30,
            "layers": [{"type": "background", "color": "#ff0000"}],
        }
        (tmp_path / "default.json").write_text(json.dumps(user_template))

        template = load_template("default")

        assert template is not None
        assert template.description == "User override"
        assert template.width_mm == 70


class TestLoadTemplateFromPath:
    """Tests for load_template_from_path function."""

    def test_load_template_from_path_success(self, tmp_path: Path):
        """Should load template from explicit path."""
        template_data = {
            "name": "path_test",
            "description": "Test",
            "layers": [{"type": "background"}],
        }
        template_path = tmp_path / "test_template.json"
        template_path.write_text(json.dumps(template_data))

        template = load_template_from_path(template_path)

        assert template is not None
        assert template.name == "path_test"

    def test_load_template_from_path_invalid_json_returns_none(self, tmp_path: Path):
        """Invalid JSON should return None."""
        invalid_path = tmp_path / "invalid.json"
        invalid_path.write_text("{ not valid json }")

        template = load_template_from_path(invalid_path)
        assert template is None

    def test_load_template_from_path_nonexistent_returns_none(self, tmp_path: Path):
        """Non-existent file should return None."""
        template = load_template_from_path(tmp_path / "nonexistent.json")
        assert template is None


class TestGetTemplateInfo:
    """Tests for get_template_info function."""

    def test_get_template_info_returns_metadata(self):
        """Should return basic template info without full load."""
        info = get_template_info("corporate")

        assert info is not None
        assert info["name"] == "corporate"
        assert "width_mm" in info
        assert "height_mm" in info
        assert "description" in info

    def test_get_template_info_nonexistent_returns_none(self):
        """Non-existent template should return None."""
        info = get_template_info("nonexistent_template_xyz")
        assert info is None


class TestSaveUserTemplate:
    """Tests for save_user_template function."""

    def test_save_user_template_creates_file(self, tmp_path: Path, monkeypatch):
        """Should create JSON file in user templates directory."""
        monkeypatch.setattr(
            "pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR",
            tmp_path,
        )

        template = Template(
            name="my_custom",
            description="Custom template",
            width_mm=50,
            height_mm=20,
            layers=[Layer(type="background", color="#ffffff")],
        )

        saved_path = save_user_template(template)

        assert saved_path.exists()
        assert saved_path.name == "my_custom.json"
        assert saved_path.parent == tmp_path

        # Verify JSON content
        with open(saved_path) as f:
            data = json.load(f)
        assert data["name"] == "my_custom"
        assert data["description"] == "Custom template"

    def test_save_user_template_creates_directory(self, tmp_path: Path, monkeypatch):
        """Should create user templates directory if it doesn't exist."""
        new_dir = tmp_path / "templates" / "user"
        monkeypatch.setattr(
            "pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR",
            new_dir,
        )

        template = Template(
            name="test",
            layers=[Layer(type="background")],
        )

        saved_path = save_user_template(template)

        assert new_dir.exists()
        assert saved_path.exists()

    def test_save_user_template_path_traversal_blocked(self, tmp_path: Path, monkeypatch):
        """Path traversal in template name should be blocked."""
        monkeypatch.setattr(
            "pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR",
            tmp_path,
        )

        template = Template(
            name="../../../etc/passwd",
            layers=[Layer(type="background")],
        )

        with pytest.raises(PathTraversalError, match="Parent directory"):
            save_user_template(template)

    def test_save_user_template_validation_fails(self, tmp_path: Path, monkeypatch):
        """Invalid template should raise ValueError."""
        monkeypatch.setattr(
            "pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR",
            tmp_path,
        )

        # Template with no layers is invalid (name is valid for sanitizer)
        template = Template(
            name="valid_name",
            layers=[],  # Empty layers list is invalid
        )

        with pytest.raises(ValueError, match="validation failed"):
            save_user_template(template)


class TestDeleteUserTemplate:
    """Tests for delete_user_template function."""

    def test_delete_user_template_removes_file(self, tmp_path: Path, monkeypatch):
        """Should delete existing user template file."""
        monkeypatch.setattr(
            "pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR",
            tmp_path,
        )

        # Create template file
        template_path = tmp_path / "to_delete.json"
        template_path.write_text('{"name": "to_delete", "layers": []}')

        result = delete_user_template("to_delete")

        assert result is True
        assert not template_path.exists()

    def test_delete_user_template_nonexistent_returns_false(self, tmp_path: Path, monkeypatch):
        """Deleting non-existent template should return False."""
        monkeypatch.setattr(
            "pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR",
            tmp_path,
        )

        result = delete_user_template("nonexistent")
        assert result is False

    def test_delete_user_template_path_traversal_blocked(self, tmp_path: Path, monkeypatch):
        """Path traversal in delete should be blocked."""
        monkeypatch.setattr(
            "pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR",
            tmp_path,
        )

        with pytest.raises(PathTraversalError, match="Parent directory"):
            delete_user_template("../../../etc/passwd")


class TestBuiltinTemplatesDirectory:
    """Tests for builtin templates directory functions."""

    def test_get_builtin_templates_dir_exists(self):
        """Builtin templates directory should exist."""
        dir_path = get_builtin_templates_dir()

        assert dir_path.exists()
        assert dir_path.is_dir()

    def test_get_user_templates_dir_returns_path(self):
        """User templates directory function should return path."""
        dir_path = get_user_templates_dir()

        assert isinstance(dir_path, Path)
        assert str(dir_path).endswith("templates")

    def test_builtin_templates_dir_has_expected_files(self):
        """Builtin directory should contain expected template files."""
        dir_path = get_builtin_templates_dir()

        assert (dir_path / "default.json").exists()
        assert (dir_path / "corporate.json").exists()
        assert (dir_path / "minimal.json").exists()
        assert (dir_path / "with_qr.json").exists()


class TestPathTraversalAttackVectors:
    """Tests for various path traversal attack patterns."""

    @pytest.mark.parametrize(
        "malicious_name",
        [
            "../secret",
            "..\\secret",
            "....//secret",
            "./../../etc/passwd",
            "templates/../../../etc/passwd",
            "..%2f..%2fetc%2fpasswd",
            "..%252f..%252fetc",
        ],
    )
    def test_load_template_blocks_traversal_patterns(self, malicious_name: str):
        """Various traversal patterns should be blocked."""
        with pytest.raises(PathTraversalError):
            load_template(malicious_name)

    @pytest.mark.parametrize(
        "malicious_name",
        [
            "/etc/passwd",
            "C:\\Windows\\System32",
            "\\\\server\\share",
        ],
    )
    def test_load_template_blocks_absolute_paths(self, malicious_name: str):
        """Absolute paths should be blocked."""
        with pytest.raises(PathTraversalError):
            load_template(malicious_name)
