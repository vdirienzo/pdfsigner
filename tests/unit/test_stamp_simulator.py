"""
test_stamp_simulator.py - Tests for StampSimulator (dry-run mode)

Author: Homero Thompson del Lago del Terror
"""


from pdfsigner.core.mock.stamp_simulator import (
    get_stamp_rect,
    parse_page_spec,
)


class TestParsePageSpec:
    """Tests for parse_page_spec function."""

    def test_parse_last(self):
        """Test parsing 'last' page spec."""
        result = parse_page_spec("last", total_pages=5)
        assert result == [4]  # 0-indexed

    def test_parse_first(self):
        """Test parsing 'first' page spec."""
        result = parse_page_spec("first", total_pages=5)
        assert result == [0]

    def test_parse_all(self):
        """Test parsing 'all' page spec."""
        result = parse_page_spec("all", total_pages=5)
        assert result == [0, 1, 2, 3, 4]

    def test_parse_integer(self):
        """Test parsing integer page spec."""
        result = parse_page_spec(3, total_pages=5)
        assert result == [3]

    def test_parse_integer_exceeds_pages(self):
        """Test integer exceeding total pages."""
        result = parse_page_spec(10, total_pages=5)
        assert result == [4]  # Should clamp to last page

    def test_parse_single_number_string(self):
        """Test parsing single number as string."""
        result = parse_page_spec("3", total_pages=5)
        assert result == [2]  # 1-indexed to 0-indexed

    def test_parse_comma_separated(self):
        """Test parsing comma-separated list."""
        result = parse_page_spec("1,3,5", total_pages=5)
        assert result == [0, 2, 4]

    def test_parse_range(self):
        """Test parsing range specification."""
        result = parse_page_spec("2-4", total_pages=5)
        assert result == [1, 2, 3]

    def test_parse_invalid_returns_last(self):
        """Test invalid spec returns last page."""
        result = parse_page_spec("invalid", total_pages=5)
        assert result == [4]

    def test_parse_filters_out_of_range(self):
        """Test out of range pages are filtered."""
        result = parse_page_spec("1,10,20", total_pages=5)
        assert result == [0]  # Only page 1 is valid


class TestGetStampRect:
    """Tests for get_stamp_rect function."""

    def test_bottom_right_position(self):
        """Test bottom-right positioning."""
        rect = get_stamp_rect(
            page_width=612,
            page_height=792,
            position="bottom_right",
            stamp_width=140,
            stamp_height=50,
        )

        # Should be near bottom-right corner
        assert rect.x1 < 612  # Within page width
        assert rect.y1 < 792  # Within page height
        assert rect.x0 > 400  # In right half
        assert rect.y0 > 700  # Near bottom

    def test_bottom_left_position(self):
        """Test bottom-left positioning."""
        rect = get_stamp_rect(
            page_width=612,
            page_height=792,
            position="bottom_left",
            stamp_width=140,
            stamp_height=50,
        )

        # Should be near bottom-left corner
        assert rect.x0 < 100  # In left portion
        assert rect.y0 > 700  # Near bottom

    def test_top_right_position(self):
        """Test top-right positioning."""
        rect = get_stamp_rect(
            page_width=612,
            page_height=792,
            position="top_right",
            stamp_width=140,
            stamp_height=50,
        )

        # Should be near top-right corner
        assert rect.x0 > 400  # In right half
        assert rect.y0 < 100  # Near top

    def test_top_left_position(self):
        """Test top-left positioning."""
        rect = get_stamp_rect(
            page_width=612,
            page_height=792,
            position="top_left",
            stamp_width=140,
            stamp_height=50,
        )

        # Should be near top-left corner
        assert rect.x0 < 100  # In left portion
        assert rect.y0 < 100  # Near top

    def test_auto_position(self):
        """Test auto positioning defaults to bottom-right."""
        rect = get_stamp_rect(
            page_width=612,
            page_height=792,
            position="auto",
            stamp_width=140,
            stamp_height=50,
        )

        # Auto should default to bottom-right
        assert rect.x0 > 400
        assert rect.y0 > 700

    def test_stamp_dimensions(self):
        """Test stamp has correct dimensions."""
        rect = get_stamp_rect(
            page_width=612,
            page_height=792,
            position="bottom_right",
            stamp_width=140,
            stamp_height=50,
        )

        assert rect.width == 140
        assert rect.height == 50
