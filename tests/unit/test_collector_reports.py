import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "services" / "collector-reports" / "main.py"
SPEC = importlib.util.spec_from_file_location("collector_reports_main", MODULE_PATH)
collector_reports_main = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(collector_reports_main)

load_state = collector_reports_main.load_state
parse_cisa_reports = collector_reports_main.parse_cisa_reports
parse_feed_items = collector_reports_main.parse_feed_items
save_state = collector_reports_main.save_state
safe_text = collector_reports_main.safe_text


def test_safe_text_strips_none_and_whitespace() -> None:
    assert safe_text(None) == ""
    assert safe_text("  hello \n") == "hello"


def test_parse_cisa_reports_finds_links_from_html() -> None:
    html = """
    <html>
      <body>
        <a href="/known-exploited-vulnerabilities-catalog/cve/CVE-2025-0001">CVE-2025-0001</a>
      </body>
    </html>
    """
    reports = parse_cisa_reports(html)
    assert len(reports) == 1
    assert reports[0]["source_name"] == "cisa"
    assert reports[0]["url"] == "https://www.cisa.gov/known-exploited-vulnerabilities-catalog/cve/CVE-2025-0001"
    assert reports[0]["title"] == "CVE-2025-0001"


def test_parse_feed_items_ignores_duplicate_urls() -> None:
    class DummyEntry:
        def __init__(self, link: str, title: str) -> None:
            self.link = link
            self.title = title
            self.summary = "Test summary"

    class Feed:
        entries = [
            DummyEntry("https://example.com/report-1", "Report One"),
            DummyEntry("https://example.com/report-1", "Report One Duplicate"),
        ]

    reports = parse_feed_items(Feed(), "msrc")
    assert len(reports) == 1
    assert reports[0]["title"] == "Report One"
    assert reports[0]["source_name"] == "msrc"


def test_state_file_roundtrip(tmp_path: Path) -> None:
    state_path = tmp_path / "collector_reports_state.json"
    state = {"seen_urls": ["https://example.com/report-1"]}
    save_state(str(state_path), state)
    loaded = load_state(str(state_path))
    assert loaded["seen_urls"] == ["https://example.com/report-1"]

    # a malformed state file should reset safely
    state_path.write_text("not valid json", encoding="utf-8")
    loaded = load_state(str(state_path))
    assert loaded == {"seen_urls": []}
