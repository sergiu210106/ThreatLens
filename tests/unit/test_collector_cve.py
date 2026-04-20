import importlib.util
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "services" / "collector-cve" / "main.py"

spec = importlib.util.spec_from_file_location("collector_cve_main", MODULE_PATH)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def test_normalize_cve_item_minimal():
    item = {
        "id": "CVE-2024-1234",
        "published": "2024-01-15T10:00:00Z",
        "cve": {
            "metadata": {"title": "Sample vulnerability"},
            "descriptions": [{"lang": "en", "value": "A sample CVE description."}],
        },
        "metrics": {
            "cvssMetricV3": [
                {"cvssData": {"baseSeverity": "CRITICAL", "baseScore": 9.8}}
            ]
        },
        "configurations": {
            "nodes": [
                {
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*"}
                    ]
                }
            ]
        },
    }
    collected_at = datetime(2024, 1, 15, 10, 15, tzinfo=timezone.utc)
    normalized = collector.normalize_cve_item(item, collected_at)

    assert normalized["source"] == "nvd"
    assert normalized["source_id"] == "CVE-2024-1234"
    assert normalized["title"] == "Sample vulnerability"
    assert normalized["description"] == "A sample CVE description."
    assert normalized["severity"] == "CRITICAL"
    assert normalized["cvss_score"] == 9.8
    assert normalized["published_at"] == "2024-01-15T10:00:00Z"
    assert normalized["collected_at"] == "2024-01-15T10:15:00Z"
    assert normalized["affected_software"] == ["cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*"]
    assert isinstance(normalized["raw_data"], dict)


def test_extract_software_from_nested_nodes():
    item = {
        "configurations": {
            "nodes": [
                {
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}
                    ],
                    "children": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:vendor:product:1.1:*:*:*:*:*:*:*"}
                            ]
                        }
                    ],
                }
            ]
        }
    }
    affected = collector.extract_affected_software(item)
    assert sorted(affected) == [
        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:vendor:product:1.1:*:*:*:*:*:*:*",
    ]
