import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

import requests
from confluent_kafka import Producer

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_POLL_INTERVAL_SECONDS = 15 * 60
MAX_RESULTS_PER_PAGE = 2000
BACKOFF_MAX_SECONDS = 60


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collector service for NVD CVE data, producing normalized events to Kafka."
    )
    parser.add_argument("--backfill", action="store_true", help="Run backfill once from the given since date")
    parser.add_argument(
        "--since",
        type=str,
        help="ISO date or date-only string for backfill mode, e.g. 2024-01-01",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=int(os.getenv("NVD_POLL_INTERVAL_SECONDS", DEFAULT_POLL_INTERVAL_SECONDS)),
        help="Polling interval in seconds when running normal mode.",
    )
    parser.add_argument(
        "--batch-days",
        type=int,
        default=int(os.getenv("NVD_BACKFILL_BATCH_DAYS", 7)),
        help="Backfill window size in days for historical CVE loading.",
    )
    parser.add_argument(
        "--broker",
        type=str,
        default=os.getenv("KAFKA_BROKER", "kafka:9092"),
        help="Kafka bootstrap broker address.",
    )
    parser.add_argument(
        "--topic",
        type=str,
        default=os.getenv("KAFKA_TOPIC_RAW_CVES", "raw-cves"),
        help="Kafka topic to publish raw CVE events to.",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=os.getenv("NVD_API_KEY"),
        help="Optional NVD API key for higher rate limits.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=os.getenv("LOG_LEVEL", "INFO"),
        help="Logging level.",
    )
    return parser.parse_args()


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_date(value: str) -> datetime:
    text = value.strip()
    if len(text) == 10 and text[4] == "-" and text[7] == "-":
        return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)
    if text.endswith("Z"):
        text = text[:-1]
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


def get_rate_limit_delay(api_key: Optional[str]) -> float:
    return 0.6 if api_key else 6.5


def build_producer(broker: str) -> Producer:
    return Producer({"bootstrap.servers": broker})


def publish_messages(producer: Producer, topic: str, messages: Iterable[Dict[str, Any]]) -> None:
    published = 0

    def delivery_report(err: Optional[Exception], msg: Optional[Any]) -> None:
        if err is not None:
            logging.error("Failed to deliver message %s: %s", msg.key(), err)

    for message in messages:
        payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        producer.produce(topic, key=message.get("source_id"), value=payload, callback=delivery_report)
        published += 1

    producer.flush()
    logging.info("Published %d messages to topic '%s'", published, topic)


def safe_get(data: Dict[str, Any], *keys: str) -> Optional[Any]:
    item = data
    for key in keys:
        if not isinstance(item, dict):
            return None
        item = item.get(key)
        if item is None:
            return None
    return item


def get_english_description(cve: Dict[str, Any]) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en" and desc.get("value"):
            return desc["value"].strip()
    return ""


def get_cve_title(cve: Dict[str, Any]) -> str:
    title = safe_get(cve, "metadata", "title")
    if title:
        return title.strip()
    return get_english_description(cve)[:200]


def extract_software_from_node(node: Dict[str, Any]) -> List[str]:
    software = []
    if not isinstance(node, dict):
        return software

    for match in node.get("cpeMatch", []) or node.get("cpe23Uri", []):
        if isinstance(match, dict):
            candidate = match.get("criteria") or match.get("cpe23Uri") or match.get("cpeName")
            if candidate:
                software.append(candidate)
        elif isinstance(match, str):
            software.append(match)

    for child in node.get("children", []) or []:
        software.extend(extract_software_from_node(child))

    return software


def extract_affected_software(item: Dict[str, Any]) -> List[str]:
    configs = item.get("configurations", {})
    nodes = configs.get("nodes", []) if isinstance(configs, dict) else []
    affected: List[str] = []

    for node in nodes:
        affected.extend(extract_software_from_node(node))

    return sorted(set(affected))


def get_cvss_info(item: Dict[str, Any]) -> Dict[str, Optional[Any]]:
    metrics = item.get("metrics", {})
    result = {"severity": "UNKNOWN", "cvss_score": None}

    for metric_key in ("cvssMetricV3", "cvssMetricV2"):
        metric_list = metrics.get(metric_key)
        if not isinstance(metric_list, list) or not metric_list:
            continue
        metric = metric_list[0]
        if not isinstance(metric, dict):
            continue

        cvss_data = metric.get("cvssData", {})
        if isinstance(cvss_data, dict):
            result["severity"] = cvss_data.get("baseSeverity", result["severity"])
            result["cvss_score"] = cvss_data.get("baseScore", result["cvss_score"])
            return result

    return result


def normalize_cve_item(item: Dict[str, Any], collected_at: datetime) -> Dict[str, Any]:
    source_id = item.get("id") or safe_get(item, "cve", "id") or ""
    source_id = str(source_id).strip()
    published_at = item.get("published") or item.get("publishedDate")
    if published_at:
        try:
            published_at = parse_date(str(published_at))
        except ValueError:
            published_at = None
    if not published_at:
        published_at = collected_at

    cve_data = item.get("cve", {})
    normalized = {
        "source": "nvd",
        "source_id": source_id,
        "title": get_cve_title(cve_data),
        "description": get_english_description(cve_data),
        "severity": "UNKNOWN",
        "cvss_score": None,
        "affected_software": extract_affected_software(item),
        "published_at": format_iso_z(published_at),
        "collected_at": format_iso_z(collected_at),
        "raw_data": item,
    }

    cvss_info = get_cvss_info(item)
    normalized["severity"] = cvss_info["severity"] or normalized["severity"]
    normalized["cvss_score"] = cvss_info["cvss_score"]
    return normalized


def request_with_retry(session: requests.Session, params: Dict[str, Any]) -> Dict[str, Any]:
    attempt = 0
    backoff = 1.0
    while True:
        attempt += 1
        try:
            response = session.get(NVD_API_URL, params=params, timeout=30)
            if response.status_code == 429:
                raise requests.HTTPError("Rate limit exceeded", response=response)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            if attempt >= 8:
                logging.error("Request failed after %d attempts: %s", attempt, exc)
                raise
            wait = min(backoff, BACKOFF_MAX_SECONDS)
            retry_after = response.headers.get("Retry-After") if 'response' in locals() else None
            if retry_after and retry_after.isdigit():
                wait = max(wait, float(retry_after))
            logging.warning(
                "Request attempt %d failed: %s. Retrying in %.1f seconds.", attempt, exc, wait
            )
            time.sleep(wait)
            backoff *= 2


def fetch_cve_page(
    session: requests.Session,
    api_key: Optional[str],
    start_index: int,
    pub_start_date: str,
    pub_end_date: str,
) -> Dict[str, Any]:
    params = {
        "pubStartDate": pub_start_date,
        "pubEndDate": pub_end_date,
        "startIndex": start_index,
        "resultsPerPage": MAX_RESULTS_PER_PAGE,
    }
    if api_key:
        params["apiKey"] = api_key

    return request_with_retry(session, params)


def fetch_cves(
    api_key: Optional[str],
    start_date: datetime,
    end_date: datetime,
    seen_ids: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    session = requests.Session()
    pub_start = format_iso_z(start_date)
    pub_end = format_iso_z(end_date)
    rate_delay = get_rate_limit_delay(api_key)

    items: List[Dict[str, Any]] = []
    start_index = 0
    seen_ids = seen_ids or set()

    while True:
        logging.info(
            "Fetching NVD CVEs from %s to %s (startIndex=%d)", pub_start, pub_end, start_index
        )
        resp = fetch_cve_page(session, api_key, start_index, pub_start, pub_end)

        result = resp.get("vulnerabilities") or resp.get("result") or resp
        if isinstance(result, dict) and "vulnerabilities" in result:
            page_items = [entry.get("cve") or entry for entry in result["vulnerabilities"]]
            total_results = result.get("totalResults", 0)
        elif "vulnerabilities" in resp:
            page_items = [entry.get("cve") or entry for entry in resp["vulnerabilities"]]
            total_results = len(page_items)
        else:
            page_items = []
            total_results = 0

        for item in page_items:
            item_id = str(item.get("id") or safe_get(item, "cve", "id") or "").strip()
            if item_id and item_id not in seen_ids:
                items.append(item)
                seen_ids.add(item_id)

        if len(page_items) + start_index >= total_results or len(page_items) == 0:
            break

        start_index += len(page_items)
        logging.debug("Sleeping %.1f seconds to honor NVD rate limits", rate_delay)
        time.sleep(rate_delay)

    logging.info("Fetched %d candidate CVE items", len(items))
    return items


def backfill_history(
    producer: Producer,
    topic: str,
    api_key: Optional[str],
    since: datetime,
    batch_days: int,
) -> None:
    end = utc_now()
    batch_size = timedelta(days=batch_days)
    cursor = since
    total_published = 0
    seen_ids: Set[str] = set()

    while cursor < end:
        batch_end = min(cursor + batch_size, end)
        logging.info("Backfill window %s -> %s", format_iso_z(cursor), format_iso_z(batch_end))
        items = fetch_cves(api_key, cursor, batch_end, seen_ids)
        messages = [normalize_cve_item(item, utc_now()) for item in items]
        if messages:
            publish_messages(producer, topic, messages)
            total_published += len(messages)
        cursor = batch_end
        time.sleep(get_rate_limit_delay(api_key))

    logging.info("Backfill complete, published %d historical CVEs", total_published)


def run_poll_loop(
    producer: Producer,
    topic: str,
    api_key: Optional[str],
    poll_interval: int,
) -> None:
    last_end = utc_now() - timedelta(seconds=poll_interval)
    seen_ids: Set[str] = set()

    while True:
        cycle_start = utc_now()
        logging.info("Starting polling cycle from %s", format_iso_z(last_end))
        new_items = fetch_cves(api_key, last_end, cycle_start, seen_ids)
        if new_items:
            messages = [normalize_cve_item(item, cycle_start) for item in new_items]
            publish_messages(producer, topic, messages)
        else:
            logging.info("No new CVEs found in this cycle")

        last_end = cycle_start
        logging.info("Poll cycle complete: %d new CVEs", len(new_items))
        time.sleep(poll_interval)


def main() -> int:
    args = parse_cli_args()
    configure_logging(args.log_level)

    if args.backfill and not args.since:
        logging.error("Backfill mode requires --since DATE")
        return 2

    if args.backfill:
        since_date = parse_date(args.since)
        producer = build_producer(args.broker)
        backfill_history(producer, args.topic, args.api_key, since_date, args.batch_days)
        return 0

    producer = build_producer(args.broker)
    try:
        run_poll_loop(producer, args.topic, args.api_key, args.poll_interval)
    except KeyboardInterrupt:
        logging.info("Collector interrupted, exiting cleanly")
        return 0
    except Exception:
        logging.exception("Collector failed unexpectedly")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
