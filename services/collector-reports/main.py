import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import feedparser
import httpx
from bs4 import BeautifulSoup
from confluent_kafka import Producer

DEFAULT_POLL_INTERVAL_SECONDS = 60 * 30
STATE_FILE_NAME = "collector_reports_state.json"

SOURCE_CISA = "cisa"
SOURCE_MSRC = "msrc"
SOURCE_PROJECT_ZERO = "google-project-zero"
SOURCE_GITHUB = "github"

USER_AGENT = "ThreatLensReportScraper/1.0 (+https://github.com/threatlens)"


class RateLimiter:
    def __init__(self, min_delay: float = 1.0) -> None:
        self.min_delay = min_delay
        self.last_access: Dict[str, float] = {}

    def wait(self, url: str) -> None:
        parsed = urlparse(url)
        domain = parsed.netloc
        previous = self.last_access.get(domain)
        if previous is not None:
            elapsed = time.monotonic() - previous
            if elapsed < self.min_delay:
                delay = self.min_delay - elapsed
                logging.debug("Sleeping %.3f seconds for domain rate limit: %s", delay, domain)
                time.sleep(delay)
        self.last_access[domain] = time.monotonic()


class RobotsTxtCache:
    def __init__(self) -> None:
        self.parsers: Dict[str, Optional[RobotFileParser]] = {}

    def is_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        domain = f"{parsed.scheme}://{parsed.netloc}"
        parser = self.parsers.get(domain)
        if parser is None:
            parser = RobotFileParser()
            parser.set_url(urljoin(domain, "/robots.txt"))
            try:
                parser.read()
            except Exception as exc:
                logging.warning("Unable to read robots.txt for %s: %s", domain, exc)
                parser = None
            self.parsers[domain] = parser

        if parser is None:
            return True
        return parser.can_fetch("*", url)


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Threat report scraper for raw-reports Kafka topic")
    parser.add_argument(
        "--broker",
        type=str,
        default=os.getenv("KAFKA_BROKER", "kafka:9092"),
        help="Kafka bootstrap broker address.",
    )
    parser.add_argument(
        "--topic",
        type=str,
        default=os.getenv("KAFKA_TOPIC_RAW_REPORTS", "raw-reports"),
        help="Kafka topic to publish threat report events to.",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=int(os.getenv("REPORT_SCRAPER_POLL_INTERVAL_SECONDS", DEFAULT_POLL_INTERVAL_SECONDS)),
        help="Polling interval in seconds for periodic scraping.",
    )
    parser.add_argument(
        "--github-token",
        type=str,
        default=os.getenv("GITHUB_TOKEN", ""),
        help="Optional GitHub token used when fetching advisories from the GitHub Advisory API.",
    )
    parser.add_argument(
        "--state-file",
        type=str,
        default=os.getenv("REPORT_SCRAPER_STATE_FILE", STATE_FILE_NAME),
        help="Path to local state file used for deduplication.",
    )
    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Run once and exit after publishing any new reports.",
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


def load_state(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
            if not isinstance(state, dict):
                return {"seen_urls": []}
            return state
    except FileNotFoundError:
        return {"seen_urls": []}
    except json.JSONDecodeError:
        logging.warning("State file %s is malformed, resetting deduplication state.", path)
        return {"seen_urls": []}


def save_state(path: str, state: Dict[str, Any]) -> None:
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path_obj.with_suffix(path_obj.suffix + ".tmp")
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)
    temp_path.replace(path_obj)


def safe_text(value: Optional[str]) -> str:
    return str(value).strip() if value else ""


def parse_cisa_reports(html: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    items: List[Dict[str, Any]] = []
    seen_urls: Set[str] = set()

    for anchor in soup.select("a[href*='/known-exploited-vulnerabilities-catalog/cve/']"):
        href = anchor.get("href")
        if not href:
            continue
        url = urljoin("https://www.cisa.gov", href)
        if url in seen_urls:
            continue

        title = safe_text(anchor.get_text())
        parent = anchor.find_parent("tr")
        description = ""
        if parent is not None:
            description = " ".join(
                safe_text(td.get_text(" ", strip=True)) for td in parent.find_all("td")
            )

        items.append(
            {
                "source_name": SOURCE_CISA,
                "source_id": url,
                "title": title or url,
                "description": description,
                "url": url,
                "published_at": None,
                "raw_data": {},
            }
        )
        seen_urls.add(url)

    if not items:
        logging.warning("No report entries were extracted from CISA HTML content.")
    return items


def parse_feed_items(feed, source_name: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    seen_urls: Set[str] = set()

    for entry in feed.entries:
        url = safe_text(getattr(entry, "link", ""))
        if not url or url in seen_urls:
            continue

        title = safe_text(getattr(entry, "title", "")) or url
        description = safe_text(getattr(entry, "summary", "") or getattr(entry, "description", ""))
        published_at = safe_text(getattr(entry, "published", "") or getattr(entry, "updated", ""))

        items.append(
            {
                "source_name": source_name,
                "source_id": f"{source_name}:{url}",
                "title": title,
                "description": description,
                "url": url,
                "published_at": published_at,
                "raw_data": {
                    "title": title,
                    "link": url,
                    "published": published_at,
                    "summary": description,
                },
            }
        )
        seen_urls.add(url)

    return items


def fetch_url(client: httpx.Client, rate_limiter: RateLimiter, robots_cache: RobotsTxtCache, url: str) -> Optional[httpx.Response]:
    if not robots_cache.is_allowed(url):
        logging.warning("Robots.txt disallows scraping URL: %s", url)
        return None

    rate_limiter.wait(url)
    try:
        response = client.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
        response.raise_for_status()
        return response
    except httpx.RequestError as exc:
        logging.warning("Request failed for %s: %s", url, exc)
        return None
    except httpx.HTTPStatusError as exc:
        logging.warning("HTTP error for %s: %s", url, exc)
        return None


def fetch_cisa_reports(client: httpx.Client, rate_limiter: RateLimiter, robots_cache: RobotsTxtCache) -> List[Dict[str, Any]]:
    url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    response = fetch_url(client, rate_limiter, robots_cache, url)
    if response is None:
        logging.warning("Skipping CISA source because content could not be retrieved.")
        return []
    return parse_cisa_reports(response.text)


def fetch_msrc_rss(client: httpx.Client, rate_limiter: RateLimiter, robots_cache: RobotsTxtCache) -> List[Dict[str, Any]]:
    url = "https://msrc.microsoft.com/update-guide/rss"
    response = fetch_url(client, rate_limiter, robots_cache, url)
    if response is None:
        logging.warning("Skipping MSRC RSS source because content could not be retrieved.")
        return []
    feed = feedparser.parse(response.text)
    return parse_feed_items(feed, SOURCE_MSRC)


def fetch_google_project_zero_rss(client: httpx.Client, rate_limiter: RateLimiter, robots_cache: RobotsTxtCache) -> List[Dict[str, Any]]:
    url = "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss"
    response = fetch_url(client, rate_limiter, robots_cache, url)
    if response is None:
        logging.warning("Skipping Project Zero RSS source because content could not be retrieved.")
        return []
    feed = feedparser.parse(response.text)
    return parse_feed_items(feed, SOURCE_PROJECT_ZERO)


def fetch_github_advisories(
    client: httpx.Client,
    rate_limiter: RateLimiter,
    robots_cache: RobotsTxtCache,
    github_token: str,
) -> List[Dict[str, Any]]:
    if not github_token:
        logging.info("GitHub token is not configured; skipping GitHub Advisory API source.")
        return []

    url = "https://api.github.com/advisories"
    if not robots_cache.is_allowed(url):
        logging.warning("Robots.txt disallows scraping URL: %s", url)
        return []

    rate_limiter.wait(url)
    headers = {"Authorization": f"token {github_token}", "Accept": "application/vnd.github+json"}
    try:
        response = client.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            logging.warning("Unexpected GitHub advisories payload type: %s", type(payload).__name__)
            return []

        items: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()
        for advisory in payload:
            url = safe_text(advisory.get("permalink") or advisory.get("url") or advisory.get("html_url"))
            if not url or url in seen_urls:
                continue
            title = safe_text(advisory.get("ghsa_id") or advisory.get("summary") or advisory.get("title") or url)
            description = safe_text(advisory.get("description") or advisory.get("summary") or "")
            published_at = safe_text(advisory.get("published_at") or advisory.get("updated_at") or "")
            items.append(
                {
                    "source_name": SOURCE_GITHUB,
                    "source_id": f"{SOURCE_GITHUB}:{title}",
                    "title": title,
                    "description": description,
                    "url": url,
                    "published_at": published_at,
                    "raw_data": advisory,
                }
            )
            seen_urls.add(url)
        return items
    except httpx.RequestError as exc:
        logging.warning("GitHub Advisory API request failed: %s", exc)
        return []
    except httpx.HTTPStatusError as exc:
        logging.warning("GitHub Advisory API returned HTTP error: %s", exc)
        return []
    except ValueError as exc:
        logging.warning("Unable to parse GitHub Advisory API JSON: %s", exc)
        return []


def normalize_report_item(item: Dict[str, Any], collected_at: datetime) -> Dict[str, Any]:
    published_at = item.get("published_at") or format_iso_z(collected_at)
    return {
        "source": "reports",
        "report_source": item.get("source_name", "unknown"),
        "source_id": item.get("source_id") or item.get("url"),
        "title": safe_text(item.get("title")) or safe_text(item.get("url")),
        "description": safe_text(item.get("description")),
        "source_url": safe_text(item.get("url")),
        "published_at": published_at,
        "collected_at": format_iso_z(collected_at),
        "raw_data": item.get("raw_data", item),
    }


def collect_reports(client: httpx.Client, rate_limiter: RateLimiter, robots_cache: RobotsTxtCache, github_token: str) -> List[Dict[str, Any]]:
    reports: List[Dict[str, Any]] = []
    for source_fetcher in (
        fetch_cisa_reports,
        fetch_msrc_rss,
        fetch_google_project_zero_rss,
        fetch_github_advisories,
    ):
        try:
            if source_fetcher is fetch_github_advisories:
                reports.extend(source_fetcher(client, rate_limiter, robots_cache, github_token))
            else:
                reports.extend(source_fetcher(client, rate_limiter, robots_cache))
        except Exception as exc:
            logging.warning("Source fetcher %s failed: %s", source_fetcher.__name__, exc)

    logging.info("Collected %d candidate reports from sources", len(reports))
    return reports


def run_scraper_loop(
    producer: Producer,
    topic: str,
    state_file: str,
    github_token: str,
    poll_interval: int,
    run_once: bool,
) -> None:
    state = load_state(state_file)
    seen_urls: Set[str] = set(state.get("seen_urls", []))
    client = httpx.Client(follow_redirects=True)
    rate_limiter = RateLimiter(min_delay=1.0)
    robots_cache = RobotsTxtCache()

    try:
        while True:
            collected_at = utc_now()
            candidates = collect_reports(client, rate_limiter, robots_cache, github_token)
            new_reports = [item for item in candidates if item.get("url") and item["url"] not in seen_urls]

            if new_reports:
                messages = [normalize_report_item(item, collected_at) for item in new_reports]
                publish_messages(producer, topic, messages)
                seen_urls.update(item["url"] for item in new_reports if item.get("url"))
                state["seen_urls"] = sorted(seen_urls)
                state["last_updated_at"] = format_iso_z(collected_at)
                save_state(state_file, state)
                logging.info("Persisted deduplication state with %d seen URLs", len(seen_urls))
            else:
                logging.info("No new report URLs found in this cycle")

            if run_once:
                break

            time.sleep(poll_interval)
    finally:
        client.close()


def main() -> int:
    args = parse_cli_args()
    configure_logging(args.log_level)

    producer = build_producer(args.broker)
    try:
        run_scraper_loop(
            producer=producer,
            topic=args.topic,
            state_file=args.state_file,
            github_token=args.github_token,
            poll_interval=args.poll_interval,
            run_once=args.run_once,
        )
    except KeyboardInterrupt:
        logging.info("Collector interrupted, exiting cleanly")
        return 0
    except Exception:
        logging.exception("Collector failed unexpectedly")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
