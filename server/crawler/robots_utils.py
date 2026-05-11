"""
Fetch and parse /robots.txt for a given base URL.
Returns structured data for security reporting and optional crawl filtering.
"""

from __future__ import annotations

import logging

import requests

from crawler.url_utils import safe_get

logger = logging.getLogger(__name__)


def fetch_robots_txt(base_url: str, headers: dict | None = None) -> dict:
    """
    Fetch and parse /robots.txt from *base_url*.

    Returns a dict with:
      - found         (bool)        : whether the file was present and readable
      - raw           (str|None)    : raw file content
      - rules         (list[dict])  : parsed User-agent/Disallow/Allow groups
      - sitemaps      (list[str])   : Sitemap: directive values
      - crawl_delay   (float|None)  : first Crawl-delay value encountered
    """
    url = base_url.rstrip('/') + '/robots.txt'
    try:
        response = safe_get(url, headers=headers, timeout=10)
        response.raise_for_status()
        raw = response.text
    except requests.RequestException as e:
        logger.info("robots.txt not found or unreachable at %s: %s", url, e)
        return {"found": False, "raw": None, "rules": [], "sitemaps": [], "crawl_delay": None}

    rules: list[dict] = []
    sitemaps: list[str] = []
    crawl_delay: float | None = None

    # Parser state — accumulate directives per User-agent group
    current_agents: list[str] = []
    current_disallowed: list[str] = []
    current_allowed: list[str] = []

    def _flush() -> None:
        for agent in current_agents:
            rules.append({
                "user_agent": agent,
                "disallowed": list(current_disallowed),
                "allowed": list(current_allowed),
            })

    for line in raw.splitlines():
        line = line.strip()
        # Skip blank lines and comments
        if not line or line.startswith('#'):
            # A blank line conventionally ends a group — flush if we have agents
            if not line and current_agents and (current_disallowed or current_allowed):
                _flush()
                current_agents = []
                current_disallowed = []
                current_allowed = []
            continue

        if ':' not in line:
            continue

        key, _, value = line.partition(':')
        key = key.strip().lower()
        value = value.strip()

        if key == 'user-agent':
            # Starting a new group — flush the previous one first if agents changed
            if current_agents and value not in current_agents and (current_disallowed or current_allowed):
                _flush()
                current_disallowed = []
                current_allowed = []
                current_agents = []
            current_agents.append(value)
        elif key == 'disallow':
            if value:
                current_disallowed.append(value)
        elif key == 'allow':
            if value:
                current_allowed.append(value)
        elif key == 'sitemap':
            if value:
                sitemaps.append(value)
        elif key == 'crawl-delay' and crawl_delay is None:
            try:
                crawl_delay = float(value)
            except ValueError:
                pass

    # Flush the final group
    if current_agents:
        _flush()

    return {
        "found": True,
        "raw": raw,
        "rules": rules,
        "sitemaps": sitemaps,
        "crawl_delay": crawl_delay,
    }


def is_disallowed(path: str, rules: list[dict]) -> bool:
    """
    Return True if *path* is disallowed for the '*' (wildcard) user-agent.
    Uses simple prefix matching as per the robots.txt spec.
    """
    for rule in rules:
        if rule["user_agent"] == '*':
            for disallowed in rule["disallowed"]:
                if disallowed and path.startswith(disallowed):
                    return True
    return False
