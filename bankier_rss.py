#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generuje kanał RSS z działu "Wiadomości dnia" na Bankier.pl.

- Skanuje pierwsze N stron listy wiadomości.
- Pobiera tytuł, link i datę publikacji głównie z listy (anti-bot friendly).
- Fallbackowo (tylko gdy potrzeba) dogrywa datę z meta tagu artykułu.
- Filtruje tylko wiadomości z ostatnich X godzin.
- Generuje RSS 2.0 na stdout (można przekierować do pliku w GitHub Actions).

Wymagane pakiety:
    pip install requests beautifulsoup4 feedgen pytz
"""

import logging
import random
import re
import sys
import time
from datetime import datetime, timedelta

import pytz
import requests
from bs4 import BeautifulSoup
from feedgen.feed import FeedGenerator

# ---------------- Konfiguracja ----------------

BASE_URL = "https://www.bankier.pl"
LISTING_BASE = f"{BASE_URL}/wiadomosc/"  # strona 1
PAGES_TO_SCAN = 5                        # ile stron listy przejść
MAX_AGE_HOURS = 48                       # filtr czasowy: ostatnie X godzin

# nagłówki HTTP – mimikra przeglądarki
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) "
        "Gecko/20100101 Firefox/132.0"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pl,en-US;q=0.9,en;q=0.8",
    "Referer": "https://www.bankier.pl/",
    "Connection": "keep-alive",
}

REQUEST_TIMEOUT = 10  # sekundy
SLEEP_BETWEEN_PAGES = (1.0, 2.5)  # min, max sekund

WARSAW_TZ = pytz.timezone("Europe/Warsaw")
DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2})")


# ---------------- Pomocnicze funkcje czasu ----------------

def parse_warsaw_datetime(date_str: str) -> datetime | None:
    """
    Parsuje string w formacie 'YYYY-MM-DD HH:MM' jako datę w strefie Europe/Warsaw.
    Zwraca obiekt datetime z tzinfo.
    """
    try:
        naive = datetime.strptime(date_str.strip(), "%Y-%m-%d %H:%M")
        return WARSAW_TZ.localize(naive)
    except Exception as exc:  # noqa: BLE001
        logging.warning("Nie udało się sparsować daty z listy: %s (%s)", date_str, exc)
        return None


def parse_iso_datetime_to_warsaw(iso_str: str) -> datetime | None:
    """
    Parsuje ISO 8601 z meta-tagów artykułu do strefy Europe/Warsaw.
    Przykłady: '2025-12-29T09:34:00+01:00', '2025-12-29T08:34:00Z'
    """
    try:
        iso_str = iso_str.strip()
        # z -> +00:00 dla kompatybilności z datetime.fromisoformat
        if iso_str.endswith("Z"):
            iso_str = iso_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            # jeśli przypadkiem brak tzinfo, załóżmy lokalną (Warszawa)
            dt = WARSAW_TZ.localize(dt)
        return dt.astimezone(WARSAW_TZ)
    except Exception as exc:  # noqa: BLE001
        logging.warning("Nie udało się sparsować daty ISO z artykułu: %s (%s)", iso_str, exc)
        return None


# ---------------- HTTP / pobieranie stron ----------------

def fetch_url(session: requests.Session, url: str) -> str | None:
    """
    Pobiera stronę z lekkim retry.
    Zwraca text HTML lub None jeśli nie udało się pobrać.
    """
    for attempt in range(3):
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return resp.text
        except Exception as exc:  # noqa: BLE001
            logging.warning("Błąd pobierania %s (próba %d): %s", url, attempt + 1, exc)
            time.sleep(1 + attempt)
    logging.error("Nie udało się pobrać: %s", url)
    return None


# ---------------- Parsowanie daty i artykułów z listy ----------------

def find_date_for_anchor(a_tag) -> datetime | None:
    """
    Szuka tekstu z datą tuż przed linkiem do artykułu na liście.
    Przykładowy tekst: '2025-12-29 12:46 Aktualizacja: 2025-12-29 13:13'
    Bierzemy pierwsze dopasowanie 'YYYY-MM-DD HH:MM'.
    """
    if a_tag is None:
        return None

    # szukamy najbliższego wcześniejszego węzła tekstowego z datą
    text_node = a_tag.find_previous(string=DATE_RE)
    if not text_node:
        return None

    match = DATE_RE.search(text_node)
    if not match:
        return None

    date_str = match.group(1)
    return parse_warsaw_datetime(date_str)


def fetch_article_published_datetime(
    session: requests.Session,
    url: str,
) -> datetime | None:
    """
    Fallback – gdy nie uda się odczytać daty z listy,
    dogrywamy ją z meta-tagów konkretnego artykułu.
    """
    html = fetch_url(session, url)
    if html is None:
        return None

    soup = BeautifulSoup(html, "html.parser")
    meta = soup.find("meta", attrs={"property": "article:published_time"})
    if not meta or not meta.get("content"):
        return None

    return parse_iso_datetime_to_warsaw(meta["content"])


def normalize_url(href: str) -> str | None:
    """
    Normalizuje href do pełnego URL i filtruje tylko linki do artykułów wiadomości.
    Pomija listingi typu /wiadomosc/, /wiadomosc/2 itd.
    """
    if not href:
        return None

    # absolutny URL
    if href.startswith("http://") or href.startswith("https://"):
        url = href
    elif href.startswith("/"):
        url = BASE_URL + href
    else:
        # link względny innego typu – pomijamy
        return None

    # tylko domena bankier.pl
    if not url.startswith(f"{BASE_URL}/"):
        return None

    # tylko ścieżki zawierające /wiadomosc/
    if "/wiadomosc/" not in url:
        return None

    # odfiltruj listingi typu /wiadomosc/, /wiadomosc/2, /wiadomosc/3 itd.
    listing_pattern = re.compile(r"/wiadomosc(/(\d+)?)?/?$")
    if listing_pattern.search(url):
        return None

    return url


def parse_listing_page(html: str, session: requests.Session) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    items: list[dict] = []

    for div in soup.select("div.entry.entry--article"):
        # --- Tytuł i URL ---
        a = div.select_one("a.entry__title")
        if not a or not a.get("href"):
            continue

        url = normalize_url(a["href"])
        if not url:
            continue

        title = a.get_text(strip=True)
        if not title:
            continue

        # --- Data publikacji (1. źródło: listing) ---
        meta = div.select_one("div.entry__meta")
        published = None

        if meta:
            match = DATE_RE.search(meta.get_text(" ", strip=True))
            if match:
                published = parse_warsaw_datetime(match.group(1))

        # --- Fallback: meta w artykule ---
        if published is None:
            logging.info("Brak daty na liście – pobieram meta z artykułu: %s", url)
            published = fetch_article_published_datetime(session, url)

        if published is None:
            logging.warning("Pomijam artykuł bez daty: %s", url)
            continue

        items.append(
            {
                "title": title,
                "url": url,
                "published": published,
            }
        )

    return items


# ---------------- Główna logika: crawl + filtracja ----------------

def crawl_bankier_news() -> list[dict]:
    """
    Skanuje kilka stron listy wiadomości i zwraca unikalne artykuły
    z datą w strefie Europe/Warsaw.
    """
    session = requests.Session()
    session.headers.update(HEADERS)

    all_items: list[dict] = []

    for page in range(1, PAGES_TO_SCAN + 1):
        if page == 1:
            url = LISTING_BASE
        else:
            url = f"{LISTING_BASE}{page}"

        logging.info("Pobieram stronę %d: %s", page, url)
        html = fetch_url(session, url)
        if html is None:
            # błąd tej strony nie przerywa całego procesu
            logging.error("Pomijam stronę %d z powodu błędu pobierania", page)
        else:
            try:
                page_items = parse_listing_page(html, session)
                logging.info("Na stronie %d znaleziono %d artykułów", page, len(page_items))
                all_items.extend(page_items)
            except Exception as exc:  # noqa: BLE001
                logging.exception("Błąd parsowania strony %d: %s", page, exc)

        # anti-bot: losowy sleep między stronami
        if page < PAGES_TO_SCAN:
            delay = random.uniform(*SLEEP_BETWEEN_PAGES)
            logging.debug("Sleep po stronie %d: %.2f s", page, delay)
            time.sleep(delay)

    # Eliminacja duplikatów po URL – zostawiamy najnowszą wersję danego linku
    dedup: dict[str, dict] = {}
    for item in all_items:
        url = item["url"]
        prev = dedup.get(url)
        if prev is None or item["published"] > prev["published"]:
            dedup[url] = item

    unique_items = list(dedup.values())
    logging.info("Po deduplikacji: %d artykułów", len(unique_items))

    # filtr czasowy (ostatnie MAX_AGE_HOURS godzin)
    now = datetime.now(WARSAW_TZ)
    cutoff = now - timedelta(hours=MAX_AGE_HOURS)
    filtered = [i for i in unique_items if i["published"] >= cutoff]
    logging.info(
        "Po filtrze czasowym (%d h): %d artykułów (cutoff=%s)",
        MAX_AGE_HOURS,
        len(filtered),
        cutoff.isoformat(),
    )

    # sortowanie od najnowszego
    filtered.sort(key=lambda x: x["published"], reverse=True)
    return filtered


# ---------------- Generowanie RSS ----------------

def build_rss_feed(items: list[dict]) -> FeedGenerator:
    """
    Buduje obiekt FeedGenerator z listy artykułów.
    """
    fg = FeedGenerator()
    fg.load_extension("dc", atom=False, rss=True)

    fg.id("bankier-wiadomosci-rss")
    fg.title("Bankier.pl – Wiadomości (nieoficjalny RSS)")
    fg.description("Nieoficjalny kanał RSS z działu wiadomości Bankier.pl, generowany skryptem w Pythonie.")
    fg.link(href=LISTING_BASE, rel="alternate")
    # jeśli masz publiczny URL RSS-a, możesz go tu wstawić
    fg.link(href="https://example.com/bankier-rss.xml", rel="self")
    fg.language("pl")

    if items:
        newest = max(i["published"] for i in items)
        fg.updated(newest)

    for item in items:
        fe = fg.add_entry()
        fe.title(item["title"])
        fe.link(href=item["url"])

        pub = item["published"]
        fe.pubDate(pub)      # RSS pubDate
        fe.updated(pub)      # dla Atom / rozszerzeń
        fe.id(item["url"])   # atom:id
        fe.guid(item["url"], permalink=True)  # RSS <guid isPermaLink="true">

    return fg


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    items = crawl_bankier_news()
    fg = build_rss_feed(items)

    # Generujemy RSS na stdout – idealne do GitHub Actions
    rss_bytes = fg.rss_str(pretty=True)
    sys.stdout.write(rss_bytes.decode("utf-8"))


if __name__ == "__main__":
    main()
