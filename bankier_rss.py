#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generuje kanał RSS z działu "Wiadomości" na Bankier.pl.

- Skanuje pierwsze PAGES_TO_SCAN stron /wiadomosc/.
- Pobiera tytuł, link i datę publikacji (najpierw z listy, ewentualnie z meta-tagów artykułu).
- Filtruje tylko artykuły z ostatnich MAX_AGE_HOURS godzin.
- Eliminacja duplikatów po URL.
- Generuje RSS 2.0 na stdout – idealne do GitHub Actions.

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

# -------------------- KONFIGURACJA --------------------

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

# dopasowuje "2025-12-29 17:46"
DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2})")


# -------------------- POMOCNICZE – CZAS --------------------

def parse_warsaw_datetime(date_str):
    """
    Parsuje string w formacie 'YYYY-MM-DD HH:MM' (ew. z sekundami)
    jako datę w strefie Europe/Warsaw.
    """
    try:
        date_str = date_str.strip()
        # jeśli jest z sekundami ("YYYY-MM-DD HH:MM:SS"), obetnij do minut
        if len(date_str) >= 16:
            date_str = date_str[:16]
        naive = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
        return WARSAW_TZ.localize(naive)
    except Exception as exc:  # noqa: BLE001
        logging.warning("Nie udało się sparsować daty z listy: %s (%s)", date_str, exc)
        return None


def parse_iso_datetime_to_warsaw(iso_str):
    """
    Parsuje ISO 8601 z meta-tagów artykułu do strefy Europe/Warsaw.
    Przykłady: '2025-12-29T09:34:00+01:00', '2025-12-29T08:34:00Z'
    """
    try:
        iso_str = iso_str.strip()
        # 'Z' -> '+00:00' dla kompatybilności z datetime.fromisoformat
        if iso_str.endswith("Z"):
            iso_str = iso_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = WARSAW_TZ.localize(dt)
        return dt.astimezone(WARSAW_TZ)
    except Exception as exc:  # noqa: BLE001
        logging.warning("Nie udało się sparsować daty ISO z artykułu: %s (%s)", iso_str, exc)
        return None


# -------------------- HTTP --------------------

def fetch_url(session, url):
    """
    Pobiera stronę z lekkim retry.
    Zwraca text HTML lub None, jeśli się nie uda.
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


# -------------------- NORMALIZACJA / DATY Z LISTY --------------------

def normalize_url(href):
    """
    Normalizuje href do pełnego URL i filtruje tylko linki do artykułów wiadomości.
    - tylko domena bankier.pl
    - tylko ścieżki zawierające /wiadomosc/
    - pomija listingi typu /wiadomosc/, /wiadomosc/2 itd.
    """
    if not href:
        return None

    # absolutny URL
    if href.startswith("http://") or href.startswith("https://"):
        url = href
    elif href.startswith("/"):
        url = BASE_URL + href
    else:
        # inne relative – pomijamy
        return None

    if not url.startswith(f"{BASE_URL}/"):
        return None

    if "/wiadomosc/" not in url:
        return None

    # odfiltruj listingi /wiadomosc/, /wiadomosc/2, /wiadomosc/3...
    listing_pattern = re.compile(r"/wiadomosc(/(\d+)?)?/?$")
    if listing_pattern.search(url):
        return None

    return url


def find_date_for_anchor(a_tag):
    """
    Szuka tekstu z datą tuż przed linkiem do artykułu na liście.
    Przykładowy tekst:
        '2025-12-29 17:14 Aktualizacja: 2025-12-29 21:09'
    Bierzemy pierwsze dopasowanie 'YYYY-MM-DD HH:MM'.
    """
    if a_tag is None:
        return None

    # najbliższy wcześniejszy węzeł tekstowy z datą
    text_node = a_tag.find_previous(string=DATE_RE)
    if not text_node:
        return None

    match = DATE_RE.search(text_node)
    if not match:
        return None

    date_str = match.group(1)
    return parse_warsaw_datetime(date_str)


def fetch_article_published_datetime(session, url):
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


# -------------------- PARSOWANIE LISTY --------------------

def parse_listing_page(html, session):
    """
    Parsuje stronę listy wiadomości, zwracając listę słowników:
    {
        "title": ...,
        "url": ...,
        "published": datetime (tz = Europe/Warsaw)
    }

    Logika:
    - przechodzimy po wszystkich <a href="...">
    - normalizujemy URL (tylko /wiadomosc/..., bez listingów)
    - ignorujemy linki typu "Czytaj dalej"
    - bierzemy artykuły, dla których uda się znaleźć datę tuż przed linkiem
      (sekcja „Wiadomości dnia”)
    - jeśli daty nie ma, jednorazowy fallback: meta w artykule
    """
    soup = BeautifulSoup(html, "html.parser")
    items = []

    for a in soup.find_all("a", href=True):
        url = normalize_url(a["href"])
        if not url:
            continue

        title = a.get_text(strip=True)
        if not title:
            continue

        # ignorujemy drugi link do tego samego artykułu typu "Czytaj dalej"
        if title.lower().startswith("czytaj dalej"):
            continue

        # najpierw spróbuj znaleźć datę na liście
        published = find_date_for_anchor(a)

        # Fallback – wchodzimy w artykuł tylko jeśli naprawdę brak daty
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

    logging.info("Na liście znaleziono %d artykułów (po stronie)", len(items))
    return items


# -------------------- CRAWL + FILTR --------------------

def crawl_bankier_news():
    """
    Skanuje kilka stron listy wiadomości i zwraca unikalne artykuły
    z datą w strefie Europe/Warsaw, przefiltrowane do ostatnich MAX_AGE_HOURS.
    """
    session = requests.Session()
    session.headers.update(HEADERS)

    all_items = []

    for page in range(1, PAGES_TO_SCAN + 1):
        if page == 1:
            url = LISTING_BASE
        else:
            url = f"{LISTING_BASE}{page}"

        logging.info("Pobieram stronę %d: %s", page, url)
        html = fetch_url(session, url)
        if html is None:
            logging.error("Pomijam stronę %d z powodu błędu pobierania", page)
        else:
            try:
                page_items = parse_listing_page(html, session)
                logging.info(
                    "Na stronie %d po parsowaniu: %d artykułów", page, len(page_items)
                )
                all_items.extend(page_items)
            except Exception as exc:  # noqa: BLE001
                logging.exception("Błąd parsowania strony %d: %s", page, exc)

        if page < PAGES_TO_SCAN:
            delay = random.uniform(*SLEEP_BETWEEN_PAGES)
            logging.debug("Sleep po stronie %d: %.2f s", page, delay)
            time.sleep(delay)

    # deduplikacja po URL – zostawiamy najnowszą datę dla danego linku
    dedup = {}
    for item in all_items:
        url = item["url"]
        prev = dedup.get(url)
        if prev is None or item["published"] > prev["published"]:
            dedup[url] = item

    unique_items = list(dedup.values())
    logging.info("Po deduplikacji: %d artykułów", len(unique_items))

    # filtr czasowy
    now = datetime.now(WARSAW_TZ)
    cutoff = now - timedelta(hours=MAX_AGE_HOURS)
    filtered = [i for i in unique_items if i["published"] >= cutoff]
    logging.info(
        "Po filtrze czasowym (%d h): %d artykułów (cutoff=%s)",
        MAX_AGE_HOURS,
        len(filtered),
        cutoff.isoformat(),
    )

    # sort od najnowszego
    filtered.sort(key=lambda x: x["published"], reverse=True)
    return filtered


# -------------------- RSS --------------------

def build_rss_feed(items):
    """
    Buduje obiekt FeedGenerator z listy artykułów.
    """
    fg = FeedGenerator()
    fg.load_extension("dc", atom=False, rss=True)

    fg.id("bankier-wiadomosci-rss")
    fg.title("Bankier.pl – Wiadomości (nieoficjalny RSS)")
    fg.description(
        "Nieoficjalny kanał RSS z działu wiadomości Bankier.pl, generowany skryptem w Pythonie."
    )
    fg.link(href=LISTING_BASE, rel="alternate")
    # jeśli masz publiczny URL RSS-a (np. z GitHub Pages), wstaw go tutaj:
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


# -------------------- MAIN --------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    items = crawl_bankier_news()
    fg = build_rss_feed(items)

    rss_bytes = fg.rss_str(pretty=True)
    sys.stdout.write(rss_bytes.decode("utf-8"))


if __name__ == "__main__":
    main()
