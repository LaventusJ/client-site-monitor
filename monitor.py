"""
Client Site Monitor
--------------------
Checks uptime (every run) and, in "full" mode, SSL certificate expiry and
domain (WHOIS) expiry for every enabled site listed in the "Monitors" tab of
the Google Sheet.

The Sheet is the single source of truth for:
  - Which sites are monitored (the "Monitors" tab -- add/remove/pause rows
    there, no code or GitHub changes needed)
  - Who gets alerted (the "Settings" tab)
  - Current + historical state (the "Status" tab), which is what lets alerts
    persist across GitHub Actions runs, since each run starts on a fresh
    machine with nothing saved locally.
  - Open/closed outages (the "Incidents" tab), which powers the dashboard's
    incident history and per-site uptime % /history bar.

Alerts go to:
  - Email (Gmail/Workspace SMTP), to every address listed in the Sheet's
    "Settings" tab
  - Slack, via two Zapier webhook URLs (one for downtime, one for expiry)

On the very first run for a given site, we just record its current state as
the baseline -- we don't fire an alert, since we have nothing to compare
against yet.
"""

import os
import re
import json
import socket
import ssl
import smtplib
import time
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from zoneinfo import ZoneInfo

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import gspread
from google.oauth2.service_account import Credentials

try:
    import whois  # python-whois
except ImportError:
    whois = None

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SPREADSHEET_ID = "1kGXRxCouDyVG_I_FNn0ERpTnsoxgKSjKfdUoDQ6i_ns"
MONITORS_SHEET_NAME = "Monitors"
STATUS_SHEET_NAME = "Status"
SETTINGS_SHEET_NAME = "Settings"
HISTORY_SHEET_NAME = "History"
INCIDENTS_SHEET_NAME = "Incidents"

STATUS_HEADERS = [
    "Name", "URL", "Status", "Last Checked (UTC)", "Consecutive Fails",
    "SSL Expiry Date", "SSL Days Left", "Domain Expiry Date", "Domain Days Left",
    "Alerted Thresholds",
]

# One row per site per check, used to power the Incidents page and per-site
# uptime %/history bar on the dashboard. Pruned back to HISTORY_RETENTION_DAYS
# once a day (during "full" mode runs) so the sheet doesn't grow forever.
HISTORY_HEADERS = ["Name", "Timestamp (UTC)", "Status", "Detail"]
HISTORY_RETENTION_DAYS = 35

# One row per outage. Opened when a site first goes DOWN, closed when it
# recovers. Open incidents (no End date yet) are always kept regardless of
# age; only closed ones get pruned.
INCIDENTS_HEADERS = ["Name", "Start (UTC)", "End (UTC)", "Duration (min)", "Detail"]

EXPIRY_THRESHOLDS = [30, 14, 7, 1]  # days -- alert once when crossing each of these

# Checks run every 5 minutes. How many consecutive failed checks before we
# send a repeat "still down" reminder, so a long outage doesn't go silent.
# 48 * 5min = ~4 hours between reminders.
STILL_DOWN_REPEAT_EVERY = 48

CHECK_MODE = os.environ.get("CHECK_MODE", "full")  # "uptime" or "full"

# UK second-level domains where the "registrable domain" is 3 labels, not 2
# (e.g. jacksonelectrical.co.uk, not just electrical.co.uk)
UK_SLDS = {"co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk", "sch.uk", "me.uk"}

# check_http() retry tuning: a few attempts with a short pause, so a single
# dropped connection/DNS hiccup on our end doesn't trigger a false DOWN
# alert that would've self-resolved by the next cycle anyway.
HTTP_CHECK_ATTEMPTS = 3
HTTP_RETRY_DELAY_SECONDS = 5

# Detail string check_http() returns for a SiteGround bot-block (counted as
# UP). main() and the dashboard both key off this exact text.
SG_BLOCK_DETAIL = "HTTP 403 (SiteGround bot block)"

# Sites whose host blocks generic "datacenter-class" traffic aggressively
# enough to drop the connection outright (not just serve a 403) -- confirmed
# on MZR from both the TrueNAS and GitHub Actions. UptimeRobot's checks
# aren't blocked there, so for these we ask UptimeRobot's API what it saw
# instead of making our own HTTP request. Map: our Monitors-tab name ->
# UptimeRobot monitor ID.
UPTIMEROBOT_MONITOR_IDS = {
    "MZR (Blocked Drains Birmingham)": 795514069,
}


# ---------------------------------------------------------------------------
# Google Sheets helpers
# ---------------------------------------------------------------------------

def get_sheets_client():
    creds_json = json.loads(os.environ["GOOGLE_SERVICE_ACCOUNT_KEY"])
    scopes = ["https://www.googleapis.com/auth/spreadsheets"]
    creds = Credentials.from_service_account_info(creds_json, scopes=scopes)
    return gspread.authorize(creds)


def ensure_worksheets(spreadsheet):
    titles = [ws.title for ws in spreadsheet.worksheets()]

    if MONITORS_SHEET_NAME not in titles:
        ws = spreadsheet.add_worksheet(title=MONITORS_SHEET_NAME, rows=200, cols=3)
        ws.append_row(["Name", "URL", "Enabled"])
        # One-time migration: seed from monitors.json if it exists, so the
        # existing site list doesn't need retyping into the Sheet.
        if os.path.exists("monitors.json"):
            with open("monitors.json") as f:
                seed = json.load(f)
            rows = [[m["name"], m["url"], "TRUE" if m.get("enabled", True) else "FALSE"] for m in seed]
            if rows:
                ws.append_rows(rows)

    if STATUS_SHEET_NAME not in titles:
        ws = spreadsheet.add_worksheet(title=STATUS_SHEET_NAME, rows=200, cols=len(STATUS_HEADERS))
        ws.append_row(STATUS_HEADERS)

    if SETTINGS_SHEET_NAME not in titles:
        ws = spreadsheet.add_worksheet(title=SETTINGS_SHEET_NAME, rows=50, cols=2)
        ws.append_row(["Alert Emails (one per row, add/remove any time)"])
        default_email = os.environ.get("ALERT_EMAIL", "")
        if default_email:
            ws.append_row([default_email])

    if HISTORY_SHEET_NAME not in titles:
        ws = spreadsheet.add_worksheet(title=HISTORY_SHEET_NAME, rows=1000, cols=len(HISTORY_HEADERS))
        ws.append_row(HISTORY_HEADERS)

    if INCIDENTS_SHEET_NAME not in titles:
        ws = spreadsheet.add_worksheet(title=INCIDENTS_SHEET_NAME, rows=500, cols=len(INCIDENTS_HEADERS))
        ws.append_row(INCIDENTS_HEADERS)


def load_monitors(spreadsheet):
    ws = spreadsheet.worksheet(MONITORS_SHEET_NAME)
    records = ws.get_all_records()
    monitors = []
    for row in records:
        name = str(row.get("Name", "")).strip()
        url = str(row.get("URL", "")).strip()
        if not name or not url:
            continue
        enabled = str(row.get("Enabled", "TRUE")).strip().upper() != "FALSE"
        monitors.append({"name": name, "url": url, "enabled": enabled})
    return [m for m in monitors if m["enabled"]]


def load_alert_emails(spreadsheet):
    ws = spreadsheet.worksheet(SETTINGS_SHEET_NAME)
    values = ws.col_values(1)[1:]  # skip header row
    emails = [v.strip() for v in values if v.strip() and "@" in v]
    if not emails:
        fallback = os.environ.get("ALERT_EMAIL")
        emails = [fallback] if fallback else []
    return emails


def load_previous_status(spreadsheet):
    ws = spreadsheet.worksheet(STATUS_SHEET_NAME)
    records = ws.get_all_records()
    # Map monitor name -> (row number in sheet, record dict)
    # Row 1 is the header, so first data row is row 2.
    return ws, {row["Name"]: (i + 2, row) for i, row in enumerate(records)}


def load_open_incidents(spreadsheet):
    """Returns (worksheet, {name: (row_num, start_str)}) for incidents with
    no End (UTC) value yet -- i.e. still ongoing. Row 1 is the header."""
    ws = spreadsheet.worksheet(INCIDENTS_SHEET_NAME)
    all_values = ws.get_all_values()
    open_incidents = {}
    for i, row in enumerate(all_values[1:], start=2):
        if len(row) < 3:
            continue
        name, start_str, end_str = row[0], row[1], row[2]
        if name and not end_str:
            open_incidents[name] = (i, start_str)
    return ws, open_incidents


def close_incident(ws, row_num, start_str, end_str):
    """Fills in the End (UTC) and Duration (min) columns for an incident row."""
    try:
        start = datetime.strptime(start_str, "%Y-%m-%d %H:%M UTC").replace(tzinfo=timezone.utc)
        end = datetime.strptime(end_str, "%Y-%m-%d %H:%M UTC").replace(tzinfo=timezone.utc)
        duration = str(int((end - start).total_seconds() // 60))
    except ValueError:
        duration = ""
    ws.update(f"C{row_num}:D{row_num}", [[end_str, duration]])


def prune_history(spreadsheet, retention_days=HISTORY_RETENTION_DAYS):
    """Deletes History rows older than retention_days. Runs once a day (full
    mode only) since it re-reads and rewrites the whole tab -- no need to pay
    that cost on every 5-min uptime check."""
    ws = spreadsheet.worksheet(HISTORY_SHEET_NAME)
    all_values = ws.get_all_values()
    if len(all_values) <= 1:
        return  # just the header, nothing to prune

    header, rows = all_values[0], all_values[1:]
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    kept = []
    for row in rows:
        timestamp = row[1] if len(row) > 1 else ""
        try:
            row_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M UTC").replace(tzinfo=timezone.utc)
        except ValueError:
            kept.append(row)  # can't parse it -- keep it rather than risk losing data
            continue
        if row_time >= cutoff:
            kept.append(row)

    if len(kept) != len(rows):
        ws.clear()
        ws.append_row(header)
        if kept:
            ws.append_rows(kept)
        print(f"History pruned: {len(rows) - len(kept)} rows older than {retention_days} days removed")


def prune_incidents(spreadsheet, retention_days=HISTORY_RETENTION_DAYS):
    """Deletes CLOSED incidents (End (UTC) set) older than retention_days.
    Open incidents are kept regardless of age -- we never want to lose track
    of an outage that's still ongoing."""
    ws = spreadsheet.worksheet(INCIDENTS_SHEET_NAME)
    all_values = ws.get_all_values()
    if len(all_values) <= 1:
        return

    header, rows = all_values[0], all_values[1:]
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    kept = []
    for row in rows:
        end_str = row[2] if len(row) > 2 else ""
        if not end_str:
            kept.append(row)  # still open -- always keep
            continue
        try:
            end_time = datetime.strptime(end_str, "%Y-%m-%d %H:%M UTC").replace(tzinfo=timezone.utc)
        except ValueError:
            kept.append(row)  # can't parse it -- keep it rather than risk losing data
            continue
        if end_time >= cutoff:
            kept.append(row)

    if len(kept) != len(rows):
        ws.clear()
        ws.append_row(header)
        if kept:
            ws.append_rows(kept)
        print(f"Incidents pruned: {len(rows) - len(kept)} closed rows older than {retention_days} days removed")


def get_hostname(url):
    return re.sub(r"^https?://", "", url).split("/")[0]


def get_registrable_domain(hostname):
    parts = hostname.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in UK_SLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def build_http_session():
    """A shared Session (connection pooling) with a second-line retry for
    transient 5xx responses from the target server.

    Note: this urllib3-level Retry does NOT reliably cover DNS-resolution
    failures -- those raise immediately and bypass it. That's why
    check_http() below has its own retry loop on top of this; the two work
    together rather than one replacing the other.
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def check_siteground_403(url):
    """Second opinion on a 403 served by SiteGround's CDN (X-SG-CDN header).

    SiteGround's bot protection intermittently 403s the monitor (seen on
    MZR from Oct 2026 -- blocks start ~03:30 UTC and last hours) while the
    same URL loads fine for browsers/curl from the same IP. Retry once on a
    fresh connection with a plain monitor UA; if SiteGround still returns
    its own 403 page, the host is clearly up and answering, so count it as
    UP rather than raising a false DOWN alert.
    """
    print(f"SiteGround 403 for {url} -- retrying on a fresh connection")
    time.sleep(HTTP_RETRY_DELAY_SECONDS)
    try:
        r = requests.get(
            url, timeout=(5, 15), allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ClientSiteMonitor/1.0)",
                     "Accept": "*/*"},
        )
    except requests.RequestException as e:
        return False, type(e).__name__
    if r.status_code == 403 and r.headers.get("X-SG-CDN"):
        return True, SG_BLOCK_DETAIL
    return r.status_code < 400, f"HTTP {r.status_code}"


def check_uptimerobot(monitor_id):
    """Returns (is_up, detail_string) using UptimeRobot's own check result
    instead of making our own HTTP request. UptimeRobot status codes: 0 =
    paused, 1 = not checked yet, 2 = up, 8 = seems down, 9 = down. Paused/
    not-checked-yet counts as up so an unrelated UptimeRobot account change
    doesn't trigger a false DOWN alert here.
    """
    try:
        r = requests.post(
            "https://api.uptimerobot.com/v2/getMonitors",
            data={
                "api_key": os.environ["UPTIMEROBOT_API_KEY"],
                "format": "json",
                "monitors": str(monitor_id),
            },
            timeout=15,
        )
        data = r.json()
        if data.get("stat") != "ok" or not data.get("monitors"):
            return False, "UptimeRobot API error"
        status = data["monitors"][0]["status"]
        if status in (8, 9):
            return False, "UptimeRobot: down"
        return True, "UptimeRobot: up"
    except (requests.RequestException, ValueError, KeyError, IndexError) as e:
        return False, f"UptimeRobot check failed: {type(e).__name__}"


def check_http(url, session):
    """Returns (is_up, detail_string).

    Retries a few times (short pause between attempts) before giving up on
    a site. Added because a single dropped connection/DNS hiccup on our end
    -- not the target site -- was being recorded as a failed check,
    triggering false DOWN alerts that self-resolved by the next 5-minute
    cycle.
    """
    last_detail = "Unknown error"
    for attempt in range(1, HTTP_CHECK_ATTEMPTS + 1):
        try:
            r = session.get(
                url, timeout=(5, 15), allow_redirects=True,
                headers={
                    # A realistic browser UA -- some WAFs (Wordfence, Cloudflare
                    # bot rules) return 403 to anything that self-identifies as a
                    # bot/monitor, causing false DOWN alerts (seen on MZR).
                    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                                   "Chrome/126.0.0.0 Safari/537.36"),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-GB,en;q=0.9",
                },
            )
            if r.status_code == 403 and r.headers.get("X-SG-CDN"):
                return check_siteground_403(url)
            return r.status_code < 400, f"HTTP {r.status_code}"
        except requests.RequestException as e:
            last_detail = type(e).__name__
            if attempt < HTTP_CHECK_ATTEMPTS:
                time.sleep(HTTP_RETRY_DELAY_SECONDS)
    return False, last_detail


def check_ssl_expiry(url):
    """Returns (expiry_date_str, days_left) or (None, None) if not https."""
    if not url.lower().startswith("https://"):
        return None, None
    hostname = get_hostname(url)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expiry - datetime.now(timezone.utc)).days
        return expiry.strftime("%Y-%m-%d"), days_left
    except Exception:
        return "ERROR", None


def check_domain_expiry(url):
    """Returns (expiry_date_str, days_left) or (None, None) on failure."""
    if whois is None:
        return "ERROR", None
    domain = get_registrable_domain(get_hostname(url))
    try:
        w = whois.whois(domain)
        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        if exp is None:
            return "UNKNOWN", None
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        days_left = (exp - datetime.now(timezone.utc)).days
        return exp.strftime("%Y-%m-%d"), days_left
    except Exception:
        return "ERROR", None


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def send_email(subject, body, recipients):
    if not recipients:
        return
    sender = os.environ["ALERT_EMAIL"]
    password = os.environ["GMAIL_APP_PASSWORD"]
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, recipients, msg.as_string())
    except Exception as e:
        print(f"Email send failed: {e}")


def send_zapier(webhook_url, message):
    if not webhook_url:
        return
    try:
        requests.post(webhook_url, json={"message": message}, timeout=10)
    except requests.RequestException as e:
        print(f"Zapier post failed: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    gc = get_sheets_client()
    spreadsheet = gc.open_by_key(SPREADSHEET_ID)
    ensure_worksheets(spreadsheet)

    recipients = load_alert_emails(spreadsheet)
    status_ws, previous = load_previous_status(spreadsheet)
    history_ws = spreadsheet.worksheet(HISTORY_SHEET_NAME)
    incidents_ws, open_incidents = load_open_incidents(spreadsheet)
    monitors = load_monitors(spreadsheet)
    http_session = build_http_session()

    down_webhook = os.environ.get("ZAPIER_WEBHOOK_DOWNTIME")
    expiry_webhook = os.environ.get("ZAPIER_WEBHOOK_EXPIRY")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    # UK local time, used only in alert messages (Slack/email). The Sheet
    # stays in UTC so duration calculations are unaffected by clock changes.
    uk_time_str = datetime.now(ZoneInfo("Europe/London")).strftime("%Y-%m-%d %H:%M %Z")
    history_rows = []

    for m in monitors:
        name, url = m["name"], m["url"]
        prev_row, prev = previous.get(name, (None, {}))
        is_first_run = prev_row is None

        prev_status = prev.get("Status", "")
        prev_fails = int(prev.get("Consecutive Fails") or 0)
        prev_alerted = str(prev.get("Alerted Thresholds") or "")
        prev_ssl_days = prev.get("SSL Days Left")
        prev_domain_days = prev.get("Domain Days Left")

        # --- Uptime check (every run) ---
        if name in UPTIMEROBOT_MONITOR_IDS:
            is_up, detail = check_uptimerobot(UPTIMEROBOT_MONITOR_IDS[name])
        else:
            is_up, detail = check_http(url, http_session)
        if is_up:
            fails = 0
            new_status = "UP"
        else:
            fails = prev_fails + 1
            # Require 2 consecutive failures before calling it DOWN, so a
            # single network blip doesn't trigger a false alarm.
            new_status = "DOWN" if fails >= 2 else (prev_status or "UP")

        history_rows.append([name, now_str, new_status, detail])

        if not is_first_run:
            if prev_status != "DOWN" and new_status == "DOWN":
                msg = (f"<!here> \U0001F534 DOWN: {name} ({url}) is unreachable -- {detail}. "
                       f"Detected: {uk_time_str}")
                send_zapier(down_webhook, msg)
                send_email(f"[Site Monitor] DOWN: {name}", msg, recipients)
                # Open an incident record (if one isn't already open)
                if name not in open_incidents:
                    incidents_ws.append_row([name, now_str, "", "", detail])
            elif prev_status == "DOWN" and new_status == "UP":
                msg = f"✅ RECOVERED: {name} ({url}) is back up as of {uk_time_str}"
                send_zapier(down_webhook, msg)
                send_email(f"[Site Monitor] Recovered: {name}", msg, recipients)
                # Close the open incident record
                if name in open_incidents:
                    row_num, start_str = open_incidents.pop(name)
                    close_incident(incidents_ws, row_num, start_str, now_str)
            elif prev_status == "DOWN" and new_status == "DOWN":
                # Still down from a previous run -- send a periodic reminder
                # rather than staying silent for the whole outage.
                if fails >= 2 and (fails - 2) % STILL_DOWN_REPEAT_EVERY == 0:
                    approx_minutes = fails * 5
                    msg = (f"<!here> \U0001F534 STILL DOWN: {name} ({url}) has been unreachable "
                           f"for approximately {approx_minutes} minutes -- {detail}")
                    send_zapier(down_webhook, msg)
                    send_email(f"[Site Monitor] Still down: {name}", msg, recipients)

        # --- SSL / domain expiry checks (only in "full" mode, once a day) ---
        if CHECK_MODE == "full":
            ssl_date, ssl_days = check_ssl_expiry(url)
            domain_date, domain_days = check_domain_expiry(url)
        else:
            ssl_date, ssl_days = prev.get("SSL Expiry Date"), prev_ssl_days
            domain_date, domain_days = prev.get("Domain Expiry Date"), prev_domain_days

        alerted = set(t for t in prev_alerted.split(",") if t)

        # SiteGround bot-block notices: one quiet Slack message (no @here, no
        # email) when a block starts and one when it lifts. The "sgblock"
        # token in Alerted Thresholds remembers we're mid-block between runs.
        if detail == SG_BLOCK_DETAIL:
            if "sgblock" not in alerted:
                if not is_first_run:
                    send_zapier(down_webhook, (
                        f"\U0001F7E0 BLOCKED: {name} ({url}) is being blocked by its host's "
                        f"bot protection (SiteGround) -- the site is up, this is not an "
                        f"outage. Detected: {uk_time_str}"))
                alerted.add("sgblock")
        elif "sgblock" in alerted:
            if is_up:
                send_zapier(down_webhook, (
                    f"{name} ({url}) is no longer being blocked by its host's "
                    f"bot protection as of {uk_time_str}"))
            alerted.discard("sgblock")

        if CHECK_MODE == "full":
            for label, days_left, prior_days, date_str in (
                ("ssl", ssl_days, prev_ssl_days, ssl_date),
                ("domain", domain_days, prev_domain_days, domain_date),
            ):
                if days_left is None or days_left == "":
                    continue
                days_left = int(days_left)

                # If days-left jumped up significantly, treat it as renewed
                # and clear any thresholds we'd previously alerted on.
                try:
                    if prior_days not in (None, "") and days_left > int(prior_days) + 5:
                        alerted = {t for t in alerted if not t.startswith(label)}
                except (ValueError, TypeError):
                    pass

                for threshold in EXPIRY_THRESHOLDS:
                    key = f"{label}{threshold}"
                    if days_left <= threshold and key not in alerted and not is_first_run:
                        msg = (f"⏰ EXPIRY WARNING: {name} ({url}) {label.upper()} "
                               f"expires in {days_left} days ({date_str})")
                        send_zapier(expiry_webhook, msg)
                        send_email(f"[Site Monitor] {label.upper()} expiry warning: {name}", msg, recipients)
                        alerted.add(key)

        row_data = [
            name, url, new_status, now_str, fails,
            ssl_date or "", ssl_days if ssl_days not in (None, "") else "",
            domain_date or "", domain_days if domain_days not in (None, "") else "",
            ",".join(sorted(alerted)),
        ]

        if prev_row:
            status_ws.update(f"A{prev_row}:J{prev_row}", [row_data])
        else:
            status_ws.append_row(row_data)

        print(f"{name}: {new_status} (SSL {ssl_days}d, Domain {domain_days}d)")

    if history_rows:
        history_ws.append_rows(history_rows)

    if CHECK_MODE == "full":
        prune_history(spreadsheet)
        prune_incidents(spreadsheet)


if __name__ == "__main__":
    main()
