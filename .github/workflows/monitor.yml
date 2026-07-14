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
from datetime import datetime, timezone
from email.mime.text import MIMEText

import requests
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

STATUS_HEADERS = [
    "Name", "URL", "Status", "Last Checked (UTC)", "Consecutive Fails",
    "SSL Expiry Date", "SSL Days Left", "Domain Expiry Date", "Domain Days Left",
    "Alerted Thresholds",
]

EXPIRY_THRESHOLDS = [30, 14, 7, 1]  # days -- alert once when crossing each of these

# How many consecutive failed checks before we send a repeat "still down"
# reminder. Uptime checks run every 30 min, so 8 checks == ~4 hours.
STILL_DOWN_REPEAT_EVERY = 8

CHECK_MODE = os.environ.get("CHECK_MODE", "full")  # "uptime" or "full"

# UK second-level domains where the "registrable domain" is 3 labels, not 2
# (e.g. jacksonelectrical.co.uk, not just electrical.co.uk)
UK_SLDS = {"co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk", "sch.uk", "me.uk"}


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

def check_http(url):
    """Returns (is_up, detail_string)."""
    try:
        r = requests.get(
            url, timeout=15, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ClientSiteMonitor/1.0)"},
        )
        return r.status_code < 400, f"HTTP {r.status_code}"
    except requests.RequestException as e:
        return False, type(e).__name__


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
    monitors = load_monitors(spreadsheet)

    down_webhook = os.environ.get("ZAPIER_WEBHOOK_DOWNTIME")
    expiry_webhook = os.environ.get("ZAPIER_WEBHOOK_EXPIRY")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

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
        is_up, detail = check_http(url)
        if is_up:
            fails = 0
            new_status = "UP"
        else:
            fails = prev_fails + 1
            # Require 2 consecutive failures before calling it DOWN, so a
            # single network blip doesn't trigger a false alarm.
            new_status = "DOWN" if fails >= 2 else (prev_status or "UP")

        if not is_first_run:
            if prev_status != "DOWN" and new_status == "DOWN":
                msg = (f"<!here> \U0001F534 DOWN: {name} ({url}) is unreachable -- {detail}. "
                       f"Detected: {now_str}")
                send_zapier(down_webhook, msg)
                send_email(f"[Site Monitor] DOWN: {name}", msg, recipients)
            elif prev_status == "DOWN" and new_status == "UP":
                msg = f"✅ RECOVERED: {name} ({url}) is back up as of {now_str}"
                send_zapier(down_webhook, msg)
                send_email(f"[Site Monitor] Recovered: {name}", msg, recipients)
            elif prev_status == "DOWN" and new_status == "DOWN":
                # Still down from a previous run -- send a periodic reminder
                # rather than staying silent for the whole outage.
                if fails >= 2 and (fails - 2) % STILL_DOWN_REPEAT_EVERY == 0:
                    approx_minutes = fails * 30
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


if __name__ == "__main__":
    main()
