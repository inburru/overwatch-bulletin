# Overwatch Daily OSINT Bulletin
### iGuardSA / Overwatch Intelligence — Automated Morning Brief

Runs every morning at **06:00 SAST** via GitHub Actions.  
Searches live web sources, synthesises a structured threat intelligence bulletin,  
and delivers a branded HTML email to inburru@gmail.com.

---

## What it does

1. Runs **8 live web searches** against current threat intelligence sources
2. Synthesises results using Claude claude-sonnet-4-20250514 into a structured bulletin
3. Applies **South Africa relevance filtering** — every finding is assessed for SA/focus-target impact
4. Delivers a **dark-themed HTML email** with threat meters, finding cards, IOC table, and source log
5. Saves JSON + HTML artifacts to the GitHub Actions run (30-day retention)

---

## One-time setup — 20 minutes

### Step 1 — Create the GitHub repository

1. Go to https://github.com/new
2. Name it `overwatch-bulletin` (or anything you like)
3. Set it to **Private**
4. Click **Create repository**

### Step 2 — Upload the files

Upload these three files to the repository root:
- `bulletin.py`
- `requirements.txt`

Then create the folder `.github/workflows/` and upload:
- `daily-bulletin.yml` into that folder

The easiest way: use the GitHub web UI — click **Add file → Upload files**.

For the workflow file, you'll need to create the folder path manually:
- Click **Add file → Create new file**
- In the filename box, type: `.github/workflows/daily-bulletin.yml`
- Paste the contents of `daily-bulletin.yml`
- Click **Commit new file**

### Step 3 — Get your Anthropic API key

1. Go to https://console.anthropic.com/settings/keys
2. Click **Create Key**
3. Copy the key (starts with `sk-ant-...`)
4. Keep it safe — you won't see it again

### Step 4 — Set up Gmail App Password

Gmail requires an App Password (not your regular password) for SMTP access.

1. Go to your Google Account: https://myaccount.google.com
2. Click **Security** in the left sidebar
3. Under "How you sign in to Google", click **2-Step Verification**
   - Enable it if not already on (required for App Passwords)
4. Go back to Security, scroll down to **App passwords**
   - Or go directly to: https://myaccount.google.com/apppasswords
5. Under "Select app", choose **Mail**
6. Under "Select device", choose **Other (custom name)** → type `Overwatch`
7. Click **Generate**
8. Copy the 16-character password (e.g. `abcd efgh ijkl mnop`)
9. **Remove the spaces** when you use it: `abcdefghijklmnop`

### Step 5 — Add Secrets to GitHub

In your GitHub repository:
1. Click **Settings** (top menu)
2. Click **Secrets and variables → Actions** (left sidebar)
3. Click **New repository secret** — add each of these:

| Secret name | Value |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key (`sk-ant-...`) |
| `GMAIL_ADDRESS` | The Gmail address you're sending FROM (can be same as recipient) |
| `GMAIL_APP_PASSWORD` | Your 16-character App Password (no spaces) |

### Step 6 — Test it manually

1. In your repository, click **Actions** (top menu)
2. Click **Overwatch Daily OSINT Bulletin** in the left sidebar
3. Click **Run workflow → Run workflow**
4. Watch it run — should take 3–5 minutes
5. Check inburru@gmail.com for your first bulletin

If it works: you're done. It will now run automatically every morning at 06:00 SAST.

---

## Customising focus topics

Open `bulletin.py` and edit the `FOCUS_TOPICS` string near the top:

```python
FOCUS_TOPICS = (
    "Barloworld, Ingrain, Zahid Group, Vostochnaya Technica, South Africa, "
    "ransomware, BEC fraud, JSE-listed companies, SAPS, financial sector, "
    "SA government, SA critical infrastructure"
)
```

Add or remove any names, sectors, or threat types. Commit the change and it takes effect next run.

## Changing delivery time

Open `.github/workflows/daily-bulletin.yml` and edit the cron line:

```yaml
- cron: '0 4 * * *'   # 04:00 UTC = 06:00 SAST
```

Use https://crontab.guru to build a different schedule.  
Common options:
- `0 3 * * *` → 05:00 SAST
- `0 5 * * *` → 07:00 SAST
- `0 4 * * 1-5` → Weekdays only, 06:00 SAST

---

## Troubleshooting

**Email not arriving**
- Check the Actions run log for errors
- Check Gmail spam folder
- Verify the App Password has no spaces
- Make sure 2-Step Verification is enabled on the sending Gmail account

**API errors**
- Check your Anthropic API key is correct and has credits
- The web search tool requires an active Anthropic API subscription

**Workflow not triggering**
- GitHub Actions scheduled workflows can be delayed by up to 15 minutes
- Workflows in repos with no recent activity may be paused — just run manually once to re-activate

---

## Cost estimate

Each daily run makes approximately 9 API calls (8 searches + 1 synthesis).  
Estimated cost per run: **~$0.03–0.05 USD** depending on response lengths.  
Monthly cost: **~$1–1.50 USD**.

---

## Files

```
overwatch-bulletin/
├── bulletin.py                          # Main script
├── requirements.txt                     # Python dependencies
├── .github/
│   └── workflows/
│       └── daily-bulletin.yml          # GitHub Actions schedule
└── README.md                           # This file
```
