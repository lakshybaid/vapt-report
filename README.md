# VAPT Report Generator — Ethical Byte

A web application that generates professional VAPT (Vulnerability Assessment & Penetration Testing) reports in **DOCX** and **PDF** format, with SMS-verified account registration, role-based access control, and an admin dashboard.

---

## Project Structure

```
vapt-report/
├── backend.py          ← Flask server (auth, report generation, API)
├── frontend.html       ← Report generator UI  (served at /)
├── login.html          ← Login / register page (served at /login)
├── logo.png            ← Ethical Byte logo
├── Report_Template.docx← DOCX template (header/footer/borders)
├── requirements.txt    ← Python dependencies
└── README.md
```

> `reports.db` and `generated_reports/` are created automatically on first run and are excluded from version control.

---

## Requirements

- Python 3.8 or higher
- pip

---

## Setup & Run

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/vapt-report.git
cd vapt-report
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. (Optional) Configure environment variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `vapt-secret-change-me-in-production` | Flask session secret — **change in production** |
| `SUPERUSER_EMAIL` | `admin@ethicalbyte.com` | Default admin email |
| `SUPERUSER_PASS` | `Admin@1234` | Default admin password |
| `OTP_EXPIRY_MIN` | `10` | SMS OTP validity in minutes |
| `TWILIO_ACCOUNT_SID` | *(empty)* | Twilio Account SID |
| `TWILIO_AUTH_TOKEN` | *(empty)* | Twilio Auth Token |
| `TWILIO_FROM_NUMBER` | *(empty)* | Twilio sender phone number |

**Linux/macOS:**
```bash
export SECRET_KEY="your-random-secret-here"
```

**Windows:**
```cmd
set SECRET_KEY=your-random-secret-here
```

> If Twilio is not configured, OTPs are printed to the terminal — useful for local development.

### 4. Run the server

```bash
python backend.py
```

Open **http://localhost:5000/login** in your browser.

---

## Default Login

```
Email:    admin@ethicalbyte.com
Password: Admin@1234
```

> Change these via environment variables before going to production.

---

## Features

- Generate VAPT reports in **DOCX** and **PDF** — both with identical double-border layout, header logo, and footer
- Add unlimited vulnerabilities with severity, OWASP mapping, POC screenshots, and remediation
- Severity distribution bar chart
- SMS OTP registration via Twilio
- Admin dashboard — manage users and reports
- Role-based access (regular user / superuser)

---

## URLs

| URL | Access | Description |
|---|---|---|
| `/login` | Public | Login / register |
| `/` | Logged-in users | Report generator |
| `/admin` | Superuser only | Admin dashboard |

---

*Ethical Byte — Confidential*
