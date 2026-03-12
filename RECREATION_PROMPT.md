# G-Cloud Guard — Full Recreation Prompt

> **Purpose**: This prompt gives another GenAI all the context it needs to recreate this project from scratch. Two reference screenshots (`main_dashboard.png` and `detailed_compliance_CIS_AWSv3.png`) are provided in the `images_logo/` folder alongside all the logo assets.

---

## 1. Project Overview

Build a **Flask-based G-Cloud Guard** web application that reads **Prowler** compliance scan output CSVs (semicolon-delimited) and presents them in a modern, light-themed dashboard with:

- **Main Dashboard page** (`/`) — overall posture gauge, passed/failed stats, top 5 lowest-scoring chart, and a filterable & sortable framework table with logos.
- **Detail Compliance page** (`/compliance/<slug>`) — per-framework breakdown with a donut chart, summary stats, and expandable sections with requirement-level detail.
- **Collapsible sidebar** with company branding, navigation, and a Settings panel for AWS configuration.

Reference screenshots are in `images_logo/`:
- `main_dashboard.png` — shows the main dashboard page layout
- `detailed_compliance_CIS_AWSv3.png` — shows the detail compliance page layout

---

## 2. Data Source

### 2.1 CSV Files
Located at `../prowler/output/compliance/` relative to the app (43 files). Each file is named:
```
prowler-output-<ACCOUNT_ID>-<TIMESTAMP>_<framework_slug>.csv
```
Examples:
```
prowler-output-283008306631-20260310123103_cis_3.0_aws.csv
prowler-output-283008306631-20260310123103_aws_foundational_security_best_practices_aws.csv
prowler-output-283008306631-20260310123103_hipaa_aws.csv
prowler-output-283008306631-20260310123103_mitre_attack_aws.csv
```

### 2.2 CSV Format
- **Delimiter**: semicolon (`;`)
- **Encoding**: UTF-8 with `errors="replace"`
- **27 columns** (in order):

| Column | Description |
|--------|-------------|
| PROVIDER | Cloud provider (e.g., "aws") |
| DESCRIPTION | Framework description |
| ACCOUNTID | AWS account ID |
| REGION | AWS region |
| ASSESSMENTDATE | Scan date |
| REQUIREMENTS_ID | Unique requirement identifier |
| REQUIREMENTS_DESCRIPTION | Requirement description |
| REQUIREMENTS_ATTRIBUTES_SECTION | Section grouping |
| REQUIREMENTS_ATTRIBUTES_SUBSECTION | Subsection |
| REQUIREMENTS_ATTRIBUTES_PROFILE | Profile level |
| REQUIREMENTS_ATTRIBUTES_ASSESSMENTSTATUS | Assessment status |
| REQUIREMENTS_ATTRIBUTES_DESCRIPTION | Attribute description |
| REQUIREMENTS_ATTRIBUTES_RATIONALESTATEMENT | Rationale |
| REQUIREMENTS_ATTRIBUTES_IMPACTSTATEMENT | Impact |
| REQUIREMENTS_ATTRIBUTES_REMEDIATIONPROCEDURE | Remediation steps |
| REQUIREMENTS_ATTRIBUTES_AUDITPROCEDURE | Audit steps |
| REQUIREMENTS_ATTRIBUTES_ADDITIONALINFORMATION | Additional info |
| REQUIREMENTS_ATTRIBUTES_DEFAULTVALUE | Default value |
| REQUIREMENTS_ATTRIBUTES_REFERENCES | References |
| STATUS | **PASS** or **FAIL** — this is the key field |
| STATUSEXTENDED | Extended status message |
| RESOURCEID | AWS resource ID |
| RESOURCENAME | AWS resource name |
| CHECKID | Prowler check ID |
| MUTED | Whether check is muted |
| FRAMEWORK | Framework identified |
| NAME | Framework display name |

### 2.3 Slug Extraction
The slug is derived from the filename by splitting on `_` after the first underscore (after timestamp) and removing `.csv`:
```python
parts = filename.split("_", 1)
slug = parts[1].replace(".csv", "")
# e.g. "cis_3.0_aws" from "prowler-output-..._cis_3.0_aws.csv"
```

### 2.4 Main Prowler Output CSV
Located at `../prowler/output/prowler-output-*.csv` (flat files in the output root, **not** in `compliance/`). Also semicolon-delimited. Used to enrich requirements with severity, service name, risk, and remediation data.

Key columns used (42 total):

| Column | Description |
|--------|-------------|
| `CHECK_ID` | Prowler check identifier (join key) |
| `CHECK_TITLE` | Human-readable check name |
| `SEVERITY` | `critical`, `high`, `medium`, `low`, `informational` |
| `SERVICE_NAME` | Raw service slug (e.g. `awslambda`, `securityhub`) |
| `STATUS_EXTENDED` | Detailed status explanation |
| `RISK` | Exposure risk description |
| `REMEDIATION_RECOMMENDATION_TEXT` | Fix recommendation |
| `REMEDIATION_RECOMMENDATION_URL` | URL to remediation docs |
| `ADDITIONAL_URLS` | Pipe-separated additional reference URLs |

### 2.5 Service Name Mapping (`service_names.csv`)
Located at `compliance-dashboard/service_names.csv`. Two-column CSV (`raw,display`) mapping 32 raw prowler service slugs to human-readable display names.

Examples: `accessanalyzer → IAM Access Analyzer`, `awslambda → Lambda`, `securityhub → Security Hub`, `elbv2 → ELB V2`.

---

## 3. File Structure

```
compliance-dashboard/
├── app.py                          # Flask backend
├── service_names.csv               # Maps raw prowler service slugs to display names (32 entries)
├── images_logo/                    # Reference screenshots + logo source files
│   ├── main_dashboard.png          # Screenshot: Main dashboard
│   ├── detailed_compliance_CIS_AWSv3.png  # Screenshot: Detail page
│   ├── aws.png                     # AWS logo
│   ├── CIS.jpg                     # CIS logo
│   ├── CCM.png                     # CSA CCM logo
│   ├── FedRAMP.jpg                 # FedRAMP logo
│   ├── GDPR.png                    # GDPR logo
│   ├── HIPAA.png                   # HIPAA logo
│   ├── ISO.png                     # ISO 27001 logo
│   ├── MITRE.png                   # MITRE ATT&CK logo
│   ├── NIST.png                    # NIST logo
│   ├── pci.webp                    # PCI DSS logo
│   ├── SOC2.png                    # SOC2 logo
│   ├── gapv.webp                   # Company logo (full, for open sidebar)
│   ├── icon_gapv.webp              # Company logo (icon, for collapsed sidebar)
│   └── setting.png                 # Settings gear icon
├── static/
│   ├── css/
│   │   └── style.css               # Complete stylesheet (~1100 lines)
│   └── logos/                       # Same logo files as images_logo/ (deployed)
│       ├── aws.png
│       ├── CIS.jpg
│       ├── CCM.png
│       ├── FedRAMP.jpg
│       ├── GDPR.png
│       ├── HIPAA.png
│       ├── ISO.png
│       ├── MITRE.png
│       ├── NIST.png
│       ├── pci.webp
│       ├── SOC2.png
│       ├── gapv.webp
│       ├── icon_gapv.webp
│       └── setting.png
└── templates/
    ├── base.html                   # Base layout with sidebar + settings panel
    ├── dashboard.html              # Main dashboard page
    └── detail.html                 # Per-framework detail page
```

---

## 4. Backend — `app.py`

### 4.1 Full Source Code

```python
import csv
import glob
import io
import json
import os
import re
import shutil
import zipfile
from collections import defaultdict
from flask import Flask, abort, jsonify, render_template, request, send_file

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB upload limit


@app.errorhandler(413)
def request_too_large(e):
    return jsonify({"error": "File too large. Maximum upload size is 500 MB."}), 413

COMPLIANCE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "prowler", "output", "compliance"
)

PROWLER_OUTPUT_DIR = os.path.join(
    os.path.dirname(__file__), "..", "prowler", "output"
)

# Load service name display mapping
SERVICE_NAME_MAP = {}
_svc_map_path = os.path.join(os.path.dirname(__file__), "service_names.csv")
if os.path.exists(_svc_map_path):
    with open(_svc_map_path, encoding="utf-8") as _f:
        for _row in csv.DictReader(_f):
            SERVICE_NAME_MAP[_row["raw"].strip()] = _row["display"].strip()

# Map slug keywords to logo files and their background style
# Each entry: (keywords_list, logo_filename, bg_css_class)
LOGO_MAP = [
    # AWS frameworks
    (["aws_account_security", "aws_audit_manager", "aws_foundational", "aws_well_architected"], "aws.png", "logo-bg-dark"),
    # CIS
    (["cis_"], "CIS.jpg", "logo-bg-white"),
    # MITRE
    (["mitre_"], "MITRE.png", "logo-bg-white"),
    # NIST
    (["nist_"], "NIST.png", "logo-bg-white"),
    # ISO
    (["iso27001"], "ISO.png", "logo-bg-white"),
    # HIPAA
    (["hipaa"], "HIPAA.png", "logo-bg-white"),
    # GDPR
    (["gdpr"], "GDPR.png", "logo-bg-white"),
    # PCI DSS
    (["pci_"], "pci.webp", "logo-bg-white"),
    # SOC2
    (["soc2"], "SOC2.png", "logo-bg-white"),
    # FedRAMP
    (["fedramp"], "FedRAMP.jpg", "logo-bg-white"),
    # CSA CCM
    (["csa_ccm", "ccc_"], "CCM.png", "logo-bg-white"),
]


def _get_logo(slug):
    """Return (logo_file, bg_class) for a given slug, or None."""
    slug_lower = slug.lower()
    for keywords, logo_file, bg_class in LOGO_MAP:
        for kw in keywords:
            if kw in slug_lower:
                return logo_file, bg_class
    return None, None


def parse_all_frameworks():
    """Parse all compliance CSVs and return per-framework summary stats."""
    frameworks = {}
    csv_files = sorted(glob.glob(os.path.join(COMPLIANCE_DIR, "*.csv")))

    for filepath in csv_files:
        filename = os.path.basename(filepath)
        parts = filename.split("_", 1)
        if len(parts) < 2:
            continue
        slug = parts[1].replace(".csv", "")

        rows = _read_csv(filepath)
        if not rows:
            continue

        name = rows[0].get("NAME", slug).strip()
        description = rows[0].get("DESCRIPTION", "").strip()
        provider = rows[0].get("PROVIDER", "").strip()
        account_id = rows[0].get("ACCOUNTID", "").strip()

        total = len(rows)
        passed = sum(1 for r in rows if r.get("STATUS", "").upper() == "PASS")
        failed = total - passed
        score = round((passed / total) * 100, 2) if total else 0

        logo_file, logo_bg = _get_logo(slug)

        frameworks[slug] = {
            "slug": slug,
            "name": name,
            "description": description[:80] + ("..." if len(description) > 80 else ""),
            "full_description": description,
            "provider": provider,
            "account_id": account_id,
            "total": total,
            "passed": passed,
            "failed": failed,
            "score": score,
            "filepath": filepath,
            "logo_file": logo_file,
            "logo_bg": logo_bg,
        }

    return frameworks


def parse_framework_detail(filepath):
    """Parse a single compliance CSV and return section-level breakdown."""
    rows = _read_csv(filepath)
    if not rows:
        return None

    name = rows[0].get("NAME", "").strip()
    description = rows[0].get("DESCRIPTION", "").strip()
    provider = rows[0].get("PROVIDER", "").strip()
    account_id = rows[0].get("ACCOUNTID", "").strip()

    total = len(rows)
    passed = sum(1 for r in rows if r.get("STATUS", "").upper() == "PASS")
    failed = total - passed
    score = round((passed / total) * 100, 2) if total else 0

    # Group by REQUIREMENTS_ATTRIBUTES_SECTION
    sections = defaultdict(lambda: {"total": 0, "passed": 0, "requirements": set()})
    for r in rows:
        section = r.get("REQUIREMENTS_ATTRIBUTES_SECTION", "").strip()
        if not section:
            section = "Uncategorized"
        sections[section]["total"] += 1
        if r.get("STATUS", "").upper() == "PASS":
            sections[section]["passed"] += 1
        req_id = r.get("REQUIREMENTS_ID", "").strip()
        if req_id:
            sections[section]["requirements"].add(req_id)

    # Build requirement-level detail (collecting resource-level rows per requirement)
    requirements = defaultdict(lambda: {"total": 0, "passed": 0, "description": "", "section": "", "check_ids": set(), "resources": []})
    for r in rows:
        req_id = r.get("REQUIREMENTS_ID", "").strip()
        if not req_id:
            continue
        requirements[req_id]["total"] += 1
        requirements[req_id]["description"] = r.get("REQUIREMENTS_DESCRIPTION", "").strip()
        requirements[req_id]["section"] = r.get("REQUIREMENTS_ATTRIBUTES_SECTION", "").strip()
        check_id = r.get("CHECKID", "").strip()
        if check_id:
            requirements[req_id]["check_ids"].add(check_id)
        # Collect resource-level data
        resource_id = r.get("RESOURCEID", "").strip()
        if resource_id:
            requirements[req_id]["resources"].append({
                "resource_id": resource_id,
                "resource_name": r.get("RESOURCENAME", "").strip(),
                "status": r.get("STATUS", "").strip().upper(),
                "status_extended": r.get("STATUSEXTENDED", "").strip(),
                "region": r.get("REGION", "").strip(),
                "check_id": check_id,
            })
        if r.get("STATUS", "").upper() == "PASS":
            requirements[req_id]["passed"] += 1

    # Enrich requirements from main prowler output CSV
    main_lookup = _parse_main_prowler_csv()

    section_list = []
    for sec_name in sorted(sections.keys()):
        s = sections[sec_name]
        sec_score = round((s["passed"] / s["total"]) * 100, 2) if s["total"] else 0
        sec_reqs = []
        for req_id, req_data in sorted(requirements.items()):
            if req_data["section"] == sec_name or (sec_name == "Uncategorized" and not req_data["section"]):
                req_score = round((req_data["passed"] / req_data["total"]) * 100, 2) if req_data["total"] else 0
                # Enrich from main CSV using the first matching check_id
                enrichment = {}
                for cid in req_data["check_ids"]:
                    if cid in main_lookup:
                        enrichment = main_lookup[cid]
                        break
                severity_raw = enrichment.get("severity", "")
                severity = severity_raw.capitalize() if severity_raw else ""
                # For requirements with only manual checks, show Manual badge
                if not severity and req_data["check_ids"] and all(c == "manual" for c in req_data["check_ids"]):
                    severity = "Manual"
                svc_raw = enrichment.get("service_name", "")
                service_display = SERVICE_NAME_MAP.get(svc_raw, svc_raw.replace("_", " ").title() if svc_raw else "")
                sec_reqs.append({
                    "id": req_id,
                    "description": req_data["description"],
                    "total": req_data["total"],
                    "passed": req_data["passed"],
                    "failed": req_data["total"] - req_data["passed"],
                    "score": req_score,
                    "check_id": enrichment.get("check_id", ""),
                    "check_title": enrichment.get("check_title", ""),
                    "severity": severity,
                    "service_name": service_display,
                    "status_extended": enrichment.get("status_extended", ""),
                    "risk": enrichment.get("risk", ""),
                    "remediation_text": enrichment.get("remediation_text", ""),
                    "remediation_url": enrichment.get("remediation_url", ""),
                    "additional_urls": enrichment.get("additional_urls", ""),
                    "resources": req_data["resources"],
                    "resources_lookup": {
                        cid: SERVICE_NAME_MAP.get(main_lookup[cid]["service_name"],
                             main_lookup[cid]["service_name"].replace("_", " ").title())
                        for cid in req_data["check_ids"] if cid in main_lookup
                    },
                })
        section_list.append({
            "name": sec_name,
            "total": s["total"],
            "passed": s["passed"],
            "failed": s["total"] - s["passed"],
            "score": sec_score,
            "requirement_count": len(s["requirements"]),
            "requirements": sec_reqs,
        })

    return {
        "name": name,
        "description": description,
        "provider": provider,
        "account_id": account_id,
        "total": total,
        "passed": passed,
        "failed": failed,
        "score": score,
        "sections": section_list,
        "requirement_count": len(requirements),
    }


def _read_csv(filepath):
    """Read a semicolon-delimited CSV file."""
    rows = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f, delimiter=";")
        for row in reader:
            rows.append(row)
    return rows


def _parse_main_prowler_csv():
    """Parse the main prowler output CSV and build a lookup by CHECK_ID."""
    csv_files = sorted(glob.glob(os.path.join(PROWLER_OUTPUT_DIR, "prowler-output-*.csv")))
    # Exclude files in subdirectories (compliance/)
    csv_files = [f for f in csv_files if os.path.abspath(os.path.dirname(f)) == os.path.abspath(PROWLER_OUTPUT_DIR)]
    if not csv_files:
        return {}
    rows = _read_csv(csv_files[0])
    lookup = {}
    for r in rows:
        check_id = r.get("CHECK_ID", "").strip()
        if not check_id:
            continue
        if check_id not in lookup:
            lookup[check_id] = {
                "check_id": check_id,
                "check_title": r.get("CHECK_TITLE", "").strip(),
                "severity": r.get("SEVERITY", "").strip(),
                "service_name": r.get("SERVICE_NAME", "").strip(),
                "status_extended": r.get("STATUS_EXTENDED", "").strip(),
                "risk": r.get("RISK", "").strip(),
                "remediation_text": r.get("REMEDIATION_RECOMMENDATION_TEXT", "").strip(),
                "remediation_url": r.get("REMEDIATION_RECOMMENDATION_URL", "").strip(),
                "additional_urls": r.get("ADDITIONAL_URLS", "").strip(),
            }
    return lookup


@app.route("/")
def dashboard():
    frameworks = parse_all_frameworks()
    total_passed = sum(f["passed"] for f in frameworks.values())
    total_failed = sum(f["failed"] for f in frameworks.values())
    total_checks = total_passed + total_failed
    overall_score = round((total_passed / total_checks) * 100, 2) if total_checks else 0

    sorted_by_score = sorted(frameworks.values(), key=lambda x: x["score"])
    lowest_5 = sorted_by_score[:5]

    return render_template(
        "dashboard.html",
        frameworks=sorted(frameworks.values(), key=lambda x: x["name"]),
        total_passed=total_passed,
        total_failed=total_failed,
        total_checks=total_checks,
        overall_score=overall_score,
        lowest_5=lowest_5,
    )


@app.route("/compliance/<slug>")
def compliance_detail(slug):
    frameworks = parse_all_frameworks()
    fw = frameworks.get(slug)
    if not fw:
        abort(404)
    detail = parse_framework_detail(fw["filepath"])
    if not detail:
        abort(404)
    detail["slug"] = slug
    detail["logo_file"] = fw.get("logo_file")
    detail["logo_bg"] = fw.get("logo_bg")
    return render_template("detail.html", fw=detail)


@app.route("/export")
def export_data():
    """Package the prowler output directory into a ZIP for download."""
    output_dir = os.path.abspath(PROWLER_OUTPUT_DIR)
    compliance_dir = os.path.abspath(COMPLIANCE_DIR)

    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as zf:
        # Main output files (csv, html, ocsf.json) in the root of the ZIP
        for f in sorted(glob.glob(os.path.join(output_dir, "prowler-output-*"))):
            if os.path.isfile(f) and os.path.abspath(os.path.dirname(f)) == output_dir:
                zf.write(f, os.path.basename(f))
        # Compliance CSVs under compliance/ subfolder
        for f in sorted(glob.glob(os.path.join(compliance_dir, "*.csv"))):
            if os.path.isfile(f):
                zf.write(f, os.path.join("compliance", os.path.basename(f)))

    mem.seek(0)
    return send_file(
        mem,
        mimetype="application/zip",
        as_attachment=True,
        download_name="prowler-output-export.zip",
    )


@app.route("/import", methods=["POST"])
def import_data():
    """Accept a ZIP upload matching the prowler output structure."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded = request.files["file"]
    if not uploaded.filename.lower().endswith(".zip"):
        return jsonify({"error": "File must be a .zip archive"}), 400

    try:
        data = uploaded.read()
    except Exception as e:
        return jsonify({"error": "Failed to read uploaded file: " + str(e)}), 400

    try:
        zf_obj = zipfile.ZipFile(io.BytesIO(data), "r")
    except zipfile.BadZipFile:
        return jsonify({"error": "Invalid or corrupted ZIP file"}), 400
    except Exception as e:
        return jsonify({"error": "Failed to open ZIP: " + str(e)}), 400

    try:
        with zf_obj as zf:
            raw_names = zf.namelist()

            # Detect and strip a single common folder prefix (e.g. "output/" or "prowler-output-xxx/")
            # so users can zip the output folder itself and still have it work.
            prefix = ""
            top_level = {n.split("/")[0] for n in raw_names if n}
            if len(top_level) == 1:
                candidate = list(top_level)[0] + "/"
                # Only treat as prefix if there are no prowler-output CSVs at the true root
                root_at_true = [n for n in raw_names if re.match(r"^prowler-output-[^/]+\.csv$", n)]
                if not root_at_true:
                    prefix = candidate

            def strip(name):
                return name[len(prefix):] if prefix and name.startswith(prefix) else name

            names = [strip(n) for n in raw_names]

            # Validate: must have at least one root prowler-output-*.csv and compliance/ CSVs
            root_csvs = [n for n in names if re.match(r"^prowler-output-[^/]+\.csv$", n)]
            compliance_csvs = [n for n in names if re.match(r"^compliance/prowler-output-[^/]+\.csv$", n)]

            if not root_csvs:
                return jsonify({"error": (
                    "ZIP must contain a prowler-output-*.csv in the root. "
                    "Export using the Export button on this page to get the correct format."
                )}), 400
            if not compliance_csvs:
                return jsonify({"error": (
                    "ZIP must contain compliance/prowler-output-*.csv files. "
                    "Export using the Export button on this page to get the correct format."
                )}), 400

            output_dir = os.path.abspath(PROWLER_OUTPUT_DIR)
            compliance_dir = os.path.abspath(COMPLIANCE_DIR)

            # Remove existing files (skip ZIP files themselves)
            for old in glob.glob(os.path.join(output_dir, "prowler-output-*")):
                if (os.path.isfile(old)
                        and os.path.abspath(os.path.dirname(old)) == output_dir
                        and not old.lower().endswith(".zip")):
                    os.remove(old)
            for old in glob.glob(os.path.join(compliance_dir, "*.csv")):
                if os.path.isfile(old):
                    os.remove(old)

            os.makedirs(compliance_dir, exist_ok=True)

            # Extract with path-traversal protection
            allowed_root = re.compile(r"^prowler-output-[^/]+\.(csv|html|json)$")
            allowed_compliance = re.compile(r"^compliance/prowler-output-[^/]+\.csv$")

            extracted = 0
            for raw_name, norm_name in zip(raw_names, names):
                if allowed_root.match(norm_name):
                    target = os.path.normpath(os.path.join(output_dir, os.path.basename(norm_name)))
                    if not target.startswith(output_dir + os.sep):
                        continue
                elif allowed_compliance.match(norm_name):
                    target = os.path.normpath(os.path.join(compliance_dir, os.path.basename(norm_name)))
                    if not target.startswith(compliance_dir + os.sep):
                        continue
                else:
                    continue

                with zf.open(raw_name) as src, open(target, "wb") as dst:
                    dst.write(src.read())
                extracted += 1

    except Exception as e:
        return jsonify({"error": "Import failed: " + str(e)}), 500

    return jsonify({"success": True, "extracted": extracted})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
```

---

## 5. Templates

### 5.1 `base.html` — Base Layout

Key elements:
- **Favicon**: `<link rel="icon" type="image/webp" href="{{ url_for('static', filename='logos/icon_gapv.webp') }}">` — uses the company icon as the browser tab icon.
- **Chart.js v4.4.7 via CDN**: `https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js`
- **Collapsible sidebar** (`nav.sidebar#sidebar`):
  - **Brand section**: The brand div content is wrapped in `<a href="/" class="sidebar-brand-link">` so clicking the logo navigates to the dashboard. Two logos — `gapv.webp` (full, shown when open, 126px height, -0.5cm left margin) and `icon_gapv.webp` (icon, shown when collapsed, 36×36px). Title text: "Cloud Guard" (shown when expanded, hidden when collapsed).
  - **Navigation**: Single item "Compliance" with grid SVG icon, links to `/`, active state based on `request.endpoint`.
  - **Settings button** at bottom with `setting.png` icon.
  - **Toggle behavior**: `.sidebar-toggle` button is hidden (`display: none`). Instead, clicking any empty area of the sidebar toggles `collapsed` class on sidebar and `sidebar-collapsed` class on body. Interactive elements (links, buttons, inputs) are excluded from toggle via `e.target.closest()`.
- **Settings Panel** (slide-over from right, 400px wide):
  - AWS Access Key ID (text input)
  - AWS Secret Access Key (password input) with hint text
  - AWS Regions: 21 checkboxes in a scrollable container (240px max-height), all major AWS regions
  - "Run Prowler Scan" button (disabled until all fields filled; currently shows alert, not implemented)
  - Cancel button
  - Dark overlay behind panel

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}G-Cloud Guard{% endblock %}</title>
    <link rel="icon" type="image/webp" href="{{ url_for('static', filename='logos/icon_gapv.webp') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
    {% block head %}{% endblock %}
</head>
<body>
    <nav class="sidebar" id="sidebar">
        <div class="sidebar-brand">
            <a href="/" class="sidebar-brand-link">
                <img src="{{ url_for('static', filename='logos/gapv.webp') }}" alt="G-ASIAPACIFIC" class="brand-logo brand-logo-full">
                <img src="{{ url_for('static', filename='logos/icon_gapv.webp') }}" alt="G-ASIAPACIFIC" class="brand-logo brand-logo-icon">
                <span class="brand-title">Cloud Guard</span>
            </a>
        </div>
        <div class="sidebar-toggle" id="sidebarToggle" title="Toggle sidebar">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
        </div>
        <ul class="sidebar-nav">
            <li><a href="/" class="{% if request.endpoint == 'dashboard' %}active{% endif %}">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
                <span>Compliance</span>
            </a></li>
        </ul>
        <div class="sidebar-bottom">
            <button class="settings-btn" id="settingsBtn" title="Settings">
                <img src="{{ url_for('static', filename='logos/setting.png') }}" alt="Settings">
                <span>Settings</span>
            </button>
        </div>
    </nav>

    <!-- Settings Panel -->
    <div class="settings-overlay" id="settingsOverlay"></div>
    <div class="settings-panel" id="settingsPanel">
        <div class="settings-panel-header">
            <h2>AWS Configuration</h2>
            <button class="settings-close" id="settingsClose">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
            </button>
        </div>
        <div class="settings-panel-body">
            <div class="settings-section">
                <label for="awsAccessKey">AWS Access Key ID</label>
                <input type="text" id="awsAccessKey" placeholder="AKIAIOSFODNN7EXAMPLE" autocomplete="off">
            </div>
            <div class="settings-section">
                <label for="awsSecretKey">AWS Secret Access Key</label>
                <input type="password" id="awsSecretKey" placeholder="••••••••••••••••••••" autocomplete="off">
                <span class="hint">Credentials are stored in browser only and sent to backend on scan trigger.</span>
            </div>
            <div class="settings-section">
                <label>AWS Regions</label>
                <div class="region-checkbox-group" id="regionCheckboxGroup">
                    <label class="region-cb"><input type="checkbox" value="us-east-1"> US East (N. Virginia) — us-east-1</label>
                    <label class="region-cb"><input type="checkbox" value="us-east-2"> US East (Ohio) — us-east-2</label>
                    <label class="region-cb"><input type="checkbox" value="us-west-1"> US West (N. California) — us-west-1</label>
                    <label class="region-cb"><input type="checkbox" value="us-west-2"> US West (Oregon) — us-west-2</label>
                    <label class="region-cb"><input type="checkbox" value="af-south-1"> Africa (Cape Town) — af-south-1</label>
                    <label class="region-cb"><input type="checkbox" value="ap-east-1"> Asia Pacific (Hong Kong) — ap-east-1</label>
                    <label class="region-cb"><input type="checkbox" value="ap-south-1"> Asia Pacific (Mumbai) — ap-south-1</label>
                    <label class="region-cb"><input type="checkbox" value="ap-southeast-1"> Asia Pacific (Singapore) — ap-southeast-1</label>
                    <label class="region-cb"><input type="checkbox" value="ap-southeast-2"> Asia Pacific (Sydney) — ap-southeast-2</label>
                    <label class="region-cb"><input type="checkbox" value="ap-northeast-1"> Asia Pacific (Tokyo) — ap-northeast-1</label>
                    <label class="region-cb"><input type="checkbox" value="ap-northeast-2"> Asia Pacific (Seoul) — ap-northeast-2</label>
                    <label class="region-cb"><input type="checkbox" value="ap-northeast-3"> Asia Pacific (Osaka) — ap-northeast-3</label>
                    <label class="region-cb"><input type="checkbox" value="ca-central-1"> Canada (Central) — ca-central-1</label>
                    <label class="region-cb"><input type="checkbox" value="eu-central-1"> Europe (Frankfurt) — eu-central-1</label>
                    <label class="region-cb"><input type="checkbox" value="eu-west-1"> Europe (Ireland) — eu-west-1</label>
                    <label class="region-cb"><input type="checkbox" value="eu-west-2"> Europe (London) — eu-west-2</label>
                    <label class="region-cb"><input type="checkbox" value="eu-west-3"> Europe (Paris) — eu-west-3</label>
                    <label class="region-cb"><input type="checkbox" value="eu-south-1"> Europe (Milan) — eu-south-1</label>
                    <label class="region-cb"><input type="checkbox" value="eu-north-1"> Europe (Stockholm) — eu-north-1</label>
                    <label class="region-cb"><input type="checkbox" value="me-south-1"> Middle East (Bahrain) — me-south-1</label>
                    <label class="region-cb"><input type="checkbox" value="sa-east-1"> South America (São Paulo) — sa-east-1</label>
                </div>
            </div>
        </div>
        <div class="settings-actions">
            <button class="btn-primary" id="triggerScan" disabled>Run Prowler Scan</button>
            <button class="btn-secondary" id="settingsCancelBtn">Cancel</button>
        </div>
    </div>

    <main class="content" id="mainContent">
        {% block content %}{% endblock %}
    </main>
    {% block scripts %}{% endblock %}
    <script>
    // Sidebar toggle — click any empty area of sidebar
    (function() {
        const sidebar = document.getElementById('sidebar');
        sidebar.addEventListener('click', (e) => {
            const target = e.target.closest('a, button, input, select, label, .settings-btn');
            if (target) return;
            sidebar.classList.toggle('collapsed');
            document.body.classList.toggle('sidebar-collapsed');
        });
        sidebar.style.cursor = 'pointer';
    })();

    // Settings panel
    (function() {
        const btn = document.getElementById('settingsBtn');
        const overlay = document.getElementById('settingsOverlay');
        const panel = document.getElementById('settingsPanel');
        const closeBtn = document.getElementById('settingsClose');
        const cancelBtn = document.getElementById('settingsCancelBtn');
        const triggerBtn = document.getElementById('triggerScan');
        const keyInput = document.getElementById('awsAccessKey');
        const secretInput = document.getElementById('awsSecretKey');
        const regionBoxes = document.querySelectorAll('#regionCheckboxGroup input[type="checkbox"]');

        function openPanel() {
            overlay.classList.add('open');
            panel.classList.add('open');
        }
        function closePanel() {
            overlay.classList.remove('open');
            panel.classList.remove('open');
        }
        function getSelectedRegions() {
            return Array.from(regionBoxes).filter(cb => cb.checked).map(cb => cb.value);
        }
        function checkReady() {
            const ready = keyInput.value.trim() && secretInput.value.trim() && getSelectedRegions().length > 0;
            triggerBtn.disabled = !ready;
        }

        btn.addEventListener('click', openPanel);
        overlay.addEventListener('click', closePanel);
        closeBtn.addEventListener('click', closePanel);
        cancelBtn.addEventListener('click', closePanel);
        keyInput.addEventListener('input', checkReady);
        secretInput.addEventListener('input', checkReady);
        regionBoxes.forEach(cb => cb.addEventListener('change', checkReady));

        triggerBtn.addEventListener('click', () => {
            const regions = getSelectedRegions();
            alert('Prowler scan trigger is not yet implemented.\n\nSelected regions: ' + regions.join(', '));
        });
    })();
    </script>
</body>
</html>
```

### 5.2 `dashboard.html` — Main Dashboard

- Extends `base.html`
- **Page title row**: `<div class="page-title-row">` containing the `<h1 class="page-title">Compliance</h1>` on the left and `<div class="page-actions">` on the right with two buttons:
  - **Import button** (`<button class="io-btn" id="importBtn">` with upload arrow SVG icon) — triggers hidden file input
  - **Export button** (`<a class="io-btn" href="/export" download>` with download arrow SVG icon) — direct link download
  - **Hidden file input**: `<input type="file" id="importFileInput" accept=".zip" style="display:none">`
  - **Import toast**: `<div id="importToast" class="import-toast" style="display:none"></div>` — fixed top-right notification
- **Stats Row** (CSS Grid: `220px 180px 1fr`):
  1. **Posture Score Gauge** — Chart.js doughnut, 180° arc (semicircle), score % centered below arc
  2. **Passed / Failed stacked** — Two cards vertically stacked, large 32px numbers. Passed is colored `#10b981`, Failed is colored `#ef4444`.
  3. **Top 5 Lowest Scoring** — Horizontal bar chart with 5-tier colors, draggable y-axis resize handle
- **Framework Table**:
  - Header with "Framework view" title and item count
  - **Filters**: Search box, Provider dropdown, Score range dropdown (90-100/70-89/50-69/0-49), Failed range dropdown (0/1-10/11-50/51-200/201+)
  - **Active filter tags** shown below filters with × remove buttons
  - **Table columns**: Framework (with logo), Description, Total Checks, Passed Checks, Failed Checks, Posture Score (bar + percentage)
  - **Clickable rows** navigate to `/compliance/<slug>`
  - **Resizable columns** via drag handles on column headers
  - **Logo display**: Each framework row shows a small logo badge (30×30px) — AWS logos get dark background (`logo-bg-dark`), all others white with border (`logo-bg-white`). Frameworks without a mapped logo show a 3-letter purple badge.
  - **5-tier score colors**: ≥90% green, ≥70% yellow, ≥50% orange, ≥20% red, <20% dark red
- **Import JS** (in `{% block scripts %}`):
  - `showToast(msg, isError)` — shows fixed toast in top-right corner for 5 seconds
  - Import button click triggers file picker
  - File picker `change` event: builds `FormData`, sends `POST /import`, checks `Content-Type` before calling `.json()` to guard against non-JSON error responses, shows success toast and reloads after 1800ms, or shows error toast
  - Button text/state restored in `finally`

```html
{% extends "base.html" %}
{% block title %}G-Cloud Guard{% endblock %}

{% block content %}
<div class="page-title-row">
    <h1 class="page-title">Compliance</h1>
    <div class="page-actions">
        <button class="io-btn" id="importBtn" title="Import a prowler output ZIP">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            Import
        </button>
        <a class="io-btn" href="/export" download>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Export
        </a>
    </div>
</div>
<!-- Hidden file picker for import -->
<input type="file" id="importFileInput" accept=".zip" style="display:none">
<!-- Import toast notification -->
<div id="importToast" class="import-toast" style="display:none"></div>

<!-- Top Stats Row -->
<div class="stats-row">
    <!-- Posture Score Gauge -->
    <div class="card gauge-card">
        <div class="card-header">
            <span>Overall Posture Score</span>
            <span class="info-icon" title="Overall percentage of passed checks across all frameworks">&#9432;</span>
        </div>
        <div class="gauge-wrapper">
            <canvas id="postureGauge" width="200" height="130"></canvas>
            <div class="gauge-value">{{ overall_score }}%</div>
        </div>
    </div>

    <!-- Passed / Failed stacked -->
    <div class="stat-stack">
        <div class="card stat-card">
            <div class="card-header">
                <span>Passed Checks</span>
                <span class="info-icon" title="Total number of passed checks">&#9432;</span>
            </div>
            <div class="stat-value passed">{{ "{:,}".format(total_passed) }}</div>
        </div>
        <div class="card stat-card">
            <div class="card-header">
                <span>Failed Checks</span>
                <span class="info-icon" title="Total number of failed checks">&#9432;</span>
            </div>
            <div class="stat-value failed">{{ "{:,}".format(total_failed) }}</div>
        </div>
    </div>

    <!-- Top 5 Lowest Scoring -->
    <div class="card chart-card wide-card">
        <div class="card-header">
            <span>Top 5 Lowest Scoring Compliance Frameworks</span>
        </div>
        <div class="chart-resizable-wrapper" style="position: relative; height: 160px;">
            <canvas id="lowestChart"></canvas>
            <div class="chart-y-resize-handle" id="chartYResizeHandle" title="Drag to resize labels"></div>
        </div>
    </div>
</div>

<!-- Framework Table -->
<div class="table-section">
    <div class="table-header-row">
        <h2 class="section-title">Framework view</h2>
        <div class="table-meta">
            <span class="item-count">{{ frameworks|length }} Items</span>
        </div>
    </div>

    <div class="table-controls">
        <div class="search-box">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            <input type="text" id="frameworkSearch" placeholder="Search frameworks..." />
        </div>
        <div class="filter-group">
            <label>Provider</label>
            <select id="filterProvider" class="filter-select">
                <option value="">All</option>
                {% set providers = frameworks|map(attribute='provider')|unique|sort %}
                {% for p in providers %}
                <option value="{{ p }}">{{ p|upper }}</option>
                {% endfor %}
            </select>
        </div>
        <div class="filter-group">
            <label>Score</label>
            <select id="filterScore" class="filter-select">
                <option value="">All</option>
                <option value="90-100">90% – 100% (High)</option>
                <option value="70-89">70% – 89% (Medium)</option>
                <option value="50-69">50% – 69% (Low)</option>
                <option value="0-49">0% – 49% (Critical)</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Failed</label>
            <select id="filterFailed" class="filter-select">
                <option value="">All</option>
                <option value="0">No failures</option>
                <option value="1-10">1 – 10</option>
                <option value="11-50">11 – 50</option>
                <option value="51-200">51 – 200</option>
                <option value="201+">201+</option>
            </select>
        </div>
    </div>
    <div class="active-filters" id="activeFilters"></div>

    <table class="data-table" id="frameworkTable">
        <thead>
            <tr>
                <th>Framework</th>
                <th>Description</th>
                <th>Total Checks</th>
                <th>Passed Checks</th>
                <th>Failed Checks</th>
                <th>Posture Score</th>
            </tr>
        </thead>
        <tbody>
            {% for fw in frameworks %}
            <tr class="clickable-row" data-href="/compliance/{{ fw.slug }}" data-provider="{{ fw.provider }}" data-score="{{ fw.score }}" data-failed="{{ fw.failed }}">
                <td class="fw-name">
                    {% if fw.logo_file %}
                    <span class="fw-logo {{ fw.logo_bg }}">
                        <img src="{{ url_for('static', filename='logos/' + fw.logo_file) }}" alt="">
                    </span>
                    {% else %}
                    <span class="fw-badge" style="background: #7c3aed">{{ fw.provider[:3]|upper }}</span>
                    {% endif %}
                    {{ fw.name }}
                </td>
                <td class="fw-desc">{{ fw.description }}</td>
                <td>{{ "{:,}".format(fw.total) }}</td>
                <td>{{ "{:,}".format(fw.passed) }}</td>
                <td>
                    {% if fw.failed > 0 %}
                    <span class="failed-link">{{ "{:,}".format(fw.failed) }}</span>
                    {% else %}
                    <span>0</span>
                    {% endif %}
                </td>
                <td>
                    <div class="score-cell">
                        <span class="score-pct">{{ fw.score }}%</span>
                        <div class="score-bar">
                            <div class="score-bar-fill {% if fw.score >= 90 %}score-green{% elif fw.score >= 70 %}score-yellow{% elif fw.score >= 50 %}score-orange{% elif fw.score >= 20 %}score-red{% else %}score-dark-red{% endif %}" style="width: {{ fw.score }}%"></div>
                        </div>
                    </div>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}

{% block scripts %}
<script>
// Color helper for 5-tier score
function scoreColor(s) {
    if (s >= 90) return '#10b981';
    if (s >= 70) return '#ca8a04';
    if (s >= 50) return '#f97316';
    if (s >= 20) return '#ef4444';
    return '#991b1b';
}

// Posture gauge
(function() {
    const ctx = document.getElementById('postureGauge').getContext('2d');
    const score = {{ overall_score }};
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, 100 - score],
                backgroundColor: [scoreColor(score), '#e2e8f0'],
                borderWidth: 0,
                circumference: 180,
                rotation: 270,
                cutout: '75%'
            }]
        },
        options: {
            responsive: false,
            plugins: { legend: { display: false }, tooltip: { enabled: false } },
            layout: { padding: 0 }
        }
    });
})();

// Top 5 lowest scoring bar chart — full names in tooltip, resizable y-axis labels
var lowestChartInstance;
var yAxisLabelWidth = null;
(function() {
    const ctx = document.getElementById('lowestChart').getContext('2d');
    const fullLabels = {{ lowest_5|map(attribute='name')|list|tojson }};
    const scores = {{ lowest_5|map(attribute='score')|list|tojson }};

    function truncateLabels(maxPx) {
        const maxChars = Math.max(8, Math.floor((maxPx || 180) / 6.5));
        return fullLabels.map(l => l.length > maxChars ? l.substring(0, maxChars - 1) + '…' : l);
    }

    lowestChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: truncateLabels(yAxisLabelWidth),
            datasets: [{
                label: 'Score %',
                data: scores,
                backgroundColor: scores.map(s => scoreColor(s)),
                borderRadius: 4,
                barThickness: 20
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { min: 0, max: 100, grid: { color: '#f1f5f9' }, ticks: { callback: v => v + '%' } },
                y: {
                    grid: { display: false },
                    ticks: { font: { size: 11 } },
                    afterFit: function(axis) {
                        if (yAxisLabelWidth !== null) {
                            axis.width = yAxisLabelWidth;
                        }
                    }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        title: function(items) { return fullLabels[items[0].dataIndex]; },
                        label: function(item) { return 'Score: ' + item.raw + '%'; }
                    }
                }
            }
        }
    });

    // Position the resize handle at the y-axis right edge
    function positionHandle() {
        const handle = document.getElementById('chartYResizeHandle');
        if (!handle || !lowestChartInstance) return;
        const chartArea = lowestChartInstance.chartArea;
        if (chartArea) {
            handle.style.left = (chartArea.left - 3) + 'px';
        }
    }
    setTimeout(positionHandle, 100);

    // Drag-to-resize y-axis labels
    const handle = document.getElementById('chartYResizeHandle');
    const wrapper = handle.parentElement;
    let startX, startWidth;

    handle.addEventListener('mousedown', function(e) {
        e.preventDefault();
        e.stopPropagation();
        const chartArea = lowestChartInstance.chartArea;
        startX = e.pageX;
        startWidth = chartArea.left;
        handle.classList.add('active');
        wrapper.classList.add('chart-resizing');

        function onMove(ev) {
            const delta = ev.pageX - startX;
            const newWidth = Math.max(60, Math.min(wrapper.offsetWidth - 80, startWidth + delta));
            yAxisLabelWidth = newWidth;
            lowestChartInstance.data.labels = truncateLabels(newWidth);
            lowestChartInstance.update('none');
            positionHandle();
        }
        function onUp() {
            handle.classList.remove('active');
            wrapper.classList.remove('chart-resizing');
            document.removeEventListener('mousemove', onMove);
            document.removeEventListener('mouseup', onUp);
        }
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
    });
})();

// Clickable rows
document.querySelectorAll('.clickable-row').forEach(row => {
    row.addEventListener('click', () => {
        window.location.href = row.dataset.href;
    });
});

// Resizable Table Columns
function makeResizable(table) {
    const thead = table.querySelector('thead tr');
    if (!thead) return;
    const cols = thead.querySelectorAll('th');
    cols.forEach(th => { th.style.width = th.offsetWidth + 'px'; });
    table.style.tableLayout = 'fixed';

    cols.forEach(th => {
        const handle = document.createElement('div');
        handle.className = 'resize-handle';
        th.appendChild(handle);

        let startX, startW;
        handle.addEventListener('mousedown', e => {
            e.preventDefault();
            e.stopPropagation();
            startX = e.pageX;
            startW = th.offsetWidth;
            handle.classList.add('active');
            table.classList.add('resizing');

            function onMove(ev) {
                const w = Math.max(40, startW + (ev.pageX - startX));
                th.style.width = w + 'px';
            }
            function onUp() {
                handle.classList.remove('active');
                table.classList.remove('resizing');
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
            }
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
        });
    });
}
document.querySelectorAll('.data-table').forEach(makeResizable);

// Filtering
function applyFilters() {
    const searchQ = document.getElementById('frameworkSearch').value.toLowerCase();
    const providerF = document.getElementById('filterProvider').value;
    const scoreF = document.getElementById('filterScore').value;
    const failedF = document.getElementById('filterFailed').value;
    let visible = 0;

    document.querySelectorAll('#frameworkTable tbody tr').forEach(row => {
        const text = row.textContent.toLowerCase();
        const provider = row.dataset.provider || '';
        const score = parseFloat(row.dataset.score) || 0;
        const failed = parseInt(row.dataset.failed) || 0;

        let show = true;
        if (searchQ && !text.includes(searchQ)) show = false;
        if (providerF && provider !== providerF) show = false;
        if (scoreF) {
            const [lo, hi] = scoreF.split('-').map(Number);
            if (score < lo || score > hi) show = false;
        }
        if (failedF) {
            if (failedF === '0' && failed !== 0) show = false;
            else if (failedF === '1-10' && (failed < 1 || failed > 10)) show = false;
            else if (failedF === '11-50' && (failed < 11 || failed > 50)) show = false;
            else if (failedF === '51-200' && (failed < 51 || failed > 200)) show = false;
            else if (failedF === '201+' && failed < 201) show = false;
        }

        row.style.display = show ? '' : 'none';
        if (show) visible++;
    });

    document.querySelector('.item-count').textContent = visible + ' Items';

    const container = document.getElementById('activeFilters');
    container.innerHTML = '';
    if (providerF) addTag(container, 'Provider: ' + providerF.toUpperCase(), 'filterProvider');
    if (scoreF) addTag(container, 'Score: ' + scoreF + '%', 'filterScore');
    if (failedF) addTag(container, 'Failed: ' + failedF, 'filterFailed');
}

function addTag(container, label, filterId) {
    const tag = document.createElement('span');
    tag.className = 'filter-tag';
    tag.innerHTML = label + ' <button onclick="clearFilter(\'' + filterId + '\')">&times;</button>';
    container.appendChild(tag);
}

function clearFilter(filterId) {
    document.getElementById(filterId).value = '';
    applyFilters();
}

document.getElementById('frameworkSearch').addEventListener('input', applyFilters);
document.getElementById('filterProvider').addEventListener('change', applyFilters);
document.getElementById('filterScore').addEventListener('change', applyFilters);
document.getElementById('filterFailed').addEventListener('change', applyFilters);

// ── Import / Export ──────────────────────────────────────────────
const importBtn = document.getElementById('importBtn');
const importFileInput = document.getElementById('importFileInput');
const importToast = document.getElementById('importToast');

function showToast(msg, isError) {
    importToast.textContent = msg;
    importToast.className = 'import-toast ' + (isError ? 'toast-error' : 'toast-success');
    importToast.style.display = 'block';
    clearTimeout(importToast._timer);
    importToast._timer = setTimeout(() => { importToast.style.display = 'none'; }, 5000);
}

importBtn.addEventListener('click', () => importFileInput.click());

importFileInput.addEventListener('change', async () => {
    const file = importFileInput.files[0];
    if (!file) return;
    importFileInput.value = '';

    importBtn.disabled = true;
    importBtn.textContent = 'Importing…';

    const form = new FormData();
    form.append('file', file);

    try {
        const res = await fetch('/import', { method: 'POST', body: form });
        // Guard against non-JSON responses (e.g. HTML 404/500 from server restart)
        const ct = res.headers.get('content-type') || '';
        if (!ct.includes('application/json')) {
            showToast('Import failed: server returned an unexpected response (HTTP ' + res.status + '). Try again.', true);
            return;
        }
        const json = await res.json();
        if (json.success) {
            showToast('Import successful (' + json.extracted + ' files). Reloading…', false);
            setTimeout(() => location.reload(), 1800);
        } else {
            showToast('Import failed: ' + (json.error || 'Unknown error'), true);
        }
    } catch (e) {
        showToast('Import failed: ' + e.message, true);
    } finally {
        importBtn.disabled = false;
        importBtn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg> Import';
    }
});
</script>
{% endblock %}
```

### 5.3 `detail.html` — Framework Detail Page

Key elements:
- Back link to dashboard (`/`)
- Framework name with large logo (38×38px)
- **Overview row** (CSS Grid: `1fr 1fr`):
  1. **Compliance Donut** — Chart.js full doughnut (220×220), pass=green / fail=gray, percentage centered. Next to it: "Requirements" count and "Sections" count with icons.
  2. **Summary Stats** — 3-column grid (Provider, Account ID, Total Checks) + row 2 has Passed (white bg, green left border, 28px font) and Failed (white bg, red left border, 28px font). Below: stacked horizontal bar chart (passed green + failed red).
- **Sections Table** (fixed layout: 30px / 35% / 25% / 12% / 12% / 12%):
  - Expandable rows — click to reveal nested requirements table
  - Chevron rotates 90° on expand
  - Each section shows: name, compliance posture bar, passed, failed, requirement count
  - **Nested requirements table** (resizable, columns: 50% / 8% / 12% / 8% / 8% / 14%): Title, Severity, Service Name, Passed, Failed, Score mini-bar
  - Each requirement row is clickable (`req-clickable-row`) — opens the detail panel
  - Row has `data-req-id`, `data-req-title`, `data-req-severity`, `data-req-status-ext`, `data-req-remediation`, `data-req-risk`, `data-req-urls`, `data-req-resources` (JSON array), `data-req-res-lookup` (JSON object) attributes
  - Severity shown as `<span class="severity-badge severity-<level>">` — classes: `severity-critical`, `severity-high`, `severity-medium`, `severity-low`, `severity-informational`, `severity-manual`
- **Requirement Detail Panel** (right slide-over, 500px wide, `req-detail-panel`):
  - `transform: translateX(100%)` when closed; `translateX(0)` when `.open`
  - Dark overlay (`req-panel-overlay`) behind panel
  - **Drag handle** (`req-panel-drag-handle`, 6px wide, left edge) — drag leftward to widen panel, min 350px, max viewport-40px
  - **Header**: `[req_id]` bracket in purple, title, severity badge (all on same line, flex-wrap)
  - **Body sections**: Description, Resources (table), Recommendation, Exposure Risk, Additional References
  - **Resources table**: columns Resource (name + resource_id as title tooltip), Region, Service, Status (`Pass`/`Fail` colored badges)
  - Service lookup uses `resLookup[check_id]` from `data-req-res-lookup`
  - **Markdown renderer** `md(text)`: escapes HTML, converts `**bold**` → `<strong>`, `` `code` `` → `<code>`, `\n` → `<br>`
  - Additional References: pipe-separated URLs rendered as `<a>` tags
  - Requirements tables made resizable via `MutationObserver` watching `.class` changes on `.table-section`

```html
{% extends "base.html" %}
{% block title %}{{ fw.name }} Compliance{% endblock %}

{% block content %}
<div class="detail-header">
    <a href="/" class="back-link">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5"/><path d="m12 19-7-7 7-7"/></svg>
        Back to Dashboard
    </a>
    <h1 class="page-title detail-title">
        {% if fw.logo_file %}
        <span class="fw-logo-lg {{ fw.logo_bg }}">
            <img src="{{ url_for('static', filename='logos/' + fw.logo_file) }}" alt="">
        </span>
        {% else %}
        <span class="fw-badge-lg" style="background:#7c3aed">{{ fw.provider[:3]|upper }}</span>
        {% endif %}
        {{ fw.name }}
    </h1>
</div>

<!-- Overview Row -->
<div class="detail-overview">
    <!-- Compliance Donut -->
    <div class="card detail-score-card">
        <div class="donut-wrapper">
            <canvas id="complianceDonut" width="220" height="220"></canvas>
            <div class="donut-center">
                <span class="donut-pct">{{ fw.score }}%</span>
                <span class="donut-label">Compliance</span>
            </div>
        </div>
        <div class="detail-stats">
            <div class="detail-stat">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                <div>
                    <div class="detail-stat-value">{{ fw.requirement_count }}</div>
                    <div class="detail-stat-label">Requirements</div>
                </div>
            </div>
            <div class="detail-stat">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <div>
                    <div class="detail-stat-value">{{ fw.sections|length }}</div>
                    <div class="detail-stat-label">Sections</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Summary Stats -->
    <div class="card detail-summary-card">
        <div class="detail-summary-grid">
            <div class="summary-item">
                <div class="summary-label">Provider</div>
                <div class="summary-value">{{ fw.provider|upper }}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Account ID</div>
                <div class="summary-value">{{ fw.account_id }}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Total Checks</div>
                <div class="summary-value">{{ "{:,}".format(fw.total) }}</div>
            </div>
            <div class="summary-item passed-bg">
                <div class="summary-label">Passed</div>
                <div class="summary-value text-green">{{ "{:,}".format(fw.passed) }}</div>
            </div>
            <div class="summary-item failed-bg">
                <div class="summary-label">Failed</div>
                <div class="summary-value text-red">{{ "{:,}".format(fw.failed) }}</div>
            </div>
        </div>
        <!-- Score bar chart -->
        <div class="score-breakdown-chart">
            <canvas id="scoreBreakdown" height="60"></canvas>
        </div>
    </div>
</div>

<!-- Sections Table -->
<div class="table-section">
    <h2 class="section-title">Compliance Sections</h2>
    <table class="data-table section-table">
        <thead>
            <tr>
                <th style="width: 30px"></th>
                <th>Section</th>
                <th>Compliance Posture</th>
                <th>Passed Checks</th>
                <th>Failed Checks</th>
                <th>Requirements</th>
            </tr>
        </thead>
        <tbody>
            {% for sec in fw.sections %}
            <tr class="section-row" data-section-idx="{{ loop.index }}">
                <td class="expand-icon">
                    <svg class="chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </td>
                <td class="sec-name">{{ sec.name }}</td>
                <td>
                    <div class="score-cell">
                        <div class="score-bar detail-bar">
                            <div class="score-bar-fill {% if sec.score >= 90 %}score-green{% elif sec.score >= 70 %}score-yellow{% elif sec.score >= 50 %}score-orange{% elif sec.score >= 20 %}score-red{% elif sec.score > 0 %}score-dark-red{% else %}gray{% endif %}" style="width: {{ sec.score }}%"></div>
                        </div>
                        <span class="score-pct">{{ sec.score }}%</span>
                    </div>
                </td>
                <td class="text-green">{{ "{:,}".format(sec.passed) }}</td>
                <td class="text-red">{{ "{:,}".format(sec.failed) }}</td>
                <td>{{ sec.requirement_count }}</td>
            </tr>
            <!-- Expandable requirements -->
            <tr class="requirements-row hidden" data-parent="{{ loop.index }}">
                <td colspan="6">
                    <div class="requirements-container">
                        <table class="requirements-table resizable-req-table">
                            <thead>
                                <tr>
                                    <th style="width:50%">Title</th>
                                    <th style="width:8%">Severity</th>
                                    <th style="width:12%">Service Name</th>
                                    <th style="width:8%">Passed</th>
                                    <th style="width:8%">Failed</th>
                                    <th style="width:14%">Score</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for req in sec.requirements %}
                                <tr class="req-clickable-row"
                                    data-req-id="{{ req.id }}"
                                    data-req-title="{{ req.check_title or req.description }}"
                                    data-req-severity="{{ req.severity }}"
                                    data-req-status-ext="{{ req.status_extended }}"
                                    data-req-remediation="{{ req.remediation_text }}"
                                    data-req-risk="{{ req.risk }}"
                                    data-req-urls="{{ req.additional_urls }}"
                                    data-req-resources='{{ req.resources | tojson }}'
                                    data-req-res-lookup='{{ req.resources_lookup | tojson }}'>
                                    <td class="req-title-cell">{{ req.check_title or req.description or req.id }}</td>
                                    <td>
                                        {% if req.severity %}
                                        <span class="severity-badge severity-{{ req.severity|lower }}">{{ req.severity }}</span>
                                        {% endif %}
                                    </td>
                                    <td class="req-service">{{ req.service_name }}</td>
                                    <td class="text-green req-count-lg">{{ req.passed }}</td>
                                    <td class="text-red req-count-lg">{{ req.failed }}</td>
                                    <td>
                                        <div class="score-cell">
                                            <div class="score-bar mini-bar">
                                                <div class="score-bar-fill {% if req.score >= 90 %}score-green{% elif req.score >= 70 %}score-yellow{% elif req.score >= 50 %}score-orange{% elif req.score >= 20 %}score-red{% elif req.score > 0 %}score-dark-red{% else %}gray{% endif %}" style="width: {{ req.score }}%"></div>
                                            </div>
                                            <span class="score-pct-sm">{{ req.score }}%</span>
                                        </div>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
<!-- Requirement Detail Panel -->
<div class="req-panel-overlay" id="reqPanelOverlay"></div>
<div class="req-detail-panel" id="reqDetailPanel">
    <div class="req-panel-drag-handle" id="reqPanelDragHandle"></div>
    <div class="req-panel-header">
        <div class="req-panel-title-row">
            <span class="req-panel-id-bracket">[<span id="reqPanelId"></span>]</span>
            <span class="req-panel-title" id="reqPanelTitle"></span>
            <span class="severity-badge" id="reqPanelSeverity"></span>
        </div>
        <button class="req-panel-close" id="reqPanelClose">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
        </button>
    </div>
    <div class="req-panel-body">
        <div class="req-panel-section">
            <h4>Description</h4>
            <div id="reqPanelDesc"></div>
        </div>
        <div class="req-panel-section" id="reqPanelResourcesSection" style="display:none">
            <h4>Resources</h4>
            <div id="reqPanelResources" class="req-panel-resources"></div>
        </div>
        <div class="req-panel-section">
            <h4>Recommendation</h4>
            <div id="reqPanelRemediation"></div>
        </div>
        <div class="req-panel-section">
            <h4>Exposure Risk</h4>
            <div id="reqPanelRisk"></div>
        </div>
        <div class="req-panel-section" id="reqPanelUrlsSection" style="display:none">
            <h4>Additional References</h4>
            <div id="reqPanelUrls"></div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
// Compliance donut
(function() {
    const ctx = document.getElementById('complianceDonut').getContext('2d');
    const score = {{ fw.score }};
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Passed', 'Failed'],
            datasets: [{
                data: [{{ fw.passed }}, {{ fw.failed }}],
                backgroundColor: ['#10b981', '#e2e8f0'],
                borderWidth: 0,
                cutout: '78%'
            }]
        },
        options: {
            responsive: false,
            plugins: { legend: { display: false }, tooltip: { enabled: true } }
        }
    });
})();

// Score breakdown stacked bar
(function() {
    const ctx = document.getElementById('scoreBreakdown').getContext('2d');
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [''],
            datasets: [
                { label: 'Passed', data: [{{ fw.passed }}], backgroundColor: '#10b981', barThickness: 30, borderRadius: 4 },
                { label: 'Failed', data: [{{ fw.failed }}], backgroundColor: '#ef4444', barThickness: 30, borderRadius: 4 }
            ]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { stacked: true, grid: { display: false }, ticks: { display: false } },
                y: { stacked: true, grid: { display: false }, ticks: { display: false } }
            },
            plugins: {
                legend: { position: 'bottom', labels: { boxWidth: 12, padding: 16, font: { size: 11 } } }
            }
        }
    });
})();

// Expandable section rows
document.querySelectorAll('.section-row').forEach(row => {
    row.addEventListener('click', () => {
        const idx = row.dataset.sectionIdx;
        const reqRow = document.querySelector(`.requirements-row[data-parent="${idx}"]`);
        const chevron = row.querySelector('.chevron');
        reqRow.classList.toggle('hidden');
        chevron.classList.toggle('rotated');
    });
});

// ===== Resizable Requirements Table Columns =====
function makeReqTableResizable(table) {
    const thead = table.querySelector('thead tr');
    if (!thead) return;
    const cols = thead.querySelectorAll('th');
    cols.forEach(th => { th.style.width = th.offsetWidth + 'px'; });
    table.style.tableLayout = 'fixed';

    cols.forEach(th => {
        const handle = document.createElement('div');
        handle.className = 'resize-handle';
        th.style.position = 'relative';
        th.appendChild(handle);

        let startX, startW;
        handle.addEventListener('mousedown', e => {
            e.preventDefault();
            e.stopPropagation();
            startX = e.pageX;
            startW = th.offsetWidth;
            handle.classList.add('active');
            table.classList.add('resizing');

            function onMove(ev) {
                const w = Math.max(40, startW + (ev.pageX - startX));
                th.style.width = w + 'px';
            }
            function onUp() {
                handle.classList.remove('active');
                table.classList.remove('resizing');
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
            }
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
        });
    });
}

// Observe for newly expanded requirement tables and make them resizable
const observer = new MutationObserver(() => {
    document.querySelectorAll('.resizable-req-table').forEach(table => {
        if (!table.dataset.resizable) {
            table.dataset.resizable = '1';
            requestAnimationFrame(() => makeReqTableResizable(table));
        }
    });
});
observer.observe(document.querySelector('.table-section'), { subtree: true, attributes: true, attributeFilter: ['class'] });

// ===== Requirement Detail Panel =====
(function() {
    const overlay = document.getElementById('reqPanelOverlay');
    const panel = document.getElementById('reqDetailPanel');
    const closeBtn = document.getElementById('reqPanelClose');
    const dragHandle = document.getElementById('reqPanelDragHandle');

    // Simple markdown-to-HTML: **bold**, `code`, newlines
    function md(text) {
        if (!text) return '';
        let h = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        h = h.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        h = h.replace(/`([^`]+)`/g, '<code>$1</code>');
        h = h.replace(/\n/g, '<br>');
        return h;
    }

    function openPanel(row) {
        const reqId = row.dataset.reqId || '';
        const title = row.dataset.reqTitle || '';
        const severity = row.dataset.reqSeverity || '';
        const statusExt = row.dataset.reqStatusExt || '';
        const remediation = row.dataset.reqRemediation || '';
        const risk = row.dataset.reqRisk || '';
        const urls = row.dataset.reqUrls || '';
        let resources = [];
        let resLookup = {};
        try { resources = JSON.parse(row.dataset.reqResources || '[]'); } catch(e) {}
        try { resLookup = JSON.parse(row.dataset.reqResLookup || '{}'); } catch(e) {}

        document.getElementById('reqPanelId').textContent = reqId;
        document.getElementById('reqPanelTitle').textContent = title;

        const sevBadge = document.getElementById('reqPanelSeverity');
        sevBadge.textContent = severity;
        sevBadge.className = 'severity-badge' + (severity ? ' severity-' + severity.toLowerCase() : '');
        sevBadge.style.display = severity ? '' : 'none';

        document.getElementById('reqPanelDesc').innerHTML = md(statusExt) || 'No description available.';
        document.getElementById('reqPanelRemediation').innerHTML = md(remediation) || 'No recommendation available.';
        document.getElementById('reqPanelRisk').innerHTML = md(risk) || 'No risk information available.';

        // Resources table
        const resSection = document.getElementById('reqPanelResourcesSection');
        const resContainer = document.getElementById('reqPanelResources');
        if (resources.length > 0) {
            resSection.style.display = '';
            resContainer.innerHTML = '<table class="req-resources-table"><thead><tr><th>Resource</th><th>Region</th><th>Service</th><th>Status</th></tr></thead><tbody>' +
                resources.map(r => {
                    const name = r.resource_name || r.resource_id;
                    const cls = r.status === 'PASS' ? 'res-pass' : 'res-fail';
                    const label = r.status === 'PASS' ? 'Pass' : 'Fail';
                    const region = (r.region || '').replace(/</g,'&lt;');
                    const svc = (resLookup[r.check_id] || '').replace(/</g,'&lt;');
                    return '<tr><td class="res-name" title="' + (r.resource_id || '').replace(/"/g,'&quot;') + '">' +
                        (name || '').replace(/</g,'&lt;') +
                        '</td><td class="res-region">' + region + '</td><td class="res-service">' + svc + '</td><td><span class="res-status ' + cls + '">' + label + '</span></td></tr>';
                }).join('') + '</tbody></table>';
        } else {
            resSection.style.display = 'none';
        }

        const urlsSection = document.getElementById('reqPanelUrlsSection');
        const urlsContainer = document.getElementById('reqPanelUrls');
        if (urls && urls.trim()) {
            urlsSection.style.display = '';
            const urlList = urls.split('|').map(u => u.trim()).filter(u => u);
            urlsContainer.innerHTML = urlList.map(u =>
                '<a href="' + u.replace(/"/g, '&quot;') + '" target="_blank" rel="noopener noreferrer">' +
                u.replace(/</g, '&lt;') + '</a>'
            ).join('<br>');
        } else {
            urlsSection.style.display = 'none';
        }

        overlay.classList.add('open');
        panel.classList.add('open');
    }

    function closePanel() {
        overlay.classList.remove('open');
        panel.classList.remove('open');
    }

    overlay.addEventListener('click', closePanel);
    closeBtn.addEventListener('click', closePanel);

    document.addEventListener('click', (e) => {
        const row = e.target.closest('.req-clickable-row');
        if (row) {
            e.stopPropagation();
            openPanel(row);
        }
    });

    // ===== Drag-to-resize panel =====
    let dragStartX, dragStartW;
    dragHandle.addEventListener('mousedown', function(e) {
        e.preventDefault();
        dragStartX = e.clientX;
        dragStartW = panel.offsetWidth;
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';

        function onMove(ev) {
            const delta = dragStartX - ev.clientX;
            const newW = Math.max(350, Math.min(window.innerWidth - 40, dragStartW + delta));
            panel.style.width = newW + 'px';
        }
        function onUp() {
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
            document.removeEventListener('mousemove', onMove);
            document.removeEventListener('mouseup', onUp);
        }
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
    });
})();
</script>
{% endblock %}
```

---

## 6. Stylesheet — `static/css/style.css`

### 6.1 Design System

| Token | Value | Usage |
|-------|-------|-------|
| `--sidebar-w` | `260px` | Sidebar width (collapses to `56px`) |
| `--bg` | `#f8fafc` | Page background (light gray-blue) |
| `--card-bg` | `#ffffff` | Card backgrounds |
| `--border` | `#e2e8f0` | All borders |
| `--text` | `#1e293b` | Primary text |
| `--text-muted` | `#64748b` | Secondary/label text |
| `--purple` | `#7c3aed` | Accent color |
| `--purple-light` | `#ede9fe` | Hover backgrounds |
| `--green` | `#10b981` | Passed / success |
| `--red` | `#ef4444` | Failed / error |
| `--radius` | `10px` | Card border radius |

### 6.2 Five-Tier Score Color Scheme

| Range | Color | CSS Class | Hex |
|-------|-------|-----------|-----|
| ≥ 90% | Green | `score-green` | `#10b981` |
| ≥ 70% | Yellow | `score-yellow` | `#ca8a04` |
| ≥ 50% | Orange | `score-orange` | `#f97316` |
| ≥ 20% | Red | `score-red` | `#ef4444` |
| < 20% | Dark Red | `score-dark-red` | `#991b1b` |

### 6.3 Key CSS Behaviors

1. **Sidebar collapse**: `.sidebar.collapsed` → width 56px. `.sidebar.collapsed .brand-logo-full` hidden, `.brand-logo-icon` shown. All text spans hidden in collapsed state.
2. **Sidebar brand link**: `.sidebar-brand-link` wraps logos and title in an `<a>` tag with `display:flex; flex-direction:column; text-decoration:none; color:inherit` so the whole brand area links to `/`.
3. **Content margin**: `.content` has `margin-left: var(--sidebar-w)`. `body.sidebar-collapsed .content` has `margin-left: 56px`.
4. **Page title row**: `.page-title-row` is `display:flex; justify-content:space-between` to place import/export buttons on the right side of the page title. `.page-title` has `margin-bottom:0` when inside this row.
5. **Import/Export buttons**: `.io-btn` — inline-flex, border, subtle hover that turns purple. Used for both `<button>` (import) and `<a>` (export). `.io-btn:disabled` has `opacity:0.55`.
6. **Import toast**: `.import-toast` is `position:fixed; top:20px; right:24px; z-index:9999`. `.toast-success` is green `#10b981`. `.toast-error` is red `#ef4444`.
7. **Stat value colors**: `.stat-value.passed { color: #10b981; }` (green), `.stat-value.failed { color: #ef4444; }` (red). These replace the previous `color: var(--text)` for both classes.
8. **Settings panel**: Fixed position, slides from right (`right: -420px` → `right: 0`). Dark overlay behind.
9. **Resizable columns**: `.resize-handle` is `position: absolute; right: 0; width: 5px; cursor: col-resize`. Purple highlight on hover/active.
10. **Chart y-axis resize**: `.chart-y-resize-handle` positioned absolute at chart area left edge. Drag updates `yAxisLabelWidth` and re-truncates labels.
11. **Section table**: `table-layout: fixed` with explicit column widths to prevent overflow.
12. **Passed/Failed boxes**: `.passed-bg` and `.failed-bg` have `background: var(--card-bg) !important; border-left: 4px solid` color. Font size 28px for the values.
13. **Severity badges**: `.severity-badge` with 6 modifier classes — `critical` (#991b1b), `high` (#ef4444), `medium` (#f97316), `low` (#ca8a04 with `color:#000`), `informational` (#3b82f6), `manual` (#6b7280).
14. **Requirement row enhancements**: `.req-clickable-row` (`cursor:pointer`, hover `#eef2ff`), `.req-title-cell` (bold), `.req-service` (muted), `.req-count-lg` (20px 800-weight numbers in passed/failed columns).
15. **Resizable requirements table**: `.resizable-req-table` — `table-layout:auto` with drag handles on `th` elements.
16. **Requirement detail panel**: `.req-detail-panel` — `position:fixed; right:0; width:500px; height:100vh; transform:translateX(100%); transition:transform .3s ease`. `.req-detail-panel.open { transform:translateX(0) }`. Panel is behind `.req-panel-overlay` (dim background) and z-index 201.
17. **Panel drag handle**: `.req-panel-drag-handle` — `position:absolute; left:0; top:0; bottom:0; width:6px; cursor:col-resize`. JS listens for mousedown to resize panel width (min 350px, max viewport-40px).
18. **Panel ID bracket**: `.req-panel-id-bracket` — purple, 15px, 700-weight text for the `[req_id]` display.
19. **Resources table in panel**: `.req-resources-table` — compact 13px table. Status cells use `.res-pass` (green bg) or `.res-fail` (red bg) badges.
20. **Responsive**: At ≤1100px: stats-row and detail-overview go single column. At ≤768px: sidebar hidden, no margin.

### 6.4 Full CSS Source

```css
/* ===== Reset & Base ===== */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
    --sidebar-w: 260px;
    --bg: #f8fafc;
    --card-bg: #ffffff;
    --border: #e2e8f0;
    --text: #1e293b;
    --text-muted: #64748b;
    --purple: #7c3aed;
    --purple-light: #ede9fe;
    --green: #10b981;
    --green-light: #d1fae5;
    --red: #ef4444;
    --red-light: #fee2e2;
    --yellow: #f59e0b;
    --yellow-light: #fef3c7;
    /* 5-tier score colors */
    --score-dark-red: #991b1b;
    --score-red: #ef4444;
    --score-orange: #f97316;
    --score-yellow: #ca8a04;
    --score-green: #10b981;
    --radius: 10px;
    --shadow: 0 1px 3px rgba(0,0,0,.06), 0 1px 2px rgba(0,0,0,.04);
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    display: flex;
    min-height: 100vh;
    line-height: 1.5;
}

/* ===== Sidebar ===== */
.sidebar {
    width: var(--sidebar-w);
    background: var(--card-bg);
    border-right: 1px solid var(--border);
    padding: 20px 0;
    position: fixed;
    top: 0;
    left: 0;
    bottom: 0;
    z-index: 100;
    display: flex;
    flex-direction: column;
    transition: width .25s ease, padding .25s ease;
    overflow: hidden;
}

.sidebar.collapsed {
    width: 56px;
}

.sidebar-brand {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 6px;
    padding: 16px 16px 16px;
    border-bottom: 1px solid var(--border);
    overflow: hidden;
}
.sidebar-brand-link {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 6px;
    text-decoration: none;
    color: inherit;
}

.brand-logo {
    object-fit: contain;
    flex-shrink: 0;
    border-radius: 6px;
}

.brand-logo-full {
    height: 126px;
    margin-left: -0.5cm;
}

.brand-logo-icon {
    display: none;
    height: 36px;
    width: 36px;
    margin-left: 0;
}

.sidebar.collapsed .brand-logo-full {
    display: none;
}

.sidebar.collapsed .brand-logo-icon {
    display: block;
}

.brand-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
}

.brand-name {
    font-size: 18px;
    font-weight: 800;
    color: var(--text);
    line-height: 1.2;
    letter-spacing: 1px;
}

.brand-title {
    font-size: 30px;
    font-weight: 500;
    color: var(--text);
    line-height: 1.3;
    text-align: left;
    white-space: nowrap;
    margin-top: -30px;
}

.sidebar.collapsed .brand-text,
.sidebar.collapsed .brand-title {
    display: none;
}

.sidebar.collapsed .sidebar-brand {
    padding: 10px 8px 12px;
    align-items: center;
}

/* Region checkbox group */
.region-checkbox-group {
    max-height: 240px;
    overflow-y: auto;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 12px;
    background: var(--bg);
    display: flex;
    flex-direction: column;
    gap: 2px;
}

.region-cb {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: var(--text);
    padding: 4px 6px;
    border-radius: 4px;
    cursor: pointer;
    text-transform: none;
    font-weight: 400;
    letter-spacing: 0;
}

.region-cb:hover {
    background: var(--purple-light);
}

.region-cb input[type="checkbox"] {
    accent-color: var(--purple);
    width: 16px;
    height: 16px;
    cursor: pointer;
}

.sidebar-toggle {
    display: none;
}

.sidebar-nav {
    list-style: none;
    padding: 12px 10px;
    flex: 1;
}

.sidebar-nav li a {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    border-radius: 8px;
    text-decoration: none;
    color: var(--text-muted);
    font-size: 14px;
    font-weight: 500;
    transition: all .15s;
    white-space: nowrap;
    overflow: hidden;
}

.sidebar.collapsed .sidebar-nav li a span {
    display: none;
}

.sidebar.collapsed .sidebar-nav li a {
    justify-content: center;
    padding: 10px 8px;
}

.sidebar-nav li a:hover,
.sidebar-nav li a.active {
    background: var(--purple-light);
    color: var(--purple);
}

/* Sidebar bottom settings */
.sidebar-bottom {
    padding: 10px;
    border-top: 1px solid var(--border);
}

.settings-btn {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    border-radius: 8px;
    cursor: pointer;
    color: var(--text-muted);
    font-size: 14px;
    font-weight: 500;
    transition: all .15s;
    white-space: nowrap;
    overflow: hidden;
    background: none;
    border: none;
    width: 100%;
    text-align: left;
}

.settings-btn:hover {
    background: var(--purple-light);
    color: var(--purple);
}

.settings-btn img {
    width: 20px;
    height: 20px;
    object-fit: contain;
    flex-shrink: 0;
}

.sidebar.collapsed .settings-btn span {
    display: none;
}

.sidebar.collapsed .settings-btn {
    justify-content: center;
    padding: 10px 8px;
}

/* Settings Panel (slide-over) */
.settings-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.3);
    z-index: 200;
}

.settings-overlay.open {
    display: block;
}

.settings-panel {
    position: fixed;
    top: 0;
    right: -420px;
    width: 400px;
    height: 100vh;
    background: var(--card-bg);
    box-shadow: -4px 0 20px rgba(0,0,0,.1);
    z-index: 201;
    display: flex;
    flex-direction: column;
    transition: right .3s ease;
    overflow-y: auto;
}

.settings-panel.open {
    right: 0;
}

.settings-panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 24px;
    border-bottom: 1px solid var(--border);
}

.settings-panel-header h2 {
    font-size: 18px;
    font-weight: 700;
}

.settings-close {
    background: none;
    border: none;
    cursor: pointer;
    color: var(--text-muted);
    padding: 4px;
    border-radius: 6px;
}

.settings-close:hover {
    background: var(--bg);
    color: var(--text);
}

.settings-panel-body {
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.settings-section {
    display: flex;
    flex-direction: column;
    gap: 6px;
}

.settings-section label {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: .3px;
}

.settings-section input,
.settings-section select {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 14px;
    color: var(--text);
    background: var(--bg);
    outline: none;
    width: 100%;
}

.settings-section input:focus,
.settings-section select:focus {
    border-color: var(--purple);
    box-shadow: 0 0 0 3px rgba(124,58,237,.1);
}

.settings-section input[type="password"] {
    font-family: monospace;
    letter-spacing: 1px;
}

.settings-section .hint {
    font-size: 11px;
    color: var(--text-muted);
}

.settings-actions {
    padding: 16px 24px;
    border-top: 1px solid var(--border);
    display: flex;
    gap: 10px;
}

.btn-primary {
    background: var(--purple);
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 10px 24px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: background .15s;
}

.btn-primary:hover {
    background: #6d28d9;
}

.btn-secondary {
    background: var(--bg);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 24px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: background .15s;
}

.btn-secondary:hover {
    background: #e2e8f0;
}

.region-select {
    max-height: 200px;
}

/* ===== Content ===== */
.content {
    margin-left: var(--sidebar-w);
    padding: 28px 32px;
    flex: 1;
    min-width: 0;
    transition: margin-left .25s ease;
}

body.sidebar-collapsed .content {
    margin-left: 56px;
}

.page-title-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 20px;
}

.page-title {
    font-size: 24px;
    font-weight: 700;
    margin-bottom: 0;
    color: var(--text);
}

.page-actions {
    display: flex;
    gap: 8px;
    align-items: center;
}

.io-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 7px 16px;
    border-radius: 7px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    border: 1px solid var(--border);
    background: var(--card-bg);
    color: var(--text);
    text-decoration: none;
    transition: background .15s, border-color .15s;
    white-space: nowrap;
}

.io-btn:hover:not(:disabled) {
    background: var(--bg);
    border-color: var(--purple);
    color: var(--purple);
}

.io-btn:disabled {
    opacity: 0.55;
    cursor: not-allowed;
}

/* Import toast */
.import-toast {
    position: fixed;
    top: 20px;
    right: 24px;
    z-index: 9999;
    padding: 12px 20px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    box-shadow: 0 4px 16px rgba(0,0,0,.2);
    max-width: 380px;
}

.toast-success {
    background: #10b981;
    color: #fff;
}

.toast-error {
    background: #ef4444;
    color: #fff;
}

/* ===== Cards ===== */
.card {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px 22px;
    box-shadow: var(--shadow);
}

.card-header {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-muted);
    margin-bottom: 12px;
    text-transform: uppercase;
    letter-spacing: .3px;
}

.info-icon {
    cursor: help;
    font-size: 14px;
    color: var(--text-muted);
}

/* ===== Stats Row ===== */
.stats-row {
    display: grid;
    grid-template-columns: 220px 180px 1fr;
    grid-template-rows: auto;
    align-items: stretch;
    gap: 16px;
    margin-bottom: 28px;
}

.stat-stack {
    display: flex;
    flex-direction: column;
    gap: 16px;
}

.gauge-card {
    display: flex;
    flex-direction: column;
    align-items: center;
}

.gauge-wrapper {
    position: relative;
    width: 200px;
    height: 120px;
    display: flex;
    align-items: flex-end;
    justify-content: center;
}

.gauge-value {
    position: absolute;
    bottom: 0;
    font-size: 28px;
    font-weight: 800;
    color: var(--text);
}

.stat-card {
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
}

.stat-value {
    font-size: 32px;
    font-weight: 800;
}

.stat-value.passed { color: #10b981; }
.stat-value.failed { color: #ef4444; }

.wide-card {
    min-width: 0;
}

.chart-card {
    min-height: 180px;
}

/* ===== Table Section ===== */
.table-section {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 24px;
    box-shadow: var(--shadow);
    overflow-x: auto;
}

.table-header-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
}

.section-title {
    font-size: 17px;
    font-weight: 700;
}

.item-count {
    font-size: 13px;
    color: var(--text-muted);
}

.table-controls {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 14px;
}

.filter-group {
    display: inline-flex;
    align-items: center;
    gap: 6px;
}

.filter-group label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: .3px;
}

.filter-select {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 6px 10px;
    font-size: 13px;
    color: var(--text);
    background: var(--bg);
    outline: none;
    cursor: pointer;
}

.filter-select:focus {
    border-color: var(--purple);
}

.active-filters {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 10px;
}

.filter-tag {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 10px;
    background: var(--purple-light);
    color: var(--purple);
    border-radius: 16px;
    font-size: 12px;
    font-weight: 600;
}

.filter-tag button {
    background: none;
    border: none;
    color: var(--purple);
    cursor: pointer;
    font-size: 14px;
    line-height: 1;
    padding: 0 2px;
}

.search-box {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 6px 12px;
    background: var(--bg);
}

.search-box input {
    border: none;
    outline: none;
    background: transparent;
    font-size: 13px;
    color: var(--text);
    width: 220px;
}

/* ===== Data Table ===== */
.data-table {
    width: 100%;
    border-collapse: collapse;
    table-layout: auto;
}

.section-table {
    table-layout: fixed;
}

.section-table th:nth-child(1) { width: 30px; }
.section-table th:nth-child(2) { width: 35%; }
.section-table th:nth-child(3) { width: 25%; }
.section-table th:nth-child(4) { width: 12%; }
.section-table th:nth-child(5) { width: 12%; }
.section-table th:nth-child(6) { width: 12%; }

.data-table th {
    text-align: left;
    padding: 10px 12px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: .3px;
    border-bottom: 2px solid var(--border);
    white-space: nowrap;
    position: relative;
    overflow: hidden;
}

/* Resizable column handle */
.data-table th .resize-handle {
    position: absolute;
    right: 0;
    top: 0;
    bottom: 0;
    width: 5px;
    cursor: col-resize;
    background: transparent;
    z-index: 1;
}

.data-table th .resize-handle:hover,
.data-table th .resize-handle.active {
    background: var(--purple);
    opacity: 0.4;
}

.data-table.resizing {
    cursor: col-resize;
    user-select: none;
}

/* Chart y-axis resize handle */
.chart-resizable-wrapper {
    overflow: hidden;
}
.chart-y-resize-handle {
    position: absolute;
    top: 0;
    bottom: 0;
    width: 6px;
    left: 0;
    cursor: col-resize;
    background: transparent;
    z-index: 5;
    transition: background .15s;
}
.chart-y-resize-handle:hover,
.chart-y-resize-handle.active {
    background: var(--purple);
    opacity: 0.4;
    border-radius: 2px;
}
.chart-resizing {
    cursor: col-resize;
    user-select: none;
}

.data-table td {
    padding: 12px;
    font-size: 13px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
    overflow: hidden;
    text-overflow: ellipsis;
}

.data-table tbody tr:hover {
    background: #f1f5f9;
}

.clickable-row {
    cursor: pointer;
    transition: background .1s;
}

.fw-name {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 600;
    white-space: nowrap;
}

.fw-badge, .fw-badge-lg {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: 6px;
    font-size: 9px;
    font-weight: 800;
    color: #fff;
    letter-spacing: .5px;
    flex-shrink: 0;
}

.fw-badge-lg {
    width: 36px;
    height: 36px;
    font-size: 11px;
    border-radius: 8px;
}

/* Logo badges */
.fw-logo {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    border-radius: 6px;
    flex-shrink: 0;
    overflow: hidden;
    padding: 3px;
}

.fw-logo img {
    max-width: 100%;
    max-height: 100%;
    object-fit: contain;
}

.logo-bg-dark {
    background: #1a1a2e;
}

.logo-bg-white {
    background: #ffffff;
    border: 1px solid var(--border);
}

.fw-logo-lg {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 38px;
    height: 38px;
    border-radius: 8px;
    flex-shrink: 0;
    overflow: hidden;
    padding: 4px;
}

.fw-logo-lg img {
    max-width: 100%;
    max-height: 100%;
    object-fit: contain;
}

.fw-logo-lg.logo-bg-dark {
    background: #1a1a2e;
}

.fw-logo-lg.logo-bg-white {
    background: #ffffff;
    border: 1px solid var(--border);
}

.fw-desc {
    color: var(--text-muted);
    max-width: 260px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.failed-link {
    color: var(--red);
    font-weight: 600;
    text-decoration: underline;
}

/* ===== Score Bars ===== */
.score-cell {
    display: flex;
    align-items: center;
    gap: 10px;
}

.score-pct {
    font-weight: 700;
    font-size: 13px;
    min-width: 52px;
}

.score-bar {
    flex: 1;
    height: 10px;
    background: #e2e8f0;
    border-radius: 5px;
    min-width: 60px;
    overflow: hidden;
}

.detail-bar {
    min-width: 80px;
}

.mini-bar {
    min-width: 60px;
    height: 6px;
}

.score-bar-fill {
    height: 100%;
    border-radius: 5px;
    transition: width .4s ease;
}

.score-bar-fill.score-dark-red { background: var(--score-dark-red); }
.score-bar-fill.score-red { background: var(--score-red); }
.score-bar-fill.score-orange { background: var(--score-orange); }
.score-bar-fill.score-yellow { background: var(--score-yellow); }
.score-bar-fill.score-green { background: var(--score-green); }
.score-bar-fill.green { background: var(--score-green); }
.score-bar-fill.yellow { background: var(--score-yellow); }
.score-bar-fill.red { background: var(--score-red); }
.score-bar-fill.gray { background: #cbd5e1; }

.score-pct-sm {
    font-weight: 600;
    font-size: 12px;
    min-width: 42px;
}

/* ===== Detail Page ===== */
.detail-header {
    margin-bottom: 20px;
}

.back-link {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--purple);
    text-decoration: none;
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 12px;
}

.back-link:hover { text-decoration: underline; }

.detail-title {
    display: flex;
    align-items: center;
    gap: 12px;
}

.detail-overview {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 28px;
}

.detail-score-card {
    display: flex;
    align-items: center;
    gap: 28px;
}

.donut-wrapper {
    position: relative;
    width: 220px;
    height: 220px;
    flex-shrink: 0;
}

.donut-center {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
}

.donut-pct {
    display: block;
    font-size: 36px;
    font-weight: 800;
    color: var(--text);
    line-height: 1.1;
}

.donut-label {
    display: block;
    font-size: 13px;
    color: var(--text-muted);
    font-weight: 500;
}

.detail-stats {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.detail-stat {
    display: flex;
    align-items: center;
    gap: 12px;
}

.detail-stat-value {
    font-size: 22px;
    font-weight: 800;
}

.detail-stat-label {
    font-size: 13px;
    color: var(--text-muted);
}

.detail-summary-card {
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}

.detail-summary-grid {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 12px;
    margin-bottom: 16px;
}

.summary-item {
    padding: 10px 14px;
    background: var(--bg);
    border-radius: 8px;
}

.summary-label {
    font-size: 11px;
    color: var(--text-muted);
    text-transform: uppercase;
    font-weight: 600;
    letter-spacing: .3px;
    margin-bottom: 4px;
}

.summary-value {
    font-size: 15px;
    font-weight: 700;
}

.passed-bg {
    background: var(--card-bg) !important;
    border-left: 4px solid var(--green);
}
.failed-bg {
    background: var(--card-bg) !important;
    border-left: 4px solid var(--red);
}
.text-green { color: var(--green); }
.text-red { color: var(--red); }

.summary-item.passed-bg .summary-value,
.summary-item.failed-bg .summary-value {
    font-size: 28px;
    font-weight: 800;
}

.score-breakdown-chart {
    height: 60px;
}

/* ===== Expandable Sections ===== */
.section-row {
    cursor: pointer;
    transition: background .1s;
}

.section-row:hover {
    background: #f1f5f9;
}

.expand-icon {
    width: 30px;
    text-align: center;
}

.chevron {
    transition: transform .2s;
}

.chevron.rotated {
    transform: rotate(90deg);
}

.sec-name {
    font-weight: 600;
}

.requirements-row {
    background: #fafbfd;
}

.requirements-row.hidden {
    display: none;
}

.requirements-container {
    padding: 8px 16px 12px 40px;
}

.requirements-table {
    width: 100%;
    border-collapse: collapse;
}

.requirements-table th {
    text-align: left;
    padding: 6px 10px;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    border-bottom: 1px solid var(--border);
}

.requirements-table td {
    padding: 8px 10px;
    font-size: 12px;
    border-bottom: 1px solid #f1f5f9;
}

.req-id {
    font-weight: 700;
    color: var(--purple);
    white-space: nowrap;
}

.req-desc {
    color: var(--text-muted);
    max-width: 400px;
}

/* ===== Severity Badges ===== */
.severity-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 500;
    text-transform: capitalize;
    white-space: nowrap;
    letter-spacing: .3px;
}
.severity-informational { background: #3b82f6; color: #fff; }
.severity-critical { background: #991b1b; color: #fff; }
.severity-high { background: #ef4444; color: #fff; }
.severity-medium { background: #f97316; color: #fff; }
.severity-low { background: #ca8a04; color: #000; }
.severity-manual { background: #6b7280; color: #fff; }

/* ===== Requirement Table Enhancements ===== */
.req-clickable-row {
    cursor: pointer;
    transition: background .1s;
}
.req-clickable-row:hover {
    background: #eef2ff;
}
.req-title-cell {
    font-weight: 600;
    font-size: 12px;
    color: var(--text);
}
.req-service {
    font-size: 12px;
    color: var(--text-muted);
}
.req-count-lg {
    font-size: 20px;
    font-weight: 800;
}

/* Resizable requirements table */
.resizable-req-table {
    table-layout: auto;
}
.resizable-req-table.resizing {
    cursor: col-resize;
    user-select: none;
}
.resizable-req-table th {
    position: relative;
    overflow: hidden;
}
.resizable-req-table th .resize-handle {
    position: absolute;
    right: 0;
    top: 0;
    bottom: 0;
    width: 5px;
    cursor: col-resize;
    background: transparent;
    z-index: 1;
}
.resizable-req-table th .resize-handle:hover,
.resizable-req-table th .resize-handle.active {
    background: var(--purple);
    opacity: 0.4;
}

/* ===== Requirement Detail Panel ===== */
.req-panel-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.3);
    z-index: 200;
}
.req-panel-overlay.open {
    display: block;
}
.req-detail-panel {
    position: fixed;
    top: 0;
    right: 0;
    width: 500px;
    height: 100vh;
    background: var(--card-bg);
    box-shadow: -4px 0 20px rgba(0,0,0,.1);
    z-index: 201;
    display: flex;
    flex-direction: column;
    transition: transform .3s ease;
    overflow-y: auto;
    transform: translateX(100%);
}
.req-detail-panel.open {
    transform: translateX(0);
}
.req-panel-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    padding: 20px 24px;
    border-bottom: 1px solid var(--border);
    gap: 12px;
}
.req-panel-title-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    flex: 1;
    min-width: 0;
}
.req-panel-id-bracket {
    font-size: 15px;
    font-weight: 700;
    color: var(--purple);
    white-space: nowrap;
    flex-shrink: 0;
}
.req-panel-title {
    font-size: 15px;
    font-weight: 600;
    color: var(--text);
    word-break: break-word;
}
.req-panel-close {
    background: none;
    border: none;
    cursor: pointer;
    color: var(--text-muted);
    padding: 4px;
    border-radius: 6px;
    flex-shrink: 0;
}
.req-panel-close:hover {
    background: var(--bg);
    color: var(--text);
}
.req-panel-body {
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
}
.req-panel-section h4 {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: .3px;
    margin-bottom: 8px;
}
.req-panel-section p,
.req-panel-section div {
    font-size: 14px;
    color: var(--text);
    line-height: 1.6;
}
/* Panel markdown rendering */
.req-panel-section code {
    background: #f1f5f9;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 13px;
    color: #c026d3;
}

/* Resources table in panel */
.req-resources-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    margin-top: 4px;
}
.req-resources-table th {
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
}
.req-resources-table td {
    padding: 5px 8px;
    border-bottom: 1px solid #f1f5f9;
}
.res-name {
    color: var(--text);
    word-break: break-all;
    max-width: 320px;
}
.res-region {
    color: var(--text-muted);
    font-size: 12px;
    white-space: nowrap;
}
.res-service {
    color: var(--text);
    font-size: 12px;
    white-space: nowrap;
}
.res-status {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
}
.res-pass {
    background: #d1fae5;
    color: #065f46;
}
.res-fail {
    background: #fee2e2;
    color: #991b1b;
}

/* Panel drag handle */
.req-panel-drag-handle {
    position: absolute;
    left: 0;
    top: 0;
    bottom: 0;
    width: 6px;
    cursor: col-resize;
    z-index: 2;
    background: transparent;
    transition: background .15s;
}
.req-panel-drag-handle:hover {
    background: var(--purple);
    opacity: 0.3;
}
.req-panel-section a {
    color: var(--purple);
    text-decoration: none;
    font-size: 13px;
    word-break: break-all;
}
.req-panel-section a:hover {
    text-decoration: underline;
}

/* ===== Responsive ===== */
@media (max-width: 1100px) {
    .stats-row {
        grid-template-columns: 1fr;
    }
    .detail-overview {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 768px) {
    .sidebar { display: none; }
    .content { margin-left: 0; padding: 16px; }
    .stats-row { grid-template-columns: 1fr; }
}

```

---

## 7. Logo Mapping Rules

The `LOGO_MAP` in `app.py` maps framework slug substrings to logo files:

| Slug contains | Logo file | Background |
|---------------|-----------|------------|
| `aws_account_security`, `aws_audit_manager`, `aws_foundational`, `aws_well_architected` | `aws.png` | Dark (`#1a1a2e`) |
| `cis_` | `CIS.jpg` | White + border |
| `mitre_` | `MITRE.png` | White + border |
| `nist_` | `NIST.png` | White + border |
| `iso27001` | `ISO.png` | White + border |
| `hipaa` | `HIPAA.png` | White + border |
| `gdpr` | `GDPR.png` | White + border |
| `pci_` | `pci.webp` | White + border |
| `soc2` | `SOC2.png` | White + border |
| `fedramp` | `FedRAMP.jpg` | White + border |
| `csa_ccm`, `ccc_` | `CCM.png` | White + border |

Frameworks not matching any keyword show a **purple badge** with first 3 letters of the provider name.

---

## 8. How to Run

```bash
# Install dependencies
pip install flask

# Run the app
cd compliance-dashboard
python app.py
# Opens at http://localhost:5000

# For production: use gunicorn + nginx with SSL
pip install gunicorn
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

Required: **Flask 3.0+**, **Python 3.10+**

**nginx note (required for ZIP import feature):** Add `client_max_body_size 500m;` inside the `server` block of your nginx site config. Without this, large ZIP uploads return HTTP 413 before Flask even receives the request. Flask itself also has `app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024` set; both limits must be raised.

---

## 9. Setup Instructions for GenAI

1. **Copy logo files** from `images_logo/` into `static/logos/` (exclude the two screenshot PNGs).
2. **Create the 5 files**: `app.py`, `templates/base.html`, `templates/dashboard.html`, `templates/detail.html`, `static/css/style.css` — all source code is provided verbatim above.
3. **Create `service_names.csv`** in the `compliance-dashboard/` directory using the content provided in section 2.5. This maps raw Prowler `SERVICE_NAME` values to human-readable display names.
4. **Point `COMPLIANCE_DIR`** to where your Prowler compliance CSVs live (semicolon-delimited). Verify `PROWLER_OUTPUT_DIR` points to the parent `prowler/output/` folder (one level up from `compliance/`) so the main `prowler-output-*.csv` can be found.
5. **Run** `python app.py`.
6. **For production nginx**: add `client_max_body_size 500m;` to your nginx server block (see Section 8 for details).
7. **Match the screenshots**: Compare your output against `images_logo/main_dashboard.png` and `images_logo/detailed_compliance_CIS_AWSv3.png`.

---

## 10. Key Design Decisions to Preserve

- **Light theme only** — `#f8fafc` background, white cards.
- **Purple accent** (`#7c3aed`) for active states, links, and highlights.
- **Sidebar click-to-toggle** — no visible toggle button; clicking empty sidebar areas collapses/expands.
- **5-tier score colors** — consistent across gauge, chart bars, table bars, and detail page.
- **Resizable table columns** — drag handles on every column header.
- **Chart y-axis drag resize** — handle positioned at chart area left edge.
- **Passed/Failed detail boxes** — white background with colored left border (green for passed, red for failed), large 28px numbers.
- **Framework logos** — AWS-branded frameworks get dark background (`#1a1a2e`); all others get white background with subtle border.
- **Company branding** — `gapv.webp` shown full-size when sidebar is open (126px tall), `icon_gapv.webp` (36×36) when collapsed. Title text "Cloud Guard" (two words). The entire brand area (`sidebar-brand-link`) is an `<a href="/">` link.
- **Favicon** — `static/logos/icon_gapv.webp` linked in `<head>` via `<link rel="icon" type="image/webp">`.
- **Colored stat numbers** — Passed count is green (`#10b981`), Failed count is red (`#ef4444`) in the dashboard stat cards.
- **Import/Export ZIP** — Dashboard has an Import button (triggers `POST /import` with ZIP validation, folder-prefix stripping, path-traversal protection) and an Export link (`GET /export` streams a ZIP). Both at top-right of page title row via `.page-title-row` / `.io-btn`. nginx must have `client_max_body_size 500m` and Flask must have `MAX_CONTENT_LENGTH = 500MB`.
- **Service name display mapping** — `service_names.csv` maps raw Prowler `SERVICE_NAME` values to display names. Loaded at startup into `SERVICE_NAME_MAP`. Used in requirement detail panel and requirements table.
- **Severity badges** — 6 levels with distinct background colors (critical=dark red, high=red, medium=orange, low=amber with black text, informational=blue, manual=gray). "Manual" severity is assigned when all check_ids for a requirement have no real findings (all-manual checks).
- **Requirement detail panel** — Right-side slide-over panel, 500px default width, draggable to resize (min 350px, max viewport-40px). Shows `[req_id]` bracket + severity badge in header, then Description / Risk / Remediation / Resources sections. `transform: translateX(100%)` → `translateX(0)` transition.
- **Resources table** — Lists individual resources found for a requirement (Resource name, Region, Service display name, PASS/FAIL status badge). Populated from the main `prowler-output-*.csv` via `_parse_main_prowler_csv()`.
- **Markdown renderer** — `md()` JS function in `detail.html` converts bold (`**text**`), inline code (`` `code` ``), and URLs to HTML for the description/risk/remediation fields.
- **Settings panel** — slide-over from right with AWS credentials + multi-select region checkboxes (UI only, scan not implemented).
