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
# Each entry: (logo_filename, bg_css_class)
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
        # Extract a slug from the filename for URL routing
        # e.g. prowler-output-..._cis_3.0_aws.csv -> cis_3.0_aws
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

    # Build requirement-level detail
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

    # Enrich with main prowler CSV data
    main_lookup = _parse_main_prowler_csv()

    section_list = []
    for sec_name in sorted(sections.keys()):
        s = sections[sec_name]
        sec_score = round((s["passed"] / s["total"]) * 100, 2) if s["total"] else 0
        # Get requirements for this section
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
                    "resources_lookup": {cid: SERVICE_NAME_MAP.get(main_lookup[cid]["service_name"], main_lookup[cid]["service_name"].replace("_", " ").title()) for cid in req_data["check_ids"] if cid in main_lookup},
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
    # Use the first (or only) main output file
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

    # Sort by score ascending for "lowest scoring" chart
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
            # so users can zip the folder itself and still have it work.
            prefix = ""
            top_level = {n.split("/")[0] for n in raw_names if n}
            if len(top_level) == 1:
                candidate = list(top_level)[0] + "/"
                # Only treat it as a prefix if there are no prowler-output CSVs at the true root
                root_at_true = [n for n in raw_names if re.match(r"^prowler-output-[^/]+\.csv$", n)]
                if not root_at_true:
                    prefix = candidate

            def strip(name):
                return name[len(prefix):] if prefix and name.startswith(prefix) else name

            names = [strip(n) for n in raw_names]

            # Validate structure
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

            # Remove existing main and compliance output files (skip ZIP files themselves)
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
