import csv
import os
import glob
from collections import defaultdict
from flask import Flask, render_template, abort

app = Flask(__name__)

COMPLIANCE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "prowler", "output", "compliance"
)

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
    requirements = defaultdict(lambda: {"total": 0, "passed": 0, "description": "", "section": "", "status_extended": []})
    for r in rows:
        req_id = r.get("REQUIREMENTS_ID", "").strip()
        if not req_id:
            continue
        requirements[req_id]["total"] += 1
        requirements[req_id]["description"] = r.get("REQUIREMENTS_DESCRIPTION", "").strip()
        requirements[req_id]["section"] = r.get("REQUIREMENTS_ATTRIBUTES_SECTION", "").strip()
        if r.get("STATUS", "").upper() == "PASS":
            requirements[req_id]["passed"] += 1

    section_list = []
    for sec_name in sorted(sections.keys()):
        s = sections[sec_name]
        sec_score = round((s["passed"] / s["total"]) * 100, 2) if s["total"] else 0
        # Get requirements for this section
        sec_reqs = []
        for req_id, req_data in sorted(requirements.items()):
            if req_data["section"] == sec_name or (sec_name == "Uncategorized" and not req_data["section"]):
                req_score = round((req_data["passed"] / req_data["total"]) * 100, 2) if req_data["total"] else 0
                sec_reqs.append({
                    "id": req_id,
                    "description": req_data["description"],
                    "total": req_data["total"],
                    "passed": req_data["passed"],
                    "failed": req_data["total"] - req_data["passed"],
                    "score": req_score,
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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
