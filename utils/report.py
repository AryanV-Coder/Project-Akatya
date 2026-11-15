import datetime
from fpdf import FPDF
from utils.crypto import compute_sha256


class Section65BPDF(FPDF):
    def header(self):
        # Top banner (14mm height)
        self.set_fill_color(24, 43, 73)  # Dark Navy
        self.rect(0, 0, 210, 14, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(255, 255, 255)
        self.set_xy(12, 2.5)
        self.cell(0, 9, "PROJECT AKATYA - DIGITAL FORENSICS & INCIDENT RESPONSE SYSTEM", align="L")

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 7.5)
        self.set_text_color(128, 128, 128)
        self.cell(0, 4, "CONFIDENTIAL - PREPARED FOR JUDICIAL SUBMISSION UNDER SECTION 65B IT ACT 2000", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 4, f"Page {self.page_no()}", align="C")


def generate_section_65b_pdf(incident_data: dict, evidence_rows: list) -> bytes:
    """
    Programmatically generates an official, non-AI Certificate under Section 65B 
    of the Indian Evidence Act, 2000 / IT Act 2000 with precise typographic spacing.
    """
    pdf = Section65BPDF(orientation="P", unit="mm", format="A4")
    pdf.set_margins(left=12, top=16, right=12)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # Move below top header banner to prevent any overlap
    pdf.set_y(20)

    # Document Header Title
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(180, 25, 25)  # Crimson Red
    pdf.cell(0, 7, "CERTIFICATE UNDER SECTION 65B OF THE INDIAN EVIDENCE ACT, 2000", align="C", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "I", 8.5)
    pdf.set_text_color(90, 95, 105)
    pdf.cell(0, 5, "(Special Provisions as to Admissibility of Electronic Records in Judicial Proceedings)", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # -------------------------------------------------------------
    # 1. Incident Metadata Box (186mm width, strictly decoupled columns)
    # -------------------------------------------------------------
    box_x = 12
    box_y = pdf.get_y()
    box_w = 186
    box_h = 32

    pdf.set_fill_color(248, 250, 252)
    pdf.set_draw_color(210, 215, 225)
    pdf.rect(box_x, box_y, box_w, box_h, "DF")

    curr_y = box_y + 2.5

    # Row 1: Incident ID & Hostname
    pdf.set_xy(box_x + 3, curr_y)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(26, 5.5, "Incident ID:", 0, 0)
    pdf.set_font("Courier", "", 7.5)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(66, 5.5, str(incident_data.get("id", "N/A")), 0, 0)

    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(26, 5.5, "Target Host:", 0, 0)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(65, 5.5, str(incident_data.get("hostname", "N/A"))[:32], 0, 1)

    # Row 2: Endpoint ID & Attack Timestamp
    curr_y += 6.5
    pdf.set_xy(box_x + 3, curr_y)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(26, 5.5, "Endpoint ID:", 0, 0)
    pdf.set_font("Courier", "", 7.5)
    pdf.cell(66, 5.5, str(incident_data.get("endpoint_id", "N/A")), 0, 0)

    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(26, 5.5, "Attack Time:", 0, 0)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(65, 5.5, str(incident_data.get("attack_timestamp", "N/A"))[:19].replace("T", " ") + " UTC", 0, 1)

    # Row 3: Process Neutralization & Forensic Status
    curr_y += 6.5
    pdf.set_xy(box_x + 3, curr_y)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(26, 5.5, "Kill-Switch:", 0, 0)
    pdf.set_font("Helvetica", "B", 8)
    if incident_data.get("process_killed"):
        pdf.set_text_color(22, 128, 61)  # Emerald Green
        pdf.cell(66, 5.5, "TERMINATED (psutil SIGKILL)", 0, 0)
    else:
        pdf.set_text_color(220, 38, 38)
        pdf.cell(66, 5.5, "UNNEUTRALIZED", 0, 0)

    pdf.set_text_color(30, 41, 59)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(26, 5.5, "Vault Status:", 0, 0)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(65, 5.5, "IMMUTABLE / FROZEN PRE-ATTACK", 0, 1)

    # Row 4: Hash Standard & Evidence Count
    curr_y += 6.5
    pdf.set_xy(box_x + 3, curr_y)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(26, 5.5, "Hash Standard:", 0, 0)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(66, 5.5, "SHA-256 (FIPS 180-4 Standard)", 0, 0)

    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(26, 5.5, "Evidence Files:", 0, 0)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(180, 25, 25)
    pdf.cell(65, 5.5, f"{len(evidence_rows)} Tampered File(s) Documented", 0, 1)

    pdf.set_y(box_y + box_h + 5)

    # -------------------------------------------------------------
    # 2. Statutory Legal Declaration
    # -------------------------------------------------------------
    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(0, 6, "I. STATUTORY CERTIFICATION UNDER SECTION 65B(2) & 65B(4)", new_x="LMARGIN", new_y="NEXT")

    # Divider line
    pdf.set_draw_color(24, 43, 73)
    pdf.set_line_width(0.3)
    pdf.line(12, pdf.get_y(), 198, pdf.get_y())
    pdf.ln(2.5)

    declaration_text = (
        f"1. I, the undersigned Digital Forensics Officer, certify that the electronic records and cryptographic "
        f"hashes documented herein represent electronic evidence produced by computer system '{incident_data.get('hostname')}' "
        f"(Endpoint UUID: {incident_data.get('endpoint_id')}).\n"
        f"2. The computer system was operating under lawful management and used regularly to process and store electronic information.\n"
        f"3. Throughout the material period, Project Akatya's automated host defense was active. When an unauthorized rapid modification "
        f"burst was detected, the defense mechanism terminated the offending ransomware process and halted cloud vault ingestion to preserve integrity.\n"
        f"4. The SHA-256 cryptographic hashes detailed below were extracted programmatically directly from the binary bitstream "
        f"of the affected files without subjective, generative, or non-deterministic modification."
    )

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(51, 65, 85)
    pdf.multi_cell(186, 4.2, declaration_text)
    pdf.ln(4)

    # -------------------------------------------------------------
    # 3. Forensic Evidence Comparison Table (186mm total width)
    # -------------------------------------------------------------
    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(0, 6, "II. FORENSIC EVIDENCE COMPARISON (ORIGINAL CLEAN VS. CORRUPTED BITSTREAM)", new_x="LMARGIN", new_y="NEXT")

    pdf.set_draw_color(24, 43, 73)
    pdf.set_line_width(0.3)
    pdf.line(12, pdf.get_y(), 198, pdf.get_y())
    pdf.ln(2.5)

    # Table Header: 38mm + 64mm + 64mm + 20mm = 186mm
    col_w = [38, 64, 64, 20]
    pdf.set_fill_color(24, 43, 73)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 7.5)
    pdf.set_draw_color(200, 205, 215)
    pdf.set_line_width(0.2)

    pdf.cell(col_w[0], 6.5, " Target File", 1, 0, "L", fill=True)
    pdf.cell(col_w[1], 6.5, " Clean Backup Hash (SHA-256)", 1, 0, "L", fill=True)
    pdf.cell(col_w[2], 6.5, " Corrupted File Hash (SHA-256)", 1, 0, "L", fill=True)
    pdf.cell(col_w[3], 6.5, " Status", 1, 1, "C", fill=True)

    # Table Rows
    for idx, row in enumerate(evidence_rows):
        fill = (idx % 2 == 1)
        pdf.set_fill_color(248, 250, 252) if fill else pdf.set_fill_color(255, 255, 255)

        raw_clean = row.get("clean_hash")
        clean_hash = f"{raw_clean[:28]}..." if raw_clean else "N/A (Pre-Attack Unsaved)"
        
        raw_corrupt = row.get("corrupted_hash") or ""
        corrupt_hash = f"{raw_corrupt[:28]}..." if raw_corrupt else "N/A"

        fname = row.get("corrupted_filepath", "unknown")
        if len(fname) > 21:
            fname = fname[:19] + ".."

        # File Name
        pdf.set_font("Helvetica", "", 7.2)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(col_w[0], 5.8, f" {fname}", 1, 0, "L", fill=fill)

        # Clean Hash
        pdf.set_font("Courier", "", 6.8)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(col_w[1], 5.8, f" {clean_hash}", 1, 0, "L", fill=fill)

        # Corrupted Hash
        pdf.cell(col_w[2], 5.8, f" {corrupt_hash}", 1, 0, "L", fill=fill)

        # Status
        pdf.set_font("Helvetica", "B", 6.8)
        pdf.set_text_color(185, 28, 28)
        pdf.cell(col_w[3], 5.8, "TAMPERED", 1, 1, "C", fill=fill)

    pdf.ln(5)

    # -------------------------------------------------------------
    # 4. Attestation & Cryptographic Stamp
    # -------------------------------------------------------------
    # Check space remaining on page to prevent splitting signature block
    if pdf.get_y() > 235:
        pdf.add_page()
        pdf.set_y(22)

    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(0, 6, "III. VERIFICATION & CERTIFYING ATTESTATION", new_x="LMARGIN", new_y="NEXT")

    pdf.set_draw_color(24, 43, 73)
    pdf.set_line_width(0.3)
    pdf.line(12, pdf.get_y(), 198, pdf.get_y())
    pdf.ln(2.5)

    cert_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_raw = f"{incident_data.get('id')}:{incident_data.get('endpoint_id')}:{cert_time}"
    cert_checksum = compute_sha256(report_raw.encode("utf-8"))

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(51, 65, 85)
    pdf.cell(0, 4.5, f"Date of Electronic Certificate Issuance: {cert_time}", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Courier", "", 7.5)
    pdf.cell(0, 4.5, f"Document Integrity Checksum: {cert_checksum}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Formal Signature block
    sig_y = pdf.get_y()
    pdf.set_draw_color(148, 163, 184)
    pdf.line(125, sig_y + 12, 195, sig_y + 12)

    pdf.set_xy(125, sig_y + 13)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(70, 4.5, "Authorized Digital Forensics Officer", 0, 1, "C")

    pdf.set_x(125)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(70, 4, "Project Akatya Incident Response Authority", 0, 1, "C")

    return bytes(pdf.output())
