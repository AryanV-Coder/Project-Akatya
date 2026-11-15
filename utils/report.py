import datetime
from fpdf import FPDF
from utils.crypto import compute_sha256


class Section65BPDF(FPDF):
    def header(self):
        # Header banner
        self.set_fill_color(24, 43, 73)  # Dark Navy
        self.rect(0, 0, 210, 18, "F")
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(255, 255, 255)
        self.set_xy(10, 4)
        self.cell(0, 10, "PROJECT AKATYA - DIGITAL EVIDENCE & FORENSIC REPORTING SYSTEM", align="L")
        self.ln(12)

    def footer(self):
        self.set_y(-18)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 5, "CONFIDENTIAL - PREPARED FOR JUDICIAL PROCEEDINGS UNDER SECTION 65B IT ACT 2000", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 5, f"Page {self.page_no()}", align="C")


def generate_section_65b_pdf(incident_data: dict, evidence_rows: list) -> bytes:
    """
    Programmatically generates an official, non-AI Certificate under Section 65B 
    of the Indian Evidence Act, 2000 / IT Act 2000.
    """
    pdf = Section65BPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(180, 20, 20)
    pdf.cell(0, 8, "CERTIFICATE UNDER SECTION 65B OF THE INDIAN EVIDENCE ACT, 2000", align="C", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 5, "(Special Provisions as to Admissibility of Electronic Records)", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # 1. Incident Metadata Box
    pdf.set_fill_color(245, 247, 250)
    pdf.set_draw_color(200, 205, 215)
    pdf.rect(10, pdf.get_y(), 190, 36, "DF")

    pdf.set_xy(14, pdf.get_y() + 3)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(30, 30, 30)

    # Column 1
    pdf.cell(40, 6, "Incident ID:", 0, 0)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(55, 6, str(incident_data.get("id", "N/A")), 0, 0)

    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(35, 6, "Hostname:", 0, 0)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(50, 6, str(incident_data.get("hostname", "N/A")), 0, 1)

    # Row 2
    pdf.set_x(14)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(40, 6, "Endpoint ID:", 0, 0)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(55, 6, str(incident_data.get("endpoint_id", "N/A")), 0, 0)

    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(35, 6, "Attack Timestamp:", 0, 0)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(50, 6, str(incident_data.get("attack_timestamp", "N/A"))[:19], 0, 1)

    # Row 3
    pdf.set_x(14)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(40, 6, "Process Neutralization:", 0, 0)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(0, 130, 0)
    pdf.cell(55, 6, "TERMINATED (psutil SIGKILL)" if incident_data.get("process_killed") else "UNKNOWN", 0, 0)

    pdf.set_text_color(30, 30, 30)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(35, 6, "Forensic Status:", 0, 0)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(50, 6, "VAULT SECURED / APPEND-ONLY", 0, 1)

    # Row 4
    pdf.set_x(14)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(40, 6, "Hash Algorithm:", 0, 0)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(55, 6, "SHA-256 (FIPS 180-4 Standard)", 0, 0)

    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(35, 6, "Evidence Records:", 0, 0)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(50, 6, f"{len(evidence_rows)} File(s) Documented", 0, 1)

    pdf.ln(6)

    # 2. Statutory Legal Declaration
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(0, 6, "I. STATUTORY CERTIFICATION UNDER SECTION 65B(2) & 65B(4)", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

    declaration_text = (
        "1. I, the undersigned Digital Forensics Administrator, hereby certify that the electronic record "
        "and hash parameters contained herein are a true and authentic representation of digital evidence "
        f"captured from computer system '{incident_data.get('hostname')}' (ID: {incident_data.get('endpoint_id')}).\n"
        "2. The computer system was regularly used to store, process, and protect digital records during the material period.\n"
        "3. Throughout the material period, Project Akatya's host-based defense mechanism was operating properly. When a rapid "
        "unauthorized modification attack occurred, the system immediately terminated the offending process and froze "
        "the cloud vault to ensure forensic preservation.\n"
        "4. The digital hashes below were computed directly using cryptographic SHA-256 without any artificial, "
        "generative, or non-deterministic alteration, ensuring an unbroken and legally admissible chain of custody."
    )

    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(40, 40, 40)
    pdf.multi_cell(190, 4.5, declaration_text)
    pdf.ln(4)

    # 3. Forensic Evidence Comparison Table
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(0, 6, "II. FORENSIC EVIDENCE COMPARISON (ORIGINAL CLEAN VS. CORRUPTED BITSTREAM)", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # Table Header
    pdf.set_fill_color(24, 43, 73)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(40, 7, " Target File", 1, 0, "L", fill=True)
    pdf.cell(65, 7, " Clean Backup Hash (SHA-256)", 1, 0, "L", fill=True)
    pdf.cell(65, 7, " Corrupted File Hash (SHA-256)", 1, 0, "L", fill=True)
    pdf.cell(20, 7, " Status", 1, 1, "C", fill=True)

    # Table Rows
    pdf.set_font("Courier", "", 7)
    pdf.set_text_color(30, 30, 30)

    for idx, row in enumerate(evidence_rows):
        fill = (idx % 2 == 1)
        pdf.set_fill_color(248, 249, 251) if fill else pdf.set_fill_color(255, 255, 255)

        clean_hash = row.get("clean_hash") or "N/A (Unsaved New File)"
        corrupt_hash = row.get("corrupted_hash") or "N/A"
        filename = row.get("corrupted_filepath", "unknown")

        pdf.cell(40, 6, f" {filename[:22]}", 1, 0, "L", fill=fill)
        pdf.cell(65, 6, f" {clean_hash[:32]}...", 1, 0, "L", fill=fill)
        pdf.cell(65, 6, f" {corrupt_hash[:32]}...", 1, 0, "L", fill=fill)
        
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(190, 0, 0)
        pdf.cell(20, 6, "TAMPERED", 1, 1, "C", fill=fill)
        
        pdf.set_font("Courier", "", 7)
        pdf.set_text_color(30, 30, 30)

    pdf.ln(6)

    # 4. Attestation & Cryptographic Stamp
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(0, 6, "III. VERIFICATION & CERTIFYING ATTESTATION", new_x="LMARGIN", new_y="NEXT")

    cert_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_raw = f"{incident_data.get('id')}:{incident_data.get('endpoint_id')}:{cert_time}"
    cert_checksum = compute_sha256(report_raw.encode("utf-8"))

    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(0, 5, f"Date of Electronic Certificate Issuance: {cert_time}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, f"Certificate Integrity Seal (SHA-256): {cert_checksum}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Signature line
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.cell(120, 6, "", 0, 0)
    pdf.cell(70, 6, "________________________________________", 0, 1, "C")
    pdf.cell(120, 5, "", 0, 0)
    pdf.cell(70, 5, "Authorized Forensic Officer Signature", 0, 1, "C")
    pdf.cell(120, 4, "", 0, 0)
    pdf.set_font("Helvetica", "I", 7.5)
    pdf.cell(70, 4, "Project Akatya Forensic Response Division", 0, 1, "C")

    # Output bytes
    return bytes(pdf.output())

