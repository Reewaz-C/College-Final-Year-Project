import logging
from typing import List, Dict
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define solutions dictionary
solutions = {
    "Injection Vulnerability": "Implement input validation and use parameterized queries to prevent SQL injection.",
    "Insecure Design Vulnerability": "Review and redesign the application architecture to address insecure design patterns.",
    "Broken Access Control": "Implement proper access controls and enforce authorization mechanisms.",
    "Security Misconfiguration": "Review and configure server and application settings to eliminate security misconfigurations.",
    "Sensitive Data Exposure": "Encrypt sensitive data in transit and at rest, and implement access controls to limit exposure.",
    "Integrity Failure": "Implement data integrity checks and validation mechanisms to ensure data consistency and prevent tampering.",
    "Logging Monitoring Failure": "Implement comprehensive logging and monitoring solutions to detect and respond to security incidents.",
    "Server-Side Request Forgery (SSRF)": "Validate and sanitize user-supplied input, and restrict access to sensitive resources.",
    "Vulnerable Components": "Regularly update and patch software components to address known vulnerabilities.",
    "Authentication Failure": "Implement secure authentication mechanisms such as multi-factor authentication and strong password policies.",
}

# Function to generate PDF report with sanitized text
def generate_pdf_report(scan_results, zap_results,owasp_api_security_result):
    try:
        # Output PDF filename
        PDF_REPORT_FILENAME = "security_scan_report.pdf"

        # Create a PDF document
        doc = SimpleDocTemplate(PDF_REPORT_FILENAME, pagesize=letter)

        # Define custom paragraph style for text wrapping
        styles = getSampleStyleSheet()
        body_style = styles["BodyText"]
        custom_body_style = ParagraphStyle(
            "CustomBodyText",
            parent=body_style,
            wordWrap="CJK",  # Word wrap for CJK (Chinese, Japanese, Korean) languages
            leftIndent=10,
            rightIndent=10,
        )

        # Create list to hold report content
        report_content = []

        # Add title to the report
        title = Paragraph("Security Scan Report", styles["Title"])
        report_content.append(title)
        report_content.append(Spacer(1, 12))

        # Add scan results to the report
        for result in scan_results:
            vulnerability_name = result[0]
            vulnerability_details = result[1]
            
            # Check if the vulnerability has a solution
            if vulnerability_name in solutions:
                solution = solutions[vulnerability_name]
                scan_result_paragraph = Paragraph(f"<strong>{vulnerability_name}</strong>: {vulnerability_details}<br/><strong>Solution</strong>: {solution}", custom_body_style)
            else:
                scan_result_paragraph = Paragraph(f"<strong>{vulnerability_name}</strong>: {vulnerability_details}", custom_body_style)
            
            report_content.append(scan_result_paragraph)
            report_content.append(Spacer(1, 6))

        # Add OWASP API security check result to the report
        owasp_result_paragraph = Paragraph(f"<strong>OWASP API Security Check</strong>: {owasp_api_security_result}", custom_body_style)
        report_content.append(owasp_result_paragraph)
        report_content.append(Spacer(1, 6))

        # Add ZAP scan results to the report
        zap_results_section = "<strong>ZAP Scan Results</strong>:<br/><br/>"
        for index, result in enumerate(zap_results, start=1):
            vuln_info = f"<strong>Issue {index}</strong>:<br/>" \
                        f"<strong>Description</strong>: {result['Description']}<br/>" \
                        f"<strong>URL</strong>: {result['URL']}<br/>" \
                        f"<strong>Tags</strong>: {result['Tags']}<br/>" \
                        f"<strong>Risk</strong>: {result['Risk']}<br/>" \
                        f"<strong>Solution</strong>: {result['Solution']}<br/>" \
                        f"<strong>Reference</strong>: {result['Reference']}<br/><br/>"
            zap_results_section += vuln_info

        zap_results_paragraph = Paragraph(zap_results_section, custom_body_style)
        report_content.append(zap_results_paragraph)
        report_content.append(Spacer(1, 6))

        # Check if there are no scan results
        if not scan_results:
            no_results_paragraph = Paragraph("No scan results found.", custom_body_style)
            report_content.append(no_results_paragraph)

        # Build the PDF report
        doc.build(report_content)

        logging.info(f"PDF report generated: {PDF_REPORT_FILENAME}")
    except Exception as e:
        logging.error(f"Error generating PDF report: {e}")
