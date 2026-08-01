import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def send_test_email(receiver_email):
    # SMTP Configuration from .env
    smtp_host = os.getenv("SMTP_HOST", "smtp-mail.outlook.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")

    if not smtp_user or not smtp_pass:
        print("Error: SMTP_USER or SMTP_PASS not found in .env file.")
        return

    # Create Message
    message = MIMEMultipart()
    message["From"] = smtp_user
    message["To"] = receiver_email
    message["Subject"] = "Test Email from Outlook SMTP"

    body = "This is a sample test email sent using Python and Outlook SMTP."
    message.attach(MIMEText(body, "plain"))

    try:
        print(f"Connecting to {smtp_host}:{smtp_port}...")
        # For outlook, use STARTTLS on port 587
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls() # Secure the connection
        
        print(f"Logging in as {smtp_user}...")
        server.login(smtp_user, smtp_pass)
        
        print(f"Sending email to {receiver_email}...")
        server.send_message(message)
        
        server.quit()
        print("✅ Email sent successfully!")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

if __name__ == "__main__":
    target = input("Enter the receiver email address: ")
    send_test_email(target)
