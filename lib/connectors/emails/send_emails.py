import secrets
import hashlib
import datetime

from urllib.parse import urlencode

import resend

import lib.settings as settings


resend.api_key = settings.load_env()['emails']['api_key']


def build_sign_in_link(researcher_id, expires_in=120):
    conf = settings.load_env()
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=expires_in)
    query = urlencode({
        "token": token,
        "rid": researcher_id,
    })
    sign_in_link = f"{conf['emails']['base_url']}/api/v1/researcher/magiclink?{query}"
    return {
        "sign_in_link": sign_in_link,
        "token_hash": token_hash,
        "researcher_id": researcher_id,
        "expires_at": expires_at.isoformat(),
    }


def send_email(email_address, sign_in_link):
    params: resend.Emails.SendParams = {
        "from": "Onboarding <onboard@onlyvulns.org>",
        "to": [email_address],
        "subject": "Access your OnlyVulns researcher account",
        "html": f"""<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#050505; margin:0; padding:0;">
  <tr>
    <td align="center" style="padding:32px 16px;">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:640px; background:#0b0b0b; border:1px solid #222; border-radius:14px; overflow:hidden;">
        
        <tr>
          <td style="padding:28px 32px 18px 32px; border-bottom:1px solid #222;">
            <div style="font-size:13px; letter-spacing:0.12em; text-transform:uppercase; color:#9ca3af;">
              OnlyVulns
            </div>
            <h1 style="margin:12px 0 0 0; font-size:28px; line-height:1.2; color:#ffffff; font-weight:700;">
              Access your researcher account
            </h1>
          </td>
        </tr>

        <tr>
          <td style="padding:32px;">
            <p style="margin:0 0 18px 0; font-size:16px; line-height:1.6; color:#e5e7eb;">
              Hi!
            </p>

            <p style="margin:0 0 18px 0; font-size:16px; line-height:1.6; color:#e5e7eb;">
              Your OnlyVulns researcher access link is ready.
            </p>

            <p style="margin:0 0 24px 0; font-size:16px; line-height:1.6; color:#d1d5db;">
              Use the secure link below to sign in and complete your researcher registration. Once inside, you can begin preparing vulnerability disclosures through a researcher-controlled workflow.
            </p>

            <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:28px 0;">
              <tr>
                <td align="center" style="border-radius:8px; background:#ffffff;">
                  <a href="{sign_in_link}" target="_blank" style="display:inline-block; padding:14px 22px; font-size:15px; line-height:1; color:#050505; text-decoration:none; font-weight:700; border-radius:8px;">
                    Sign in and register
                  </a>
                </td>
              </tr>
            </table>

            <p style="margin:0 0 16px 0; font-size:15px; line-height:1.6; color:#d1d5db;">
              After signing in, you will be able to:
            </p>

            <ul style="margin:0 0 24px 20px; padding:0; color:#d1d5db; font-size:15px; line-height:1.7;">
              <li>Complete your researcher profile</li>
              <li>Create and manage private vulnerability disclosures before publication</li>
              <li>Add affected versions, CVSS vectors, CWE tags, PoC details, screenshots, references, and mitigation notes</li>
              <li>Set embargoes and waiting periods before public release</li>
              <li>Maintain researcher attribution through documented, reproducible advisories</li>
            </ul>

            <p style="margin:0 0 18px 0; font-size:14px; line-height:1.6; color:#9ca3af;">
              This sign-in link expires in 30 days. If it expires or you need a different link, you can request a new one from the sign-in page.
            </p>

            <p style="margin:0; font-size:14px; line-height:1.6; color:#9ca3af;">
              If you were not expecting this link, you can ignore this email.
            </p>
          </td>
        </tr>

        <tr>
          <td style="padding:24px 32px; border-top:1px solid #222; background:#080808;">
            <p style="margin:0 0 6px 0; font-size:14px; color:#ffffff; font-weight:700;">
              OnlyVulns
            </p>
            <p style="margin:0 0 10px 0; font-size:13px; line-height:1.5; color:#9ca3af;">
              Researcher-controlled vulnerability disclosure
            </p>
            <p style="margin:0; font-size:13px; line-height:1.5; color:#6b7280;">
              contact@perkinsfund.org
            </p>
          </td>
        </tr>

      </table>
    </td>
  </tr>
</table>"""
    }
    try:
        resend.Emails.send(params)
        return True
    except:
        return False

