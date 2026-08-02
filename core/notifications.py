import os
import json

def send_webhook_alert(target_name: str, findings: list, is_sast: bool = False):
    slack_url = os.getenv("SLACK_WEBHOOK_URL")
    if not slack_url:
        print("[Slack Webhook] No SLACK_WEBHOOK_URL environment variable defined. Webhook dispatch bypassed successfully (Simulating sandbox).")
        return
    
    # Filter for Critical and High threat levels
    danger_findings = [f for f in findings if str(f.get("severity", "")).upper() in ["CRITICAL", "HIGH"]]
    if not danger_findings:
        print(f"[Slack Webhook] Threat level clean (No Critical/High findings) for {target_name}. Webhook omitted.")
        return
        
    print(f"[Slack Webhook] Processing alerts for {len(danger_findings)} Critical/High threat postures on {target_name}...")
    
    # Compose professional standard Slack Block Layout
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 Sentinel Security: Danger Target Threat Discovered!",
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Target Environment:* `{target_name}`"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Audit Method:* `{'SAST Code Repository Audit' if is_sast else 'Subprocess Vulnerability Scan'}`"
                }
            ]
        },
        {
            "type": "divider"
        }
    ]
    
    for idx, f in enumerate(danger_findings[:3], 1):
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{idx}. {f.get('title', 'Security Vulnerability')}*\n*Severity:* `{f.get('severity', 'HIGH')}`\n*Telemetry Details:* {f.get('description', 'Potential breach suspected.')}"
            }
        })
        
    if len(danger_findings) > 3:
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"_And {len(danger_findings) - 3} other security findings... Please check details inside client dashboard._"
                }
            ]
        })
        
    payload = {
        "text": f"🚨 CRITICAL THREAT DETECTED on {target_name}: {danger_findings[0].get('title')}",
        "blocks": blocks
    }
    
    try:
        import urllib.request
        req = urllib.request.Request(
            slack_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            res_body = response.read()
            print(f"[Slack Webhook] Dispatch succeeded. Code: {response.status}, Reply: {res_body.decode('utf-8')}")
    except Exception as ex:
        print(f"[Slack Webhook] Flipped connection error invoking webhook endpoint: {ex}")
