import json
import os
import logging
import boto3
import hashlib
from datetime import datetime, timezone

# Mapping of Wazuh rule groups → AWS Security Hub Types
WAZUH_TO_SECURITYHUB_TYPES = {
    # Authentication / SSH
    "authentication_failed": "Unusual Behaviors/Unauthorized Access",
    "authentication_success": "Unusual Behaviors/Authorized Access",
    "sshd": "Unusual Behaviors/Unauthorized Access",
    "invalid_login": "Unusual Behaviors/Unauthorized Access",
    "users": "Unusual Behaviors/Unauthorized Access",

    # Windows
    "windows": "TTPs/Execution",
    "windows_security": "TTPs/Execution",
    "windows_system": "Unusual Behaviors/System Activity",
    "windows_application": "Unusual Behaviors/System Activity",

    # Malware, threats
    "malware": "Malware",
    "virus": "Malware",
    "clamav": "Malware",
    "osquery": "TTPs/Discovery",

    # Syslog / system activity
    "syslog": "Unusual Behaviors/System Activity",
    "system": "Unusual Behaviors/System Activity",

    # Policies / compliance
    "pci_dss": "Policy/Configuration",
    "gdpr": "Policy/Configuration",
    "nist_800_53": "Policy/Configuration",
    "hipaa": "Policy/Configuration",
    "ruleset": "Policy/Configuration",

    # Network activity
    "network": "TTPs/Command and Control",
    "firewall": "TTPs/Defense Evasion",
    "iptables": "TTPs/Defense Evasion",

    # File integrity monitoring
    "fim": "TTPs/Defense Evasion",
    "file": "TTPs/Defense Evasion",

    # Updates
    "package": "Unusual Behaviors/System Activity",
    "updates": "Unusual Behaviors/System Activity",

    # Default for everything unknown
    "*": "Unusual Behaviors/System Activity"
}

s3 = boto3.client('s3')
securityhub = boto3.client('securityhub')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

securityhub = boto3.client('securityhub')
sns = boto3.client('sns')
events = boto3.client('events')

# Config from environment variables
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
EVENT_BUS_NAME = os.environ.get('EVENT_BUS_NAME')
FINDING_PRODUCT_ARN = os.environ.get('FINDING_PRODUCT_ARN')

def map_wazuh_to_securityhub_types(alert):
    groups = alert.get("rule", {}).get("groups", [])
    matched_types = set()

    for g in groups:
        if g in WAZUH_TO_SECURITYHUB_TYPES:
            matched_types.add(WAZUH_TO_SECURITYHUB_TYPES[g])

    # Fallback for unmapped groups
    if not matched_types:
        matched_types.add(WAZUH_TO_SECURITYHUB_TYPES["*"])

    return list(matched_types)

def clean_windows_message(msg):
    if not msg or msg == "not applicable":
        return msg
    try:
        if msg.startswith("{"):
            msg = json.loads(msg)
            return msg
    except Exception:
        pass
    try:
        cleaned = msg.encode('utf-8').decode('unicode_escape')
        cleaned = cleaned.replace('\r\n', '\n').replace('\r', '\n')
        cleaned = cleaned.strip()
        return cleaned
    except Exception:
        return msg

def generate_id(alert):
    key = f"{alert['rule']['id']}-{alert['agent']['id']}-{alert['timestamp']}"
    return hashlib.sha256(key.encode()).hexdigest()

def iso8601_now():
    return datetime.now(timezone.utc).isoformat()

def handler(event, context):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.info("Received event: %s", json.dumps(event))

    alerts = []

    if 'Records' in event and event['Records'][0].get('eventSource') == 'aws:s3':
        for record in event.get('Records', []):
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']
            print(f"Reading from bucket: {bucket}, key: {key}")

            logger.info(f"Processing S3 object: s3://{bucket}/{key}")

            # Read file from S3
            obj = s3.get_object(Bucket=bucket, Key=key)
            data = obj['Body'].read().decode('utf-8')

            for line in data.splitlines():
                if line.strip():
                    try:
                        alert = json.loads(line)
                        alerts.append(alert)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse alert JSON: {e}")

        #except Exception as e:
         #   logger.error("Failed to parse alert JSON from S3: %s", e)
         #   return {"statusCode": 400, "body": json.dumps({"error": "invalid json"})}
                
         #   alerts.extend(body if isinstance(body, list) else [body])
        flat_alerts = []
        for a in alerts: 
            if isinstance(a, list):
                flat_alerts.extend(a)
            else:
                flat_alerts.append(a)
        alerts = flat_alerts

        for alert in alerts:
            build_securityhub_finding(alert)
            
    return {"statusCode": 200, "body": json.dumps({"processed": len(alerts)})}
    print(alert)

def map_severity(wazuh_level):
    try:
       lvl = int(wazuh_level)
    except Exception:
       lvl = 5
    if lvl >= 12:
        return 'CRITICAL', 90.0
    if lvl >= 8:
        return 'HIGH', 70.0
    if lvl >= 4:
        return 'MEDIUM', 40.0
    return 'LOW', 10.0

def build_securityhub_finding(alert):
    rule = alert.get('rule', {})
    rule_id = alert.get("rule", {}).get("id")
    agent = alert.get('agent', {})
    agent_id = agent.get('id', 'unknown')
    agent_name = agent.get('name', 'unknown')
    agent_ip = agent.get('ip', 'unknown')
    source_ip = alert.get('data', {}).get('srcip')
    win_data = alert.get('data', {}).get('win', {}).get('system', {})
    win_message = clean_windows_message(win_data.get('message'))
    win_event_source = win_data.get('eventSourceName')
    
    if not win_message:
        win_message = "not applicable"
    if not win_event_source:
        win_event_source = "not applicable"

    if source_ip is None:
        source_ip = "not applicable"
    
    level = rule.get('level', 0)
    severity_label, normalized_score = map_severity(level)
    created_at = alert.get('timestamp') or iso8601_now()

    # if wazuh agent is stopped, trigger critical
    if rule_id == 503:
        severity_label = "CRITICAL"
    
    finding_id = f"wazuh-{agent.get('id','unknown')}-{rule.get('id','0')}-{created_at}"

    product_arn = FINDING_PRODUCT_ARN or f"arn:aws:securityhub:{os.environ['AWS_REGION']}:{os.environ['AWS_ACCOUNT_ID']}:product/{os.environ['AWS_ACCOUNT_ID']}/default"

    description = alert.get('full_log', rule.get('description', 'No Description Available'))

    if win_message != "not applicable":
        description += f"\n\nWindows Event Message: {win_message}"

    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": f"wazuh-{generate_id(alert)}",
        "ProductArn": product_arn,
        "GeneratorId": "wazuh-manager",
        "AwsAccountId": os.environ['AWS_ACCOUNT_ID'],
        "Types" : map_wazuh_to_securityhub_types(alert),
        "CreatedAt": created_at,
        "UpdatedAt": created_at,
        "Severity": {
            "Label": severity_label,
            "Normalized": int(normalized_score)
        },
        "Title": f"[Rule {rule_id}] {rule.get('description', 'Wazuh alert')}",
        "Description": description,
        "Resources": [
            {
                "Type": "AwsEc2Instance",
                "Id": agent_name,
                "Details": {
                    "Other": {
                        "AgentId": agent_id,
                        "AgentIP": agent_ip,
                        "SourceIP": source_ip
                        }
                    },
                },
            ],

        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
        "Confidence": int(alert.get('confidence', 50))
    }

    srcip = alert.get('srcip') or alert.get('src_ip') or None
    if srcip:
        finding["Network"] = { "SourceIpV4": srcip }

    
    try:
        #send to securityhub
        response = securityhub.batch_import_findings(Findings=[finding])
        print(response)
        logger.info(f"SecurityHub response: {response}")
    
        if EVENT_BUS_NAME:
            events.put_events(
                Entries=[{
                    'Source': 'custom.wazuh',
                    'DetailType': 'Wazuh Alert',
                    'Detail': json.dumps(alert),
                    'EventBusName': EVENT_BUS_NAME
                }]
            )

    except Exception as e:
        logger.error(f"Failed to send finding: {e}")
    
    return finding
