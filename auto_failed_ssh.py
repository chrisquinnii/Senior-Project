import boto3
import json

ec2 = boto3.client('ec2')

NACL_ID = <Enter NACL ID>

def extract_ip(event):
    """
    Handles ALL possible incoming shapes:
    - Direct SecurityHub JSON (test events)
    - EventBridge-wrapped SecurityHub events
    - Wazuh direct finding (just in case)
    """
    # Case 1: EventBridge → SecurityHub shape
    try:
        return event["detail"]["findings"][0]["Resources"][0]["Details"]["Other"]["SourceIP"]
    except:
        pass

    # Case 2: Direct SecurityHub JSON (your test event)
    try:
        return event["Resources"][0]["Details"]["Other"]["SourceIP"]
    except:
        pass

    # No match
    return None

def ip_already_blocked(nacl, attacker_ip):
    cidr = f"{attacker_ip}/32"
    for entry in nacl["Entries"]:
        if entry.get("CidrBlock") == cidr and entry["RuleAction"] == "deny" and entry["Egress"] is False:
            return True
    return False

def lambda_handler(event, context):
    print("=== EVENT RECEIVED ===")
    print(json.dumps(event, indent=2))

    try:
        attacker_ip = extract_ip(event)
        if not attacker_ip:
            raise ValueError("Could not extract SourceIP from event")

        print(f"Attacker IP detected: {attacker_ip}")

        nacl = ec2.describe_network_acls(NetworkAclIds=[NACL_ID])["NetworkAcls"][0]

        if ip_already_blocked(nacl, attacker_ip):
            print(f"IP {attacker_ip} is already blocked in NACL {NACL_ID}.")
            return {"status": "already_blocked", "blocked_ip": attacker_ip}
        
        ingress_rules = [
            entry["RuleNumber"]
            for entry in nacl["Entries"]
            if entry["Egress"] is False and entry["RuleNumber"] != 32767
            ]

        print(f' Max Rules: {(max(ingress_rules) + 1)}') 

        if not ingress_rules:
            next_rule_number = 200  
        else:
            next_rule_number =  max(ingress_rules) + 1

        if next_rule_number > 32766:
            raise Exception("No available NACL rule numbers remain!")

            print(f"Using NACL rule number: {next_rule_number}")

            # Create deny rule to block attacker
        response = ec2.create_network_acl_entry(
            NetworkAclId=NACL_ID,
            RuleNumber=next_rule_number,
            Protocol="-1",  # ALL protocols
            RuleAction="deny",
            Egress=False,
            CidrBlock=f"{attacker_ip}/32"
            )

        print("Successfully added deny rule:")
        print(json.dumps(response))

        print("LAMBDA COMPLETED")

        return {"status": "success", "blocked_ip": attacker_ip, "rule_number": next_rule_number}

    except Exception as e:
        print("ERROR:", str(e))
        raise
