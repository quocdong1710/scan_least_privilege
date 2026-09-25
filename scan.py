#!/usr/bin/env python3
"""AWS IAM Least Privilege Analyzer - Full privilege escalation + least privilege check."""

import json
import argparse
import time
import urllib.parse
from datetime import datetime, timezone
from collections import defaultdict
from fnmatch import fnmatch

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

# ============================================================================
# CONSTANTS
# ============================================================================

ESCALATION_COMBOS = [
    {"name": "CreatePolicyVersion", "permissions": ["iam:CreatePolicyVersion"],
     "description": "Create new policy version with elevated privileges", "severity": "critical"},
    {"name": "SetDefaultPolicyVersion", "permissions": ["iam:SetDefaultPolicyVersion"],
     "description": "Set a previously created permissive policy version as default", "severity": "critical"},
    {"name": "PassRole+Lambda", "permissions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
     "description": "Pass privileged role to Lambda and invoke it", "severity": "critical"},
    {"name": "PassRole+EC2", "permissions": ["iam:PassRole", "ec2:RunInstances"],
     "description": "Launch EC2 with privileged instance profile", "severity": "critical"},
    {"name": "PassRole+CloudFormation", "permissions": ["iam:PassRole", "cloudformation:CreateStack"],
     "description": "Deploy CloudFormation stack with privileged role", "severity": "high"},
    {"name": "AttachUserPolicy", "permissions": ["iam:AttachUserPolicy"],
     "description": "Attach AdministratorAccess to own user", "severity": "critical"},
    {"name": "AttachGroupPolicy", "permissions": ["iam:AttachGroupPolicy"],
     "description": "Attach AdministratorAccess to own group", "severity": "critical"},
    {"name": "AttachRolePolicy", "permissions": ["iam:AttachRolePolicy"],
     "description": "Attach elevated policy to assumable role", "severity": "high"},
    {"name": "PutUserPolicy", "permissions": ["iam:PutUserPolicy"],
     "description": "Add inline policy to own user", "severity": "critical"},
    {"name": "PutGroupPolicy", "permissions": ["iam:PutGroupPolicy"],
     "description": "Add inline policy to own group", "severity": "high"},
    {"name": "AssumeRole", "permissions": ["sts:AssumeRole"],
     "description": "Assume role with higher privileges", "severity": "medium"},
    {"name": "PassRole+SageMaker", "permissions": ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
     "description": "Create SageMaker notebook with privileged role", "severity": "high"},
    {"name": "UpdateAssumeRolePolicy", "permissions": ["iam:UpdateAssumeRolePolicy"],
     "description": "Modify trust policy to assume privileged role", "severity": "critical"},
    {"name": "PassRole+SSM", "permissions": ["iam:PassRole", "ssm:SendCommand"],
     "description": "Execute commands on EC2 via SSM with privileged role", "severity": "critical"},
]

# Actions that modify/delete/write data and MUST have specific Resource ARN (not "*")
SENSITIVE_DATA_ACTIONS = {
    "s3:putobject", "s3:deleteobject", "s3:deletebucket", "s3:getobject",
    "dynamodb:putitem", "dynamodb:deleteitem", "dynamodb:deletetable", "dynamodb:getitem",
    "secretsmanager:getsecretvalue", "secretsmanager:deletesecret",
    "kms:decrypt", "kms:encrypt", "kms:disablekey",
    "rds:deletedbinstance", "rds:deletedbcluster",
    "lambda:deletefunction", "lambda:updatefunctioncode",
    "sqs:sendmessage", "sqs:deletemessage", "sqs:deletequeue",
    "sns:publish", "sns:deletetopic",
    "logs:deleteloggroup",
    "ec2:terminateinstances", "ec2:stopinstances",
}

# Dangerous wildcard service patterns
DANGEROUS_WILDCARD_SERVICES = {"iam:*", "sts:*", "lambda:*", "ec2:*", "s3:*", "cloudformation:*", "*"}


# ============================================================================
# STAGE 0: DATA COLLECTION (take data from live AWS account or pre-downloaded JSON)
# ============================================================================

def get_account_authorization(profile=None):
    """Download full IAM authorization details via boto3."""
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam")
    paginator = iam.get_paginator("get_account_authorization_details")
    details = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    for page in paginator.paginate():
        details["UserDetailList"].extend(page.get("UserDetailList", []))
        details["GroupDetailList"].extend(page.get("GroupDetailList", []))
        details["RoleDetailList"].extend(page.get("RoleDetailList", []))
        details["Policies"].extend(page.get("Policies", []))
    return details


# ============================================================================
# STAGE 1: STATIC ANALYSIS - Improved policy parsing
# ============================================================================

# function to parse policy documents and extract allowed/denied actions, including wildcard resource checks
def parse_policy_document(policy_document):
    """Parse a policy document string/dict into normalized statements.
    Returns a list of statement dicts."""
    if isinstance(policy_document, str):
        try:
            policy_document = json.loads(urllib.parse.unquote(policy_document))
        except Exception:
            try:
                policy_document = json.loads(policy_document)
            except Exception:
                return []
    if not isinstance(policy_document, dict):
        return []
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    elif not isinstance(statements, list):
        return []
    return [s for s in statements if isinstance(s, dict)]

# function to extract allowed and denied actions from a policy document, including wildcard resource checks
def extract_allow_deny_actions(policy_document):
    """Extract actions separated into allowed and denied sets, plus resource info.
    Returns: (allowed_actions: set, denied_actions: set, wildcard_resource_actions: set)
    """
    allowed = set()
    denied = set()
    wildcard_resource_actions = set()

    # loop through each statement in the policy document
    for statement in parse_policy_document(policy_document):
        effect = statement.get("Effect", "")
        stmt_actions = statement.get("Action", [])
        if isinstance(stmt_actions, str):
            stmt_actions = [stmt_actions]
        elif not isinstance(stmt_actions, list):
            continue

        normalized = set()
        #loop through each action in the statement and normalize to lowercase
        for action in stmt_actions:
            if isinstance(action, str):
                normalized.add(action.lower())

        resource = statement.get("Resource", "")
        has_wildcard_resource = (resource == "*" or
                                (isinstance(resource, list) and "*" in resource))

        if effect == "Allow":
            allowed.update(normalized)
            if has_wildcard_resource:
                wildcard_resource_actions.update(normalized)
        elif effect == "Deny":
            denied.update(normalized)

    return allowed, denied, wildcard_resource_actions

# function to resolve managed policy actions by looking up the policy ARN in the list of all policies and extracting allowed/denied actions
def resolve_managed_policy_actions(policy_arn, all_policies):
    """Look up a managed policy ARN in the Policies list and extract actions."""
    # loop through all policies to find the one matching the given ARN
    for p in all_policies:
        if p.get("Arn") == policy_arn:
            # loop through the policy versions to find the default version and extract actions
            for ver in p.get("PolicyVersionList", []):
                if ver.get("IsDefaultVersion"):
                    return extract_allow_deny_actions(ver.get("Document", {}))
    return set(), set(), set()

# function to collect all allowed/denied actions for a principal, including group inheritance for users
def collect_principal_permissions(principal, principal_type, auth_details):
    """Collect all allowed/denied actions for a principal, including Group inheritance.
    Returns: (effective_actions, denied_actions, wildcard_resource_actions, permission_sources)
    """
    all_allowed = set()
    all_denied = set()
    all_wildcard_res = set()
    sources = []
    all_policies_list = auth_details.get("Policies", [])

    # 1. Inline policies of the principal itself
    inline_key = "UserPolicyList" if principal_type == "User" else "RolePolicyList"

    for policy in principal.get(inline_key, []):
        allowed, denied, wc_res = extract_allow_deny_actions(policy.get("PolicyDocument", {}))
        all_allowed.update(allowed)
        all_denied.update(denied)
        all_wildcard_res.update(wc_res)
        if allowed or denied:
            sources.append({
                "source_type": "inline",
                "policy_name": policy.get("PolicyName", "unknown"),
                "allowed_count": len(allowed),
                "denied_count": len(denied),
            })

    # 2. Attached managed policies of the principal
    for policy in principal.get("AttachedManagedPolicies", []):
        arn = policy.get("PolicyArn", "")
        allowed, denied, wc_res = resolve_managed_policy_actions(arn, all_policies_list)
        all_allowed.update(allowed)
        all_denied.update(denied)
        all_wildcard_res.update(wc_res)
        if allowed or denied:
            sources.append({
                "source_type": "managed",
                "policy_name": policy.get("PolicyName", "unknown"),
                "policy_arn": arn,
                "allowed_count": len(allowed),
                "denied_count": len(denied),
            })

    # 3. Group inheritance (only for Users)
    if principal_type == "User":
        user_groups = principal.get("GroupList", [])
        # loop through each group the user belongs to and extract allowed/denied actions from group policies
        for group_name in user_groups:
            # loop through all groups in the auth_details to find the matching group and extract its policies
            for group in auth_details.get("GroupDetailList", []):
                if group.get("GroupName") == group_name:
                    # Group inline policies
                    for policy in group.get("GroupPolicyList", []):
                        allowed, denied, wc_res = extract_allow_deny_actions(
                            policy.get("PolicyDocument", {}))
                        all_allowed.update(allowed)
                        all_denied.update(denied)
                        all_wildcard_res.update(wc_res)
                        if allowed or denied:
                            sources.append({
                                "source_type": "group_inline",
                                "group_name": group_name,
                                "policy_name": policy.get("PolicyName", "unknown"),
                                "allowed_count": len(allowed),
                                "denied_count": len(denied),
                            })
                    # Group attached managed policies
                    for policy in group.get("AttachedManagedPolicies", []):
                        arn = policy.get("PolicyArn", "")
                        allowed, denied, wc_res = resolve_managed_policy_actions(
                            arn, all_policies_list)
                        all_allowed.update(allowed)
                        all_denied.update(denied)
                        all_wildcard_res.update(wc_res)
                        if allowed or denied:
                            sources.append({
                                "source_type": "group_managed",
                                "group_name": group_name,
                                "policy_name": policy.get("PolicyName", "unknown"),
                                "policy_arn": arn,
                                "allowed_count": len(allowed),
                                "denied_count": len(denied),
                            })

    # Compute effective actions: Allow minus Deny
    effective_actions = set()
    # Loop through all allowed actions and check if they are denied by any deny statement, including wildcard handling
    for action in all_allowed:
        is_denied = False
        # Loop through all denied actions to check if the current allowed action is explicitly denied or matches a wildcard deny
        for deny_action in all_denied:
            if deny_action == action:
                is_denied = True
                break
            # Handle wildcard deny like "iam:*" blocking "iam:passrole"
            if deny_action.endswith(":*"):
                deny_prefix = deny_action[:-1]  # "iam:"
                if action.startswith(deny_prefix):
                    is_denied = True
                    break
            if deny_action == "*":
                is_denied = True
                break
        if not is_denied:
            effective_actions.add(action)

    return effective_actions, all_denied, all_wildcard_res, sources


# ============================================================================
# STAGE 1: CHECKS - Escalation, Wildcards, Resource Wildcards
# ============================================================================

# function to check if effective actions contain known privilege escalation combos
def check_escalation_paths(effective_actions):
    """Check if effective actions contain known privilege escalation combos."""
    findings = []
    has_wildcard = "iam:*" in effective_actions or "*" in effective_actions
    # loop through each escalation combo and check if the required permissions are a subset of effective actions or if a wildcard is present
    for combo in ESCALATION_COMBOS:
        required = {p.lower() for p in combo["permissions"]}
        if has_wildcard or required.issubset(effective_actions):
            findings.append({
                "escalation_path": combo["name"],
                "required_permissions": combo["permissions"],
                "description": combo["description"],
                "severity": combo["severity"],
            })
    return findings

# function to check for dangerous wildcard action patterns in effective actions
def check_wildcard_actions(effective_actions):
    """Flag dangerous wildcard action patterns in effective actions."""
    dangerous_wildcards = []
    wildcard_patterns = [a for a in effective_actions if a.endswith(":*") or a == "*"]
    # loop through each wildcard pattern and check if it is in the list of dangerous wildcard services
    for wp in wildcard_patterns:
        if wp in DANGEROUS_WILDCARD_SERVICES:
            dangerous_wildcards.append({
                "action": wp,
                "severity": "critical" if wp in {"iam:*", "*"} else "high",
                "finding": f"Wildcard action '{wp}' grants broad access",
            })
    return dangerous_wildcards

# function to check for sensitive actions that use Resource: '*' in wildcard resource actions
def check_sensitive_resource_wildcard(wildcard_resource_actions, denied_actions):
    """[STAGE 1 NEW] Flag sensitive data actions that use Resource: '*'."""
    findings = []
    seen = set()
    
    # loop through each action in wildcard resource actions and check if it matches any sensitive pattern
    for action in wildcard_resource_actions:
        # Check if action matches any sensitive pattern
        if action in SENSITIVE_DATA_ACTIONS and action not in denied_actions:
            if action not in seen:
                findings.append({
                    "action": action,
                    "severity": "high",
                    "finding": f"Sensitive action '{action}' uses Resource: '*' - "
                               f"should be scoped to specific ARNs",
                })
                seen.add(action)
        # Also check wildcard service patterns against sensitive actions
        if action.endswith(":*"):
            prefix = action[:-1]  # e.g. "s3:"
            matched = [s for s in SENSITIVE_DATA_ACTIONS if s.startswith(prefix)]
            for m in matched:
                if m not in denied_actions and m not in seen:
                    findings.append({
                        "action": f"{action} (implies {m})",
                        "severity": "high",
                        "finding": f"Wildcard '{action}' implicitly grants sensitive action "
                                   f"'{m}' on all resources",
                    })
                    seen.add(m)
    return findings


# ============================================================================
# STAGE 2: DYNAMIC ANALYSIS - IAM Access Advisor (unused services)
# ============================================================================

# function to get unused services for a principal using IAM Access Advisor
def get_unused_services(iam_client, principal_arn, max_unused_days=90):
    """[STAGE 2] Use IAM Access Advisor to find services that were granted
    but never accessed or not accessed within max_unused_days."""
    try:
        response = iam_client.generate_service_last_accessed_details(Arn=principal_arn)
        job_id = response["JobId"]

        # loop to poll the job status until it is completed or failed, with a timeout of 30 seconds
        for _ in range(30):
            result = iam_client.get_service_last_accessed_details(JobId=job_id)
            if result["JobStatus"] == "COMPLETED":
                break
            elif result["JobStatus"] == "FAILED":
                return [], f"Access Advisor job failed"
            time.sleep(1)
        else:
            return [], "Access Advisor job timed out after 30 seconds"

        unused_services = []
        now = datetime.now(timezone.utc)
        
        # Loop through each service in the result and check last accessed time
        for service in result.get("ServicesLastAccessed", []):
            service_name = service.get("ServiceName", "unknown")
            service_namespace = service.get("ServiceNamespace", "unknown")
            last_accessed = service.get("LastAuthenticated")

            if not last_accessed:
                unused_services.append({
                    "service_name": service_name,
                    "service_namespace": service_namespace,
                    "status": "never_used",
                    "severity": "medium",
                    "finding": f"Service '{service_name}' ({service_namespace}) is granted "
                               f"but has NEVER been used",
                    "days_inactive": None,
                })
            else:
                days_inactive = (now - last_accessed).days
                if days_inactive > max_unused_days:
                    unused_services.append({
                        "service_name": service_name,
                        "service_namespace": service_namespace,
                        "status": "inactive",
                        "severity": "low" if days_inactive < 180 else "medium",
                        "finding": f"Service '{service_name}' ({service_namespace}) not used "
                                   f"for {days_inactive} days (last: {last_accessed.strftime('%Y-%m-%d')})",
                        "days_inactive": days_inactive,
                    })

        return unused_services, None

    except Exception as e:
        return [], f"Access Advisor error: {str(e)}"


# ============================================================================
# MAIN ANALYSIS
# ============================================================================

# function to analyze all principals for escalation paths and least privilege violations
def analyze_account(auth_details, iam_client=None, check_unused=False, max_unused_days=90):
    """Analyze all principals for escalation paths and least privilege violations."""
    findings = []
    principals = []

    # Loop through all users and roles in the auth_details and collect their details into a principals list
    for user in auth_details.get("UserDetailList", []):
        principals.append(("User", user, user.get("UserName"), user.get("Arn")))

    # loop through all roles in the auth_details and collect their details into a principals list
    for role in auth_details.get("RoleDetailList", []):
        principals.append(("Role", role, role.get("RoleName"), role.get("Arn")))

    # loop through each principal and collect their effective actions, denied actions, wildcard resource actions, and permission sources
    for principal_type, principal, name, arn in principals:
        effective_actions, denied_actions, wildcard_res_actions, sources = \
            collect_principal_permissions(principal, principal_type, auth_details)

        escalations = check_escalation_paths(effective_actions)
        wildcards = check_wildcard_actions(effective_actions)
        resource_wildcards = check_sensitive_resource_wildcard(
            wildcard_res_actions, denied_actions)

        unused_services = []
        access_advisor_error = None
        if check_unused and iam_client and arn:
            unused_services, access_advisor_error = get_unused_services(
                iam_client, arn, max_unused_days)

        has_findings = (escalations or wildcards or resource_wildcards or unused_services)
        if has_findings:
            entry = {
                "principal_type": principal_type,
                "principal_name": name,
                "arn": arn,
                "permission_sources": sources,
                "denied_actions": sorted(denied_actions) if denied_actions else [],
                "effective_action_count": len(effective_actions),
                "escalation_paths": escalations,
                "wildcard_findings": wildcards,
                "resource_wildcard_findings": resource_wildcards,
            }
            if check_unused:
                entry["unused_services"] = unused_services
                if access_advisor_error:
                    entry["access_advisor_error"] = access_advisor_error
            findings.append(entry)

    return findings


def generate_report(findings, source, stages_run):
    """Generate comprehensive least privilege analysis report."""
    severity_counts = defaultdict(int)
    for f in findings:
        for esc in f.get("escalation_paths", []):
            severity_counts[esc["severity"]] += 1
        for wc in f.get("wildcard_findings", []):
            severity_counts[wc["severity"]] += 1
        for rw in f.get("resource_wildcard_findings", []):
            severity_counts[rw["severity"]] += 1
        for us in f.get("unused_services", []):
            severity_counts[us["severity"]] += 1

    return {
        "report_time": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "stages_run": stages_run,
        "total_principals_with_findings": len(findings),
        "severity_summary": dict(severity_counts),
        "findings": findings,
    }


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AWS IAM Least Privilege Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Stage 1 only (static analysis, offline from JSON):
  python scan.py --input-file auth_details.json --output report.json

  # Stage 1 only (live scan from AWS account):
  python scan.py --output report.json

  # Stage 1 + Stage 2 (live scan + Access Advisor):
  python scan.py --check-unused --max-unused-days 90 --output report.json
        """)
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--input-file", help="Pre-downloaded authorization details JSON")
    parser.add_argument("--output", default="least_privilege_report.json",
                        help="Output report file (default: least_privilege_report.json)")
    parser.add_argument("--check-unused", action="store_true",
                        help="[Stage 2] Enable Access Advisor check for unused services")
    parser.add_argument("--max-unused-days", type=int, default=90,
                        help="[Stage 2] Days of inactivity to flag a service (default: 90)")
    args = parser.parse_args()

    iam_client = None

    if args.input_file:
        with open(args.input_file) as f:
            auth_details = json.load(f)
        source = args.input_file
        if args.check_unused and HAS_BOTO3:
            session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
            iam_client = session.client("iam")
    elif HAS_BOTO3:
        session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
        iam_client = session.client("iam")
        auth_details = get_account_authorization(args.profile)
        source = f"live-account (profile={args.profile or 'default'})"
    else:
        print("[!] boto3 not installed and no --input-file provided")
        return

    stages_run = ["stage1_static_analysis"]
    if args.check_unused:
        stages_run.append("stage2_access_advisor")

    print(f"[*] Running stages: {', '.join(stages_run)}")
    print(f"[*] Analyzing {len(auth_details.get('UserDetailList', []))} users, "
          f"{len(auth_details.get('RoleDetailList', []))} roles, "
          f"{len(auth_details.get('GroupDetailList', []))} groups")

    findings = analyze_account(
        auth_details,
        iam_client=iam_client,
        check_unused=args.check_unused,
        max_unused_days=args.max_unused_days,
    )

    report = generate_report(findings, source, stages_run)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)

    # Print summary
    print(f"\n{'='*60}")
    print(f"  LEAST PRIVILEGE ANALYSIS REPORT")
    print(f"{'='*60}")
    print(f"  Principals with findings: {len(findings)}")
    sev = report["severity_summary"]
    print(f"  Critical: {sev.get('critical', 0)} | High: {sev.get('high', 0)} | "
          f"Medium: {sev.get('medium', 0)} | Low: {sev.get('low', 0)}")
    print()
    for f_entry in findings:
        ptype = f_entry['principal_type']
        pname = f_entry['principal_name']
        esc_count = len(f_entry.get('escalation_paths', []))
        wc_count = len(f_entry.get('wildcard_findings', []))
        rw_count = len(f_entry.get('resource_wildcard_findings', []))
        us_count = len(f_entry.get('unused_services', []))
        denied = f_entry.get('denied_actions', [])
        print(f"  [{ptype}] {pname}")
        if denied:
            print(f"    Denied actions (Explicit Deny): {len(denied)} actions")
        if esc_count:
            print(f"    Escalation paths: {esc_count}")
        if wc_count:
            print(f"    Wildcard warnings: {wc_count}")
        if rw_count:
            print(f"    Sensitive Resource:* warnings: {rw_count}")
        if us_count:
            print(f"    Unused services: {us_count}")
        print()

    print(f"  Report saved to: {args.output}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
