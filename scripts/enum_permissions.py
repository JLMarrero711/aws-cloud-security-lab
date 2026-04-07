import boto3
import urllib.request


def get_instance_role():
    """Try to fetch the IAM role attached to this EC2 instance."""
    try:
        # Grab IMDSv2 token first
        req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            method="PUT",
        )
        token = urllib.request.urlopen(req).read().decode()

        # Use token to get role name
        req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            headers={"X-aws-ec2-metadata-token": token},
        )
        role = urllib.request.urlopen(req).read().decode().strip()

        print(f"[+] Found IAM role: {role}")
        return role

    except Exception as err:
        print(f"[-] Failed to get IAM role: {err}")
        return None


def enumerate_role_policies(role_name):
    """Print managed policies attached to the role."""
    iam = boto3.client("iam")

    print("\n[+] Managed policies:")
    try:
        res = iam.list_attached_role_policies(RoleName=role_name)
        policies = res.get("AttachedPolicies", [])

        if not policies:
            print("    (none)")
            return []

        for p in policies:
            print(f"    - {p['PolicyName']} ({p['PolicyArn']})")

        return policies

    except Exception as err:
        print(f"    Error listing policies: {err}")
        return []


def enumerate_inline_policies(role_name):
    """Print inline policies and their contents."""
    iam = boto3.client("iam")

    print("\n[+] Inline policies:")
    try:
        res = iam.list_role_policies(RoleName=role_name)
        names = res.get("PolicyNames", [])

        if not names:
            print("    (none)")
            return

        for name in names:
            print(f"\n    Policy: {name}")

            doc = iam.get_role_policy(
                RoleName=role_name, PolicyName=name
            )["PolicyDocument"]

            for stmt in doc.get("Statement", []):
                effect = stmt.get("Effect")
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])

                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                print(f"      Effect: {effect}")
                print(f"      Actions: {', '.join(actions)}")
                print(f"      Resources: {', '.join(resources)}")

    except Exception as err:
        print(f"    Error reading inline policies: {err}")


def check_dangerous_permissions(role_name):
    """Look for permissions that might be risky."""
    iam = boto3.client("iam")

    risky = {
        "iam:*": "Full IAM control",
        "iam:CreateAccessKey": "Create access keys",
        "iam:AttachRolePolicy": "Attach policies to roles",
        "iam:PutRolePolicy": "Add inline policies",
        "s3:GetObject": "Read S3 objects",
        "s3:*": "Full S3 access",
        "ec2:*": "Full EC2 control",
        "secretsmanager:GetSecretValue": "Read secrets",
        "lambda:InvokeFunction": "Invoke Lambda",
        "sts:AssumeRole": "Assume other roles",
    }

    print("\n[+] Checking for risky permissions:")

    try:
        # Check managed policies
        attached = iam.list_attached_role_policies(RoleName=role_name)

        for p in attached.get("AttachedPolicies", []):
            policy = iam.get_policy(PolicyArn=p["PolicyArn"])
            version = policy["Policy"]["DefaultVersionId"]

            doc = iam.get_policy_version(
                PolicyArn=p["PolicyArn"], VersionId=version
            )["PolicyVersion"]["Document"]

            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue

                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                for action in actions:
                    if action in risky:
                        print(f"    [!] {action} -> {risky[action]}")

        # Check inline policies
        inline = iam.list_role_policies(RoleName=role_name)

        for name in inline.get("PolicyNames", []):
            doc = iam.get_role_policy(
                RoleName=role_name, PolicyName=name
            )["PolicyDocument"]

            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue

                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                for action in actions:
                    if action in risky:
                        print(f"    [!] {action} -> {risky[action]}")

    except Exception as err:
        print(f"    Error during permission check: {err}")


if __name__ == "__main__":
    print("=" * 50)
    print("IAM Role Permission Enumerator")
    print("=" * 50)

    role = get_instance_role()

    if role:
        enumerate_role_policies(role)
        enumerate_inline_policies(role)
        check_dangerous_permissions(role)

    print("\n" + "=" * 50)
    print("Done")
    print("=" * 50)