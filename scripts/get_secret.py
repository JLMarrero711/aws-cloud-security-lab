import boto3
import json
from botocore.exceptions import ClientError

def get_secret():
    secret_name = "prod/myapp/api-key"
    region_name = "us-east-2"

    client = boto3.client(
        service_name="secretsmanager",
        region_name=region_name
    )

    try:
        response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ResourceNotFoundException":
            print(f"Secret {secret_name} not found")
        elif error_code == "AccessDeniedException":
            print("IAM role does not have permission to read this secret")
        else:
            print(f"Error: {e}")
        return None

    secret = json.loads(response["SecretString"])
    return secret

if __name__ == "__main__":
    secret = get_secret()
    if secret:
        print(f"Successfully retrieved secret")
        print(f"API key starts with: {secret['api_key'][:8]}...")
