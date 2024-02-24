import os
import argparse
import json
import getpass
import urllib.parse
from configparser import ConfigParser
import time

import boto3
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from seleniumwire import webdriver


############### Logging Functions ###############

def log(message):
    """Prints a log message."""
    print(f"[LOG] {message}")

def error(message):
    """Prints an error message."""
    print(f"[ERROR] {message}")

def success(message):
    """Prints a success message."""
    print(f"[SUCCESS] {message}")

############### Configuration Loading ###############

def load_configuration(args):
    """
    Loads configuration from a JSON file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        dict: Configuration settings.
    """

    try:
        with open(args.config, 'r') as f:
            config = json.load(f)
        log("Configuration loaded successfully.")

        # Override Configuration with Command Line Arguments
        if args.duration is not None:
            config["duration_seconds"] = args.duration
        if args.sso_url is not None:
            config["sso_url"] = args.sso_url
        if args.role_arn is not None:
            config["role_arn"] = args.role_arn
        if args.principal_arn is not None:
            config["principal_arn"] = args.principal_arn
        if args.userid is not None:
            config["userid"] = args.userid
        if args.profile_name is not None:
            config["profile_name"] = args.profile_name
        if args.store_in_env is not None:
            config["store_in_env"] = args.store_in_env

        return config
    except Exception as e:
        error(f"Failed to load configuration: {str(e)}")
        return None

############### Command Line Arguments ###############

def process_command_line_args():
    """
    Parses command-line arguments.

    Returns:
        Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Login to SSO portal and obtain AWS access tokens")
    parser.add_argument("--config", default="config.json", help="Path to the configuration file (default: config.json)")
    parser.add_argument("--duration", type=int, default=14400, help="Duration in seconds for the temporary credentials (default: 14400 seconds)")
    parser.add_argument("--sso-url", help="Optional if in config: SSO login URL")
    parser.add_argument("--role-arn", help="Optional if in config: ARN of the IAM role to assume")
    parser.add_argument("--principal-arn", help="Optional if in config: ARN of the SAML provider")
    parser.add_argument("--userid", help="Optional if in config: SSO User ID")
    parser.add_argument("--profile-name", default="default", help="Optional: The name of the AWS profile ~/.aws/credentials file")
    parser.add_argument("--store-in-env", action="store_true", help="Optional: Store AWS credentials in environment variables (Default: False)")
    return parser.parse_args()

############### Configuration Validation ###############

def get_required_config(config, *keys):
    """
    Retrieves required configuration values.

    Args:
        config (dict): Configuration settings.
        *keys (str): Configuration keys to retrieve.

    Returns:
        tuple: Values of the requested configuration keys.
    """
    for key in keys:
        if key not in config or config[key] is None:
            error(f"{key.upper()} is required in the configuration.")
            return None
    return tuple(config[key] for key in keys)

############### SSO Login ###############

def login_and_return_saml_response(sso_url, userid, password):
    """
    Logs into the SSO portal and returns the SAML assertion.

    Args:
        sso_url (str): The URL of the SSO portal.
        userid (str): The SSO USER ID.
        password (str): The user's password.

    Returns:
        str: The SAML assertion obtained after successful login.
    """
    try:
        log("Logging into the SSO portal...")
        chrome_options = Options()
        chrome_options.add_argument("--ignore-urlfetcher-cert-requests")
        # chrome_options.add_argument("--headless")

        # Initialize the WebDriver with seleniumwire
        driver = webdriver.Chrome(options=chrome_options)

        # Navigate to the SSO login page
        driver.get(sso_url)
        username_input = driver.find_element(By.ID, "identifierInput")
        username_input.send_keys(userid)

        # Click on the login button
        next_button = driver.find_element(By.ID, "submitBtn")
        next_button.click()

        # Fill in the password field
        password_input = driver.find_element(By.ID, "password")
        password_input.send_keys(password)

        # Click on the login button
        login_button = driver.find_element(By.CSS_SELECTOR, "input[value='Login']")
        login_button.click()

        # Wait for the SAML POST request to be captured
        WebDriverWait(driver, 1800).until(EC.url_contains("signin.aws.amazon.com/saml"))

        saml_response = None
        for request in driver.requests:
            if request.url == "https://signin.aws.amazon.com/saml" and request.method == 'POST':
                params = urllib.parse.parse_qs(request.body.decode())
                saml_response = params.get('SAMLResponse')[0]

        success("Login successful.")
        return saml_response

    except Exception as e:
        error(f"Failed to login: {str(e)}")
        return None

############### AWS STS Tokens ###############

def get_sts_tokens(saml_assertion, role_arn, principal_arn, duration_seconds):
    """
    Exchanges SAML assertion for AWS STS tokens.

    Args:
        saml_assertion (str): The SAML assertion obtained after SSO login.
        role_arn (str): The ARN of the IAM role to assume.
        principal_arn (str): The ARN of the SAML identity provider.
        duration_seconds (int): The duration, in seconds, for which the temporary credentials should remain valid.

    Returns:
        dict: Temporary AWS credentials.
    """
    try:
        log("Exchanging SAML assertion for AWS STS tokens...")
        sts_client = boto3.client('sts')
        response = sts_client.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=principal_arn,
            SAMLAssertion=saml_assertion,
            DurationSeconds=duration_seconds
        )
        credentials = response['Credentials']
        success("STS tokens obtained successfully.")
        return credentials

    except Exception as e:
        error(f"Failed to exchange SAML assertion for AWS STS tokens: {str(e)}")
        return None

############### Writing AWS Credentials ###############

def write_aws_credentials(access_key_id, secret_access_key, session_token=None, profile_name="default", store_in_env=False):
    """
    Writes AWS credentials to the credentials file and optionally sets them as environment variables.

    Args:
        access_key_id (str): The AWS access key ID.
        secret_access_key (str): The AWS secret access key.
        session_token (str, optional): The session token.
        profile_name (str, optional): The name of the AWS profile.
        store_in_env (bool, optional): Whether to store the credentials in environment variables.
    """
    try:
        log("Writing AWS credentials")

        # Get user's home directory
        home_dir = os.path.expanduser("~")

        # Create ~/.aws directory if it doesn't exist
        aws_dir = os.path.join(home_dir, '.aws')
        os.makedirs(aws_dir, exist_ok=True)

        # Create ConfigParser instance
        config = ConfigParser()

        # Load existing credentials file if it exists
        credentials_file = os.path.join(aws_dir, 'credentials')
        if os.path.exists(credentials_file):
            config.read(credentials_file)

        # Create or update profile with provided credentials
        if profile_name not in config:
            config.add_section(profile_name)
        config.set(profile_name, 'aws_access_key_id', access_key_id)
        config.set(profile_name, 'aws_secret_access_key', secret_access_key)
        if session_token:
            config.set(profile_name, 'aws_session_token', session_token)

        # Write updated credentials to file
        with open(credentials_file, 'w') as configfile:
            config.write(configfile)

        # Store in OS env if set in args
        if store_in_env:
            os.environ['AWS_ACCESS_KEY_ID'] = access_key_id
            os.environ['AWS_SECRET_ACCESS_KEY'] = secret_access_key
            if session_token:
                os.environ['AWS_SESSION_TOKEN'] = session_token
            else:
                os.environ.pop('AWS_SESSION_TOKEN', None)
        success("AWS credentials written successfully.")

    except Exception as e:
        error(f"Failed to write AWS credentials: {str(e)}")


def main():
    print("****************************************************")
    print("* AWS SSO Session Token Exchange *")
    print("****************************************************\n")

    ############### Load Configuration ###############
    args = process_command_line_args()
    config = load_configuration(args)
    if config is None:
        exit(1)

    ############### Validate Configuration ###############
    required_config = get_required_config(config, "duration_seconds", "sso_url", "role_arn", "principal_arn")
    if required_config is None:
        exit(1)
    duration_seconds, sso_url, role_arn, principal_arn = required_config

    ############### User Input ###############
    userid = config.get("userid")
    if not userid:
        userid = input("Enter your SSO USERID: ")
    password = config.get("password")
    if not password:
        password = getpass.getpass(prompt="Enter your SSO PASSWORD: ")

    ############### Print Configuration ###############
    print()
    log("Configuration settings:")
    for key, value in config.items():
        log(f"{key}: {value}")
    print()

    ############### SSO Login ###############
    saml_assertion = login_and_return_saml_response(sso_url, userid, password)
    if saml_assertion is None:
        exit(1)

    ############### Get AWS STS Tokens ###############
    sts_tokens = get_sts_tokens(saml_assertion, role_arn, principal_arn, duration_seconds)
    if sts_tokens is None:
        exit(1)

    ############### Write AWS Credentials ###############
    write_aws_credentials(sts_tokens['AccessKeyId'], sts_tokens['SecretAccessKey'], sts_tokens.get('SessionToken'), store_in_env=config.get("store_in_env", False))

    success("Program execution completed.")
    print("\n****************************************************")
    print("* End of execution. *")
    print("****************************************************")

############### Main Function ###############

if __name__ == "__main__":
    main()
