import os
import argparse
import json
import getpass
from configparser import ConfigParser

import boto3
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager


def log(message):
    print(f"[LOG] {message}")


def error(message):
    print(f"[ERROR] {message}")


def success(message):
    print(f"[SUCCESS] {message}")


def load_configuration(args):
    try:
        with open(args.config, "r") as f:
            config = json.load(f)

        log("Configuration loaded successfully.")

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


def process_command_line_args():
    parser = argparse.ArgumentParser(
        description="Login to SSO portal and obtain AWS access tokens"
    )

    parser.add_argument("--config", default="config.json")
    parser.add_argument("--duration", type=int, default=14400)
    parser.add_argument("--sso-url")
    parser.add_argument("--role-arn")
    parser.add_argument("--principal-arn")
    parser.add_argument("--userid")
    parser.add_argument("--profile-name", default="default")
    parser.add_argument("--store-in-env", action="store_true")

    return parser.parse_args()


def get_required_config(config, *keys):
    for key in keys:
        if key not in config or config[key] is None:
            error(f"{key.upper()} is required in the configuration.")
            return None

    return tuple(config[key] for key in keys)


def login_and_return_saml_response(sso_url, userid, password):
    driver = None

    try:
        log("Logging into the SSO portal...")

        chrome_options = Options()
        chrome_options.add_argument("--start-maximized")

        # Use normal Selenium, not Selenium Wire.
        service = Service(ChromeDriverManager().install())

        driver = webdriver.Chrome(
            service=service,
            options=chrome_options
        )

        driver.get(sso_url)

        username_input = WebDriverWait(driver, 60).until(
            EC.presence_of_element_located((By.ID, "identifierInput"))
        )
        username_input.send_keys(userid)

        next_button = driver.find_element(By.ID, "submitBtn")
        next_button.click()

        password_input = WebDriverWait(driver, 60).until(
            EC.presence_of_element_located((By.ID, "password"))
        )
        password_input.send_keys(password)

        login_button = driver.find_element(By.CSS_SELECTOR, "input[value='Login']")
        login_button.click()

        # Wait until the SAMLResponse field exists on the AWS SAML form.
        saml_element = WebDriverWait(driver, 1800).until(
            EC.presence_of_element_located((By.NAME, "SAMLResponse"))
        )

        saml_response = saml_element.get_attribute("value")

        if not saml_response:
            error("SAMLResponse field was found, but it was empty.")
            return None

        success("Login successful.")
        return saml_response

    except Exception as e:
        error(f"Failed to login: {str(e)}")
        return None

    finally:
        if driver:
            driver.quit()


def get_sts_tokens(saml_assertion, role_arn, principal_arn, duration_seconds):
    try:
        log("Exchanging SAML assertion for AWS STS tokens...")

        sts_client = boto3.client("sts")

        response = sts_client.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=principal_arn,
            SAMLAssertion=saml_assertion,
            DurationSeconds=duration_seconds
        )

        success("STS tokens obtained successfully.")
        return response["Credentials"]

    except Exception as e:
        error(f"Failed to exchange SAML assertion for AWS STS tokens: {str(e)}")
        return None


def write_aws_credentials(
    access_key_id,
    secret_access_key,
    session_token=None,
    profile_name="default",
    store_in_env=False
):
    try:
        log("Writing AWS credentials...")

        aws_dir = os.path.join(os.path.expanduser("~"), ".aws")
        os.makedirs(aws_dir, exist_ok=True)

        credentials_file = os.path.join(aws_dir, "credentials")

        config = ConfigParser()

        if os.path.exists(credentials_file):
            config.read(credentials_file)

        if profile_name not in config:
            config.add_section(profile_name)

        config.set(profile_name, "aws_access_key_id", access_key_id)
        config.set(profile_name, "aws_secret_access_key", secret_access_key)

        if session_token:
            config.set(profile_name, "aws_session_token", session_token)

        with open(credentials_file, "w") as configfile:
            config.write(configfile)

        if store_in_env:
            os.environ["AWS_ACCESS_KEY_ID"] = access_key_id
            os.environ["AWS_SECRET_ACCESS_KEY"] = secret_access_key

            if session_token:
                os.environ["AWS_SESSION_TOKEN"] = session_token
            else:
                os.environ.pop("AWS_SESSION_TOKEN", None)

        success("AWS credentials written successfully.")

    except Exception as e:
        error(f"Failed to write AWS credentials: {str(e)}")


def main():
    print("****************************************************")
    print("* AWS SSO Session Token Exchange *")
    print("****************************************************\n")

    args = process_command_line_args()

    config = load_configuration(args)
    if config is None:
        exit(1)

    required_config = get_required_config(
        config,
        "duration_seconds",
        "sso_url",
        "role_arn",
        "principal_arn"
    )

    if required_config is None:
        exit(1)

    duration_seconds, sso_url, role_arn, principal_arn = required_config

    userid = config.get("userid")
    if not userid:
        userid = input("Enter your SSO USERID: ")

    password = config.get("password")
    if not password:
        password = getpass.getpass(prompt="Enter your SSO PASSWORD: ")

    profile_name = config.get("profile_name", "default")
    store_in_env = config.get("store_in_env", False)

    print()
    log("Configuration settings:")
    for key, value in config.items():
        if key.lower() == "password":
            log(f"{key}: ********")
        else:
            log(f"{key}: {value}")
    print()

    saml_assertion = login_and_return_saml_response(
        sso_url,
        userid,
        password
    )

    if saml_assertion is None:
        exit(1)

    sts_tokens = get_sts_tokens(
        saml_assertion,
        role_arn,
        principal_arn,
        duration_seconds
    )

    if sts_tokens is None:
        exit(1)

    write_aws_credentials(
        sts_tokens["AccessKeyId"],
        sts_tokens["SecretAccessKey"],
        sts_tokens.get("SessionToken"),
        profile_name=profile_name,
        store_in_env=store_in_env
    )

    success("Program execution completed.")

    print("\n****************************************************")
    print("* End of execution. *")
    print("****************************************************")


if __name__ == "__main__":
    main()
