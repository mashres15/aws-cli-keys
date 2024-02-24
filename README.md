# SSO Login and AWS STS Tokens Script

The SSO Login AWS STS CLI Tool is a command-line interface (CLI) tool designed to simplify the process of logging in to Single Sign-On (SSO) portals and obtaining temporary AWS credentials using Security Token Service (STS) in an automated manner. This tool is particularly useful for developers and administrators who frequently work with AWS services and need a streamlined way to manage their AWS credentials.

## Features:

- **SSO Login Automation**: The CLI tool automates the login process to SSO portals, eliminating the need for manual intervention.
- **AWS STS Integration**: It seamlessly integrates with AWS Security Token Service (STS) to obtain temporary AWS credentials.
- **Configuration Flexibility**: Users can specify configuration options such as SSO login URL, IAM role ARN, SAML provider ARN, and more through command-line arguments or a configuration file.
- **AWS Profile Management**: The tool can write the obtained AWS credentials to the AWS credentials file (`~/.aws/credentials`) and optionally store them as environment variables for easy access.
- **Customization**: Users can customize the tool's behavior by adjusting configuration options or extending its functionality through Python scripting.


## Requirements

- Python 3.7+
- `boto3` library
- `selenium` library
- `selenium-wire` library
- Chrome WebDriver
- Chrome browser

## Installation

1. Clone the repository: git clone https://github.com/mashres15/aws-cli-keys.git
2. Navigate to the project directory: cd aws-cli-keys
3. Install the dependencies: pip install -r requirements.txt

## Usage

1. Update a `config.json` file with your SSO and AWS configuration settings. You can use the provided `config.json` as a template.
```json
{
    "duration_seconds": 14400,
    "sso_url": "https://your-sso-url.com",
    "role_arn": "arn:aws:iam::123456789012:role/YourRole",
    "principal_arn": "arn:aws:iam::123456789012:saml-provider/YourProvider",
    "profile_name": "default",
    "store_in_env": false,
    "userid": "userid"
}
```

2. Run the script: python cli --store_in_env

You can also override specific configuration settings via command-line arguments. Run `python sso_login_aws_sts.py --help` for more information.

## Configuration Options

- `duration_seconds`: Duration in seconds for the temporary credentials (default: 14400 seconds)
- `sso_url`: URL of the SSO login page
- `role_arn`: ARN of the IAM role to assume
- `principal_arn`: ARN of the SAML identity provider
- `profile_name`: Name of the AWS profile in `~/.aws/credentials` file (default: "default")
- `store_in_env`: Whether to store AWS credentials in OS environment variables (default: False)
- `userid`: username for the sso login

## Contributions:

Contributions to the project are welcome! If you encounter any issues, have feature requests, or want to contribute code, please feel free to open an issue or submit a pull request on the project's GitHub repository.

## License:

This project is licensed under the MIT License.
