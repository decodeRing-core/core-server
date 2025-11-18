<a name="top"></a>
[![decodeRing Core Server](https://decodering.org/wp-content/uploads/2025/11/Git-Banner-2-scaled.png)](https://decodering.org)
![Go](https://img.shields.io/badge/Go-1.24.4-blue) ![OS](https://img.shields.io/badge/OS-Linux_Windows_MacOS-green) ![CPU](https://img.shields.io/badge/CPU-x64-FF8C00) ![Release](https://img.shields.io/badge/Release-v0.1.0-blue) ![Release Date](https://img.shields.io/badge/Release_Date-November_2025-blue) ![License](https://img.shields.io/badge/License-Apache_2.0-blue)

> [!IMPORTANT]
> This is an alpha release and is not intended for production use. There are a number of features that need to be completed before the decodeRing server can be used in a production capacity.

⭐ Star us on GitHub — your support means a lot to us! 🙏😊

## Table of Contents
- [About](#-about)
- [What's New](#-whats-new)
- [Usage](#-usage)
- [Documentation](#-documentation)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [How to Build](#-how-to-build)
- [Roadmap](#-roadmap)
- [Feedback & Contributions](#-feedback--contributions)
- [License](#-license)
- [Contacts](#-contacts)

## 🚀 About
decodeRing is an open-source security orchestration layer written in Go that de-risks and accelerates secrets vault consolidation across clouds and vendors. decodeRing does this by implementing the [dcdr open standard](https://github.com/decodeRing-core/dcdr-standard) via RESTful API.

This allows developers to focus on coding instead of learning how to interact with multiple secrets back-ends. By abstracting away the complexity of the back-end secrets vaults decodeRing reduces friction for developers and provides SECOPS teams with the tools they need to consolidate their secrets landscape.

The 'dcdr-server' comes accompanied with the `dcdr` CLI tool that allows users and administrators to interact with the server.

## ✨ What's New

### Version 0.1.0-alpha (Latest)

💻 **Simple Admin UI**

![Admin UI](https://decodering.org/wp-content/uploads/2025/11/Screenshot-2025-11-17-at-10.43.08-AM-scaled.png)

🚀 **Supported Secrets Back-Ends**

- HashiCorp Vault
- OpenBao
- AWS Secrets Manager
- Azure Key Vault
- GCP Secret Manager

💾 **Available SDKs**

- [Go](https://github.com/decodeRing-core/dcdr-go-sdk)
- [Python](https://github.com/decodeRing-core/dcdr-python-sdk)

📖 **Swagger API Docs**

![Swagger API Docs](https://decodering.org/wp-content/uploads/2025/11/Screenshot-2025-11-17-at-10.45.29-AM.png)

## 📘 Usage

### Server

The server can be configured via a configuration file and/or environment variables. Command-line flags take precedence over environment variables.

#### Server Flags

- `--config <path>`: Path to the server configuration file. Defaults to `config/server.cfg`.

#### Server Commands

`dcdr-server generate-ssl [--out <path>]`
: Generates a self-signed SSL certificate and private key for the server. The optional `--out` flag specifies the directory where the files will be created. Defaults to `config/ssl`.

`dcdr-server verify`
: Verifies the connection to all configured backends.

#### Server Configuration (Environment Variables)

##### General
- `DCDR_PORT`: The port for the server to listen on.
- `DCDR_USE_SSL`: Set to `true` to enable SSL.
- `DCDR_SSL_CERT_FILE`: Path to the SSL certificate file.
- `DCDR_SSL_KEY_FILE`: Path to the SSL key file.
- `DCDR_SKIP_VERIFY`: Set to `true` to skip SSL certificate verification for backend connections.

##### Database
- `DB_USER`: Database user.
- `DB_PASSWORD`: Database password.
- `DB_NAME`: Database name.
- `DB_HOST`: Database host.
- `DB_PORT`: Database port.

##### Logging
- `DCDR_ACCESS_LOG`: Path to the access log file.
- `DCDR_ERROR_LOG`: Path to the error log file.
- `DCDR_AUDIT_ENABLED`: Set to `true` to enable audit logging.
- `DCDR_AUDIT_RETENTION`: Duration to retain audit logs (e.g., "24h", "30d").
- `DCDR_AUDIT_CLEANUP_INTERVAL`: How often to run the audit log cleanup (e.g., "1h").

##### Backend Specific
The server supports multiple secret manager backends. Configuration for each is also done via environment variables, typically prefixed with the backend type (e.g., `VAULT_`, `BAO_`, `AWS_`, `AZURE_`, `CONJUR_`). Refer to the backend's documentation for specific variables.

### Client

`dcdr` is a CLI client for interacting with the dcdr server.

#### Global Flags & Environment Variables

- `--skip-verify` or `DCDR_SKIP_VERIFY=true`: Skip SSL certificate verification.
- `DCDR_ADDR`: The address of the dcdr server (e.g., `https://localhost:8301`).
- `DCDR_TOKEN`: The authentication token. The client will also cache this token in `~/.dcdr/token`.

#### Client Commands

##### Core Commands
- `dcdr ident`: Get the server instance ID.
- `dcdr auth --token <token>`: Authenticate with the server.
- `dcdr whoami [--table]`: Print the current user's information.
- `dcdr logout`: Log out the current user by deleting the cached token.

##### Application Management
- `dcdr register --name <app_name>`: Register a new application.
- `dcdr list-apps [--table]`: List registered applications.
- `dcdr delete-app --appid <app_id>`: Delete an application.

##### Secret Management
- `dcdr create --appid <app_id> --name <secret_name> --backend <backend> --mount <mount_path> --data '{"key":"value"}'`: Create a secret.
- `dcdr get --appid <app_id> --name <secret_name>`: Get a secret.
- `dcdr list-secrets --appid <app_id>`: List secrets for an application.
- `dcdr taint --appid <app_id> --name <secret_name>`: Taint a secret, suspending access.
- `dcdr untaint --appid <app_id> --name <secret_name>`: Untaint a secret, restoring access.
- `dcdr istainted --appid <app_id> --name <secret_name>`: Check if a secret is tainted.
- `dcdr destroy --appid <app_id> --name <secret_name>`: Destroy a secret from the backend.

##### Backend Management
- `dcdr list-backends`: List configured backends and their stats.

##### Application User Management (`dcdr app-user ...`)
- `dcdr app-user create --appid <app_id> --name <user_name>`: Create a user for an application.
- `dcdr app-user list-users [--table]`: List all application users.
- `dcdr app-user suspend-user --userid <user_id>`: Suspend an application user.
- `dcdr app-user unsuspend-user --userid <user_id>`: Unsuspend an application user.
- `dcdr app-user delete-user --userid <user_id>`: Delete an application user.
- `dcdr app-user get-token --userid <user_id>`: Get a new token for an application user.

##### Audit Log Management
- `dcdr download-audit-logs [--json | --csv] [--out <filename>]`: Download the audit log bundle.


## 📚 Documentation

- [dcdr-server man page](https://decodering.org)
- [dcdr man page](https://decodering.org)

## 📐 Architecture

![High level architecture](https://decodering.org/wp-content/uploads/2025/11/high-level-arch.excalidraw-scaled.png)

## 💾 Installation

- [EL9 RPMs](https://decodering.org)

## 🔨 How to Build

```shell
# Open a terminal (Command Prompt or PowerShell for Windows, Terminal for macOS or Linux)

# Ensure Git is installed
# Visit https://git-scm.com to download and install console Git if not already installed

# Clone the repository
git clone https://github.com/decodeRing-core/core-server.git

# Navigate to the project directory
cd core-server

# Check if GoLang >=1.24 is installed
go version 
# Visit the official go.dev website to install or update if necessary

# Fetch dependencies
go mod init

# Compile the project
make build

```

## 🚗 Roadmap

TBD

## 🤝 Feedback & Contributions

We've made every effort to provide documentation to help users stand up a test instance of decodeRing. However, if you have problems please reach out!

> [!IMPORTANT]
> Whether you have feedback on features, have encountered a bug or have suggestions for enhancements, we're eager to hear from you! Your insights help us make decodeRing more robust and usable.

Please feel free to contribute by [submitting an issue](https://github.com/decodeRing-core/core-server/issues) or [joining the discussions](https://github.com/orgs/decodeRing-core/discussions). Every contribution helps us improve decodeRing.

## 📃 License
Licensed under the Apache License, Version 2.0.

## 💬 Contacts

For more details about our products, services, or any general information regarding the decodeRing Server, feel free to reach out to us. We are here to provide support and answer any questions you may have. Below are the best ways to contact our team:

- **Email**: Send us your inquiries or support requests at [support@decodering.org](mailto:support@decodering.org).
- **Website**: Visit the official decodeRing website for more information: [decodering.org](https://decodering.org).

We look forward to assisting you and ensuring your experience with our product is successful and enjoyable!

[Back to top](#top)
