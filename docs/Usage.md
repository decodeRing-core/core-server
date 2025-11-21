# decodeRing Core usage

## Server

The server can be configured via a configuration file and/or environment variables. Command-line flags take precedence over environment variables.

### Server Flags

- `--config <path>`: Path to the server configuration file. Defaults to `config/server.cfg`.

### Server Commands

`dcdr-server generate-ssl [--out <path>]`
: Generates a self-signed SSL certificate and private key for the server. The optional `--out` flag specifies the directory where the files will be created. Defaults to `config/ssl`.

`dcdr-server verify`
: Verifies the connection to all configured backends.

### Server Configuration (Environment Variables)

#### General
- `DCDR_PORT`: The port for the server to listen on.
- `DCDR_USE_SSL`: Set to `true` to enable SSL.
- `DCDR_SSL_CERT_FILE`: Path to the SSL certificate file.
- `DCDR_SSL_KEY_FILE`: Path to the SSL key file.
- `DCDR_SKIP_VERIFY`: Set to `true` to skip SSL certificate verification for backend connections.

#### Database
- `DB_USER`: Database user.
- `DB_PASSWORD`: Database password.
- `DB_NAME`: Database name.
- `DB_HOST`: Database host.
- `DB_PORT`: Database port.

#### Logging
- `DCDR_ACCESS_LOG`: Path to the access log file.
- `DCDR_ERROR_LOG`: Path to the error log file.
- `DCDR_AUDIT_ENABLED`: Set to `true` to enable audit logging.
- `DCDR_AUDIT_RETENTION`: Duration to retain audit logs (e.g., "24h", "30d").
- `DCDR_AUDIT_CLEANUP_INTERVAL`: How often to run the audit log cleanup (e.g., "1h").

#### Backend Specific
The server supports multiple secret manager backends. Configuration for each is also done via environment variables, typically prefixed with the backend type (e.g., `VAULT_`, `BAO_`, `AWS_`, `AZURE_`, `CONJUR_`). Refer to the backend's documentation for specific variables.

## Client

`dcdr` is a CLI client for interacting with the dcdr server.

### Global Flags & Environment Variables

- `--skip-verify` or `DCDR_SKIP_VERIFY=true`: Skip SSL certificate verification.
- `DCDR_ADDR`: The address of the dcdr server (e.g., `https://localhost:8301`).
- `DCDR_TOKEN`: The authentication token. The client will also cache this token in `~/.dcdr/token`.

### Client Commands

#### Core Commands
- `dcdr ident`: Get the server instance ID.
- `dcdr auth --token <token>`: Authenticate with the server.
- `dcdr whoami [--table]`: Print the current user's information.
- `dcdr logout`: Log out the current user by deleting the cached token.

#### Application Management
- `dcdr register --name <app_name>`: Register a new application.
- `dcdr list-apps [--table]`: List registered applications.
- `dcdr delete-app --appid <app_id>`: Delete an application.

#### Secret Management
- `dcdr create --appid <app_id> --name <secret_name> --backend <backend> --mount <mount_path> --data '{"key":"value"}'`: Create a secret.
- `dcdr get --appid <app_id> --name <secret_name>`: Get a secret.
- `dcdr list-secrets --appid <app_id>`: List secrets for an application.
- `dcdr taint --appid <app_id> --name <secret_name>`: Taint a secret, suspending access.
- `dcdr untaint --appid <app_id> --name <secret_name>`: Untaint a secret, restoring access.
- `dcdr istainted --appid <app_id> --name <secret_name>`: Check if a secret is tainted.
- `dcdr destroy --appid <app_id> --name <secret_name>`: Destroy a secret from the backend.

#### Backend Management
- `dcdr list-backends`: List configured backends and their stats.

#### Application User Management (`dcdr app-user ...`)
- `dcdr app-user create --appid <app_id> --name <user_name>`: Create a user for an application.
- `dcdr app-user list-users [--table]`: List all application users.
- `dcdr app-user suspend-user --userid <user_id>`: Suspend an application user.
- `dcdr app-user unsuspend-user --userid <user_id>`: Unsuspend an application user.
- `dcdr app-user delete-user --userid <user_id>`: Delete an application user.
- `dcdr app-user get-token --userid <user_id>`: Get a new token for an application user.

#### Audit Log Management
- `dcdr download-audit-logs [--json | --csv] [--out <filename>]`: Download the audit log bundle.
