# DCDR API Documentation

This document provides detailed information about the DCDR API endpoints.

## Authentication

Most API endpoints require authentication. Authentication can be done via a bearer token in the `Authorization` header or a session cookie.

- **Bearer Token**: `Authorization: Bearer <token>`
- **Session Cookie**: `dcdr-session`

## API Endpoints

### Unauthenticated Endpoints

#### `POST /api/dcdrAuth`

Authenticates a user or application and returns a session token.

- **Request Body**:
  ```json
  {
    "token": "your-api-token"
  }
  ```
- **Responses**:
  - `200 OK`: Authentication successful.
  - `401 Unauthorized`: Authentication failed.

#### `GET /api/dcdrIdent`

Returns a dummy instance ID.

- **Responses**:
  - `200 OK`:
    ```json
    {
      "instance_id": "dummy-instance-id"
    }
    ```

#### `GET /api/health`

Health check endpoint.

- **Responses**:
  - `200 OK`:
    ```json
    {
      "status": "ok"
    }
    ```

### Authenticated Endpoints

#### `POST /api/dcdrRegister`

Registers a new application. (Root only)

- **Request Body**:
  ```json
  {
    "app_name": "my-new-app"
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "app_id": "generated-app-id"
    }
    ```
  - `403 Forbidden`: Permission denied.

#### `POST /api/dcdrCreateSecret`

Creates or updates a secret in a specified backend.

- **Request Body**:
  ```json
  {
    "app_id": "your-app-id",
    "secret_name": "my-secret",
    "backend": "vault-1",
    "mount_path": "secret",
    "data": {
      "key1": "value1",
      "key2": "value2"
    }
  }
  ```
- **Responses**:
  - `200 OK`: Secret created/updated successfully.
  - `400 Bad Request`: Invalid request body.
  - `403 Forbidden`: Permission denied.
  - `500 Internal Server Error`: Error creating/updating secret.

#### `POST /api/dcdrGet`

Retrieves a secret from a backend.

- **Request Body**:
  ```json
  {
    "app_id": "your-app-id",
    "secret_name": "my-secret"
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "key1": "value1",
      "key2": "value2"
    }
    ```
  - `403 Forbidden`: Permission denied or secret is tainted.
  - `404 Not Found`: Secret not found.

#### `POST /api/dcdrTaint`

Taints a secret, suspending access to it.

- **Request Body**:
  ```json
  {
    "app_id": "your-app-id",
    "secret_name": "my-secret"
  }
  ```
- **Responses**:
  - `200 OK`: Secret tainted successfully.
  - `403 Forbidden`: Permission denied.
  - `404 Not Found`: Secret not found.

#### `POST /api/dcdrUntaint`

Untaints a secret, restoring access.

- **Request Body**:
  ```json
  {
    "app_id": "your-app-id",
    "secret_name": "my-secret"
  }
  ```
- **Responses**:
  - `200 OK`: Secret untainted successfully.
  - `403 Forbidden`: Permission denied.
  - `404 Not Found`: Secret not found.

#### `POST /api/dcdrDestroy`

Deletes a secret from the backend.

- **Request Body**:
  ```json
  {
    "app_id": "your-app-id",
    "secret_name": "my-secret"
  }
  ```
- **Responses**:
  - `200 OK`: Secret deleted successfully.
  - `403 Forbidden`: Permission denied.
  - `404 Not Found`: Secret not found.

#### `POST /api/dcdrIsTainted`

Checks if a secret is tainted.

- **Request Body**:
  ```json
  {
    "app_id": "your-app-id",
    "secret_name": "my-secret"
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "tainted": true
    }
    ```
  - `404 Not Found`: Secret not found.

#### `POST /api/dcdrRotate`

Rotates a secret. (Not implemented)

- **Responses**:
  - `501 Not Implemented`

#### `GET /api/dcdrListApps`

Lists applications.

- **Responses**:
  - `200 OK`:
    ```json
    [
      {
        "app_id": "app-id-1",
        "app_name": "app-1"
      },
      {
        "app_id": "app-id-2",
        "app_name": "app-2"
      }
    ]
    ```

#### `POST /api/dcdrListSecrets`

Lists secrets for an application.

- **Request Body**:
  ```json
  {
    "app_id": "your-app-id"
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    [
      {
        "secret_name": "secret-1",
        "backend": "vault-1",
        "mount_path": "secret",
        "tainted": false
      }
    ]
    ```

#### `GET /api/dcdrListBackends`

Lists available backends.

- **Responses**:
  - `200 OK`:
    ```json
    [
      {
        "backend": "vault-1",
        "num_applications": 1,
        "num_secrets": 1,
        "type": "vault"
      }
    ]
    ```

#### `POST /api/dcdrDeleteApp`

Deletes an application. (Root only)

- **Request Body**:
  ```json
  {
    "app_id": "app-to-delete-id"
  }
  ```
- **Responses**:
  - `200 OK`: Application deleted successfully.
  - `403 Forbidden`: Permission denied.
  - `409 Conflict`: Cannot delete app with associated secrets.

#### `GET /api/dcdrWhoami`

Returns information about the current user/application.

- **Responses**:
  - `200 OK` (for root user):
    ```json
    {
      "user_id": 1,
      "user_name": "root",
      "is_root": true
    }
    ```
  - `200 OK` (for application user):
    ```json
    {
      "user_id": "user-id",
      "user_name": "app-user",
      "app_id": "app-id",
      "app_name": "my-app",
      "is_root": false
    }
    ```

#### `GET /api/dcdrAudit/download`

Downloads the audit log as a zip file. (Root only)

- **Query Parameters**:
  - `format`: `csv` (default) or `json`
- **Responses**:
  - `200 OK`: A zip file containing the audit logs.
  - `403 Forbidden`: Permission denied.

#### `GET /api/dcdrAudit/stream`

Streams the audit log via WebSocket. (Root only)

### Application User Management

These endpoints are for managing application users and require root privileges.

#### `POST /api/dcdrAppUser/create`

Creates a new application user.

- **Request Body**:
  ```json
  {
    "app_id": "your-app-id",
    "user_name": "new-app-user"
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "user_id": "generated-user-id",
      "token": "generated-token"
    }
    ```
  - `403 Forbidden`: Permission denied.

#### `GET /api/dcdrAppUser/list`

Lists application users for an application.

- **Query Parameters**:
  - `app_id`: The ID of the application.
- **Responses**:
  - `200 OK`:
    ```json
    [
      {
        "user_id": "user-id-1",
        "user_name": "user-1",
        "status": "active"
      }
    ]
    ```
  - `403 Forbidden`: Permission denied.

#### `POST /api/dcdrAppUser/suspend`

Suspends an application user.

- **Request Body**:
  ```json
  {
    "user_id": "user-to-suspend-id"
  }
  ```
- **Responses**:
  - `200 OK`: User suspended successfully.
  - `403 Forbidden`: Permission denied.

#### `POST /api/dcdrAppUser/unsuspend`

Unsuspends an application user.

- **Request Body**:
  ```json
  {
    "user_id": "user-to-unsuspend-id"
  }
  ```
- **Responses**:
  - `200 OK`: User unsuspended successfully.
  - `403 Forbidden`: Permission denied.

#### `POST /api/dcdrAppUser/delete`

Deletes an application user.

- **Request Body**:
  ```json
  {
    "user_id": "user-to-delete-id"
  }
  ```
- **Responses**:
  - `200 OK`: User deleted successfully.
  - `403 Forbidden`: Permission denied.

#### `POST /api/dcdrAppUser/getToken`

Gets a new token for an application user.

- **Request Body**:
  ```json
  {
    "user_id": "user-id"
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "token": "new-generated-token"
    }
    ```
  - `403 Forbidden`: Permission denied.

### UI Endpoints

These endpoints are used by the web UI.

#### `GET /api/ui/backends`

Lists backends for the UI.

#### `GET /api/ui/applications`

Lists applications for the UI.

#### `GET /api/ui/applications/:id/secrets`

Lists secrets for an application for the UI.

#### `GET /api/ui/user`

Gets user information for the UI.

#### `POST /api/logout`

Logs out the user and clears the session cookie.
