# LFX v2 Auth Service

A NATS-based authentication and user management microservice for the LFX v2 platform. This service provides an abstraction layer between applications and identity providers (Auth0 and Authelia).

## Overview

The LFX v2 Auth Service provides authentication and profile access in the v2 Platform, serving as an abstraction layer between applications and identity providers (Auth0 and Authelia). This service enables user management, profile updates, email/social account linking, and user discovery while maintaining compatibility across different deployment environments.

The service operates as a NATS-based microservice, responding to request/reply patterns on specific subjects.

### Prerequisites
- Go 1.24.5+
- NATS server
- Auth0 configuration (optional, defaults to mock mode)
- Kubernetes cluster (for local Authelia development setup)

### Local Development Support

The auth-service supports **Authelia + NATS KV** integration for local development environments. This setup provides:

- **Authelia** as a local identity provider running in Kubernetes
- **NATS Key-Value store** for persistent user data storage
- **Automatic synchronization** between NATS KV and Authelia's ConfigMap/Secrets
- **DaemonSet restart capability** when user data changes require Authelia pod restarts

For detailed information about the Authelia integration architecture and sync mechanisms, see: [`internal/infrastructure/authelia`](internal/infrastructure/authelia)


### Installation

```bash
├── .github/                        # Github files
│   └── workflows/                  # Github Action workflow files
├── charts/                         # Helm charts for running the service in kubernetes
├── cmd/                            # Services (main packages)
│   └── server/                     # Auth service code
├── internal/                       # Internal service packages
│   ├── domain/                     # Domain logic layer (business logic)
│   │   ├── model/                  # Domain models and entities
│   │   └── port/                   # Repository and service interfaces
│   ├── service/                    # Service logic layer (use cases)
│   └── infrastructure/             # Infrastructure layer
├── pkg/                            # Shared packages
│   ├── constants/                  # Application constants
│   ├── converters/                 # Data conversion utilities
│   ├── errors/                     # Error handling utilities
│   ├── httpclient/                 # HTTP client utilities
│   └── log/                        # Logging utilities
└── README.md                       # This documentation
```

## Usage

### NATS Request/Reply Pattern

The LFX v2 Auth Service operates as a NATS-based microservice that responds to request/reply patterns on specific subjects. The service provides user management capabilities through NATS messaging.

---

### Email to Username Lookup

To look up a username by email address, send a NATS request to the following subject:

**Subject:** `lfx.auth-service.email_to_username`  
**Pattern:** Request/Reply

##### Request Payload

The request payload should be a plain text email address (no JSON wrapping required):

```
user@example.com
```

##### Reply

The service returns the username as plain text if the email is found:

**Success Reply:**
```
john.doe
```

**Error Reply:**
```json
{
  "success": false,
  "error": "user not found"
}
```

##### Example using NATS CLI

```bash
# Look up username by email
nats request lfx.auth-service.email_to_username zephyr.stormwind@mythicaltech.io

# Expected response: zephyr.stormwind
```

**Important Notes:**
- This service searches for users by their **primary email** only
- Linked/alternate email addresses are **not** supported for lookup
- The service works with Auth0, Authelia, and mock repositories based on configuration

---

### Email to Subject Identifier Lookup

To look up a subject identifier by email address, send a NATS request to the following subject:

**Subject:** `lfx.auth-service.email_to_sub`  
**Pattern:** Request/Reply

##### Request Payload

The request payload should be a plain text email address (no JSON wrapping required):

```
user@example.com
```

##### Reply

The service returns the subject identifier as plain text if the email is found:

**Success Reply:**
```
auth0|123456789
```

**Error Reply:**
```json
{
  "success": false,
  "error": "user not found"
}
```

##### Example using NATS CLI

```bash
# Look up subject identifier by email
nats request lfx.auth-service.email_to_sub zephyr.stormwind@mythicaltech.io

# Expected response: auth0|zephyr001
```

**Important Notes:**
- This service searches for users by their **primary email** only
- Linked/alternate email addresses are **not** supported for lookup
- The service works with Auth0, Authelia, and mock repositories based on configuration
- The returned subject identifier is the canonical user identifier used throughout the system
- For Authelia-specific SUB identifier details and how they are populated, see: [`internal/infrastructure/authelia/README.md`](internal/infrastructure/authelia/README.md)

---

### User Metadata Retrieval

To retrieve user metadata, send a NATS request to the following subject:

**Subject:** `lfx.auth-service.user_metadata.read`  
**Pattern:** Request/Reply

The service supports two lookup strategies based on the input format, providing both authoritative identification and convenient username-based searches.

##### Input Format and Strategy Selection

The service automatically determines the lookup strategy based on the input format:

- **Canonical Lookup** (contains `|`): `<connection>|<provider_user_id>` - Subject identifier
- **Search Lookup** (no `|`): `<username>` - Convenience lookup

##### Canonical Lookup Strategy (Recommended)

**Format:** `<connection>|<provider_user_id>`

The canonical lookup is the **authoritative, standard way to identify a user**, regardless of which provider they come from.

**Examples:** `auth0|123456789`, `google-oauth2|987654321`, `samlp|my-connection|user123`

##### Search Lookup Strategy (Convenience)

**Format:** `<username>`

Username lookups are **convenience only** and help avoid connection collisions within the Username-Password-Authentication connection.

**Examples:** `john.doe`, `jane.smith`, `developer123`

##### Request Payload

The request payload should be a plain text identifier (no JSON wrapping required):

**Canonical Lookup:**
```
auth0|123456789
```

**Search Lookup:**
```
john.doe
```

##### Reply

The service returns a structured reply with user metadata:

**Success Reply:**
```json
{
  "success": true,
  "data": {
    "name": "John Doe",
    "given_name": "John",
    "family_name": "Doe",
    "job_title": "Software Engineer",
    "organization": "Example Corp",
    "country": "United States",
    "state_province": "California",
    "city": "San Francisco",
    "address": "123 Main Street",
    "postal_code": "94102",
    "phone_number": "+1-555-0123",
    "t_shirt_size": "L",
    "picture": "https://example.com/avatar.jpg",
    "zoneinfo": "America/Los_Angeles"
  }
}
```

**Error Reply (User Not Found):**
```json
{
  "success": false,
  "error": "user not found"
}
```

**Error Reply (Invalid Input):**
```json
{
  "success": false,
  "error": "input is required"
}
```

##### Examples using NATS CLI

```bash
# Canonical lookup (subject identifier)
# Note: Use quotes to escape the pipe character in shell commands
nats request lfx.auth-service.user_metadata.read "auth0|123456789"

# Search lookup (convenience username lookup)
nats request lfx.auth-service.user_metadata.read john.doe

```

**Important Notes:**
- **Canonical lookups** are the preferred method for system-to-system communication
- **Search lookups** are provided for convenience and user-facing interfaces
- The pipe character (`|`) in canonical identifiers must be escaped with quotes in shell commands
- Both strategies return the same metadata format on success
- The service supports **Auth0**, **Authelia**, and **mock** repositories based on configuration
- When using mock or authelia mode, the service simulates Auth0 behavior for development and testing
- For detailed Auth0-specific behavior and limitations, see the [Auth0 Integration Documentation](internal/infrastructure/auth0/README.md)
- For detailed Authelia-specific behavior and SUB management, see the [Authelia Integration Documentation](internal/infrastructure/authelia/README.md)

---

### User Update Operation

To update a user profile, send a NATS request to the following subject:

**Subject:** `lfx.auth-service.user_metadata.update`  
**Pattern:** Request/Reply

##### Request Payload

The request payload must be a JSON object containing the user data to update. The `token` field is **required** for authentication and authorization.

```json
{
  "token": "eyJhbG...",
  "user_id": "auth0|zephyr001",
  "username": "zephyr.stormwind",
  "primary_email": "zephyr.stormwind@mythicaltech.io",
  "user_metadata": {
    "name": "Zephyr Stormwind",
    "given_name": "Zephyr",
    "family_name": "Stormwind",
    "job_title": "Cloud Architect",
    "organization": "Mythical Tech Solutions",
    "country": "Aetheria",
    "state_province": "Skylands",
    "city": "Nimbus City",
    "address": "42 Celestial Tower, Cloud District",
    "postal_code": "90210",
    "phone_number": "+1-555-STORM-01",
    "t_shirt_size": "M",
    "picture": "https://avatars.mythicaltech.io/zephyr.jpg",
    "zoneinfo": "Aetheria/Skylands"
  }
}
```

##### Required Fields

- `token`: JWT authentication token (required for all requests)
- `user_metadata`: Object containing additional user profile information

##### Reply

The service returns a structured reply indicating success or failure:

**Success Reply:**
```json
{
  "success": true,
  "data": {
    "name": "Zephyr Stormwind",
    "given_name": "Zephyr",
    "family_name": "Stormwind",
    "job_title": "Cloud Architect",
    "organization": "Mythical Tech Solutions",
    "country": "Aetheria",
    "state_province": "Skylands",
    "city": "Nimbus City",
    "address": "42 Celestial Tower, Cloud District",
    "postal_code": "90210",
    "phone_number": "+1-555-STORM-01",
    "t_shirt_size": "M",
    "picture": "https://avatars.mythicaltech.io/zephyr.jpg",
    "zoneinfo": "Aetheria/Skylands"
  }
}
```

**Error Reply:**
```json
{
  "success": false,
  "error": "username is required"
}
```

##### Example using NATS CLI

```bash
# Update user profile
nats request lfx.auth-service.user_metadata.update '{
  "token": "eyJhbG...",
  "user_metadata": {
    "name": "Aurora Moonbeam",
    "job_title": "Senior DevOps Enchanter"
  }
}'
```

**Important Notes:**
- The service works with Auth0, Authelia, and mock repositories based on configuration

#### Configuration

##### NATS Configuration

The NATS client can be configured using environment variables:

- `NATS_URL`: NATS server URL (default: `nats://localhost:4222`)
- `NATS_TIMEOUT`: Request timeout duration (default: `10s`)
- `NATS_MAX_RECONNECT`: Maximum reconnection attempts (default: `3`)
- `NATS_RECONNECT_WAIT`: Time between reconnection attempts (default: `2s`)

##### Auth0 Configuration

The Auth0 integration can be configured using environment variables:

- `USER_REPOSITORY_TYPE`: Set to `"auth0"` to use Auth0 integration, or `"mock"` for local development
  - **If not set, defaults to `"mock"`**
- `AUTH0_TENANT`: Auth0 tenant name (e.g., `"linuxfoundation"`, `"linuxfoundation-staging"`, `"linuxfoundation-dev"`)
  - **Required when using Auth0 repository type**
- `AUTH0_DOMAIN`: Auth0 domain for Management API calls (e.g., `"sso.linuxfoundation.org"`)
  - **If not set, defaults to `${AUTH0_TENANT}.auth0.com`**
- `AUTH0_CLIENT_ID`: Auth0 Machine-to-Machine application client ID
  - **Required when using Auth0 repository type**
- `AUTH0_PRIVATE_BASE64_KEY`: Base64-encoded private key for Auth0 M2M authentication
  - **Required when using Auth0 repository type**
- `AUTH0_AUDIENCE`: Auth0 API audience/identifier for the Management API
  - **Required when using Auth0 repository type**

## Releases

### Creating a Release

To create a new release of the auth service:

1. **Update the chart version** in `charts/lfx-v2-auth-service/Chart.yaml` prior to any project releases, or if any
   change is made to the chart manifests or configuration:
   ```yaml
   version: 0.2.0  # Increment this version
   appVersion: "latest"  # Keep this as "latest"
   ```

2. **After the pull request is merged**, create a GitHub release and choose the
   option for GitHub to also tag the repository. The tag must follow the format
   `v{version}` (e.g., `v0.2.0`). This tag does _not_ have to match the chart
   version: it is the version for the project release, which will dynamically
   update the `appVersion` in the released chart.

3. **The GitHub Actions workflow will automatically**:
   - Build and publish the container images (auth-service)
   - Package and publish the Helm chart to GitHub Pages
   - Publish the chart to GitHub Container Registry (GHCR)
   - Sign the chart with Cosign
   - Generate SLSA provenance

### Important Notes

- The `appVersion` in `Chart.yaml` should always remain `"latest"` in the committed code.
- During the release process, the `ko-build-tag.yaml` workflow automatically overrides the `appVersion` with the actual tag version (e.g., `v0.2.0` becomes `0.2.0`).
- Only update the chart `version` field when making releases - this represents the Helm chart version.
- The container image tags are automatically managed by the consolidated CI/CD pipeline using the git tag.
- Both container images (auth-service) and the Helm chart are published together in a single workflow.

## Development

To contribute to this repository:

1. Fork the repository
2. Commit your changes to a feature branch in your fork. Ensure your commits
   are signed with the [Developer Certificate of Origin
   (DCO)](https://developercertificate.org/).
   You can use the `git commit -s` command to sign your commits.
3. Ensure the chart version in `charts/lfx-v2-auth-service/Chart.yaml` has been
   updated following semantic version conventions if you are making changes to the chart.
4. Submit your pull request

## License

Copyright The Linux Foundation and each contributor to LFX.

This project’s source code is licensed under the MIT License. A copy of the
license is available in `LICENSE`.

This project’s documentation is licensed under the Creative Commons Attribution
4.0 International License \(CC-BY-4.0\). A copy of the license is available in
`LICENSE-docs`.