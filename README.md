#  Mobility Auth Server


  **OAuth 2.1 Authorization Server for the Mobility Platform**

---

## Overview

`mobility-authserver` is the centralized authentication and authorization service for the 
Mobility microservices platform. Built on top of [Spring Authorization Server](https://spring.io/projects/spring-authorization-server), 
it issues and manages OAuth2.1 compliant tokens, handles user identity, and exposes 
internal APIs over gRPC.

### Key Capabilities

- **OAuth 2.1 Authorization Server** - Full implementation of the PKCE and client credentials grant type flows
- **JWT Token Issuance** - Self-contained access tokens enriched with custom claims
- **gRPC API** - High performance inter-service communication 
- **Database-per-Service** - Dedicated PostgreSQL instance with Liquibase managed schema migrations
- **RabbitMQ Integration** - Asynchronous event publishing via shared messaging library
- **Structured Logging** - Logback with profile configurations.

---
## Architecture

The auth server sits at the center of the Mobility platform as the single source of 
truth for authentication and authorization.
Internal microservices communicate with the auth server with **gRPC** and **RabbitMQ**,
while external clients obtain tokens via standard **OAuth 2.1** endpoints.

- **External clients** obtain tokens via standard OAuth 2.1 endpoints (authorization code + PKCE, client credentials)
- **Internal microservices** communicate with the auth server over **gRPC** for user creation and identity confirmation
- **RabbitMQ** handles asynchronous operations such as saga compensation/rollbacks and email dispatch
- **PostgreSQL** serves as the dedicated database, with schema managed by Liquibase

---

## Tech Stack

| Layer              | Technology                                     |
|--------------------|------------------------------------------------|
| Language           | Java 21                                        |
| Framework          | Spring Boot 3.5.6, Spring Authorization Server |
| Database           | PostgreSQL                                     |
| Migrations         | Liquibase                                      |
| Inter-service RPC  | gRPC 1.58.0                                    |
| Messaging          | RabbitMQ (via `rabbitmq-common` library)       |
| Token Format       | JWT (JJWT 0.11.5 + Spring Security OAuth2)     |
| Logging            | Logback                                        |
| Build              | Maven                                          |

---

## Prerequisites

- **Java 21** or later
- **Maven 3.8+**
- **PostgreSQL**
- **RabbitMQ**
- **Docker**
- Access to internal Maven artifacts:
  - `com.theodore.common:infrastructure-common:${version}`
  - `com.theodore.common:proto-common:${version}`
  - `com.theodore.queue.common:rabbitmq-common:${version}`

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/theodoreromeos/auth-server.git
cd /mobility-authserver
```

### 2. Start the Database

```bash
docker compose up -d
```

> The Docker Compose file provisions a PostgreSQL instance dedicated to the auth server. 
> Liquibase migrations run automatically on application startup.

### 3. Configure the Application

Select a profile to run the application (local, staging, prod).


### 4. Build & Run

```bash
# Build
mvn clean package -DskipTests

# Run
java -jar target/mobility-authserver-1.0.0.jar --spring.profiles.active=local
```

The server will start on the default HTTP port with the gRPC server listening on 
its configured port.

---

## OAuth 2.1 Clients

The auth server registers two OAuth clients out of the box:

### Client Credentials Grant Type Flow

Intended for **internal service-to-service** authentication.

| Property                  | Value                                  |
|---------------------------|----------------------------------------|
| Client ID                 | `mobility-api`                         |
| Authentication Method     | `CLIENT_SECRET_BASIC`                  |
| Grant Type                | `client_credentials`                   |
| Scopes                    | `openid`, `INTERNAL_SERVICE`           |
| Access Token TTL          | 10 minutes                             |
| Token Format              | Self-contained JWT                     |

### PKCE Grant Type Flow

Intended for **public-facing client applications** (SPAs, mobile apps).

| Property                  | Value                                  |
|---------------------------|----------------------------------------|
| Client ID                 | `mobility-public`                      |
| Authentication Method     | `none` (public client)                 |
| Grant Types               | `authorization_code`, `refresh_token`  |
| PKCE Required             | Yes                                    |
| Scopes                    | `openid`, `email`                      |
| Access Token TTL          | 100 minutes                            |
| Refresh Token TTL         | 8 hours                                |
| Refresh Token Reuse       | Disabled (rotation enforced)           |
| Redirect URI              | `http://localhost:9999/login/callback` |
| Token Format              | Self-contained JWT                     |

---

## JWT Custom Claims

Access tokens are enriched with application-specific claims depending on the grant type:

**Client Credentials flow:**

```json
{
  "username": "testemail@mobilityapp.com",
  "roles": ["openid", "ROLE_INTERNAL_SERVICE"]
}
```

**Authorization Code flow (end-user):**

```json
{
  "username": "testemail@mobilityapp.com",
  "organization": "123456789",
  "roles": ["ROLE_DRIVER", "..."]
}
```

The `organization` claim is included only when the authenticated user 
is associated with an organization.

---

## gRPC API

The auth server exposes gRPC endpoints consumed by sibling microservices within 
the platform. Protocol buffer definitions live in the shared `proto-common` library.


Error mapping is handled centrally via `GrpcExceptionMapper`, which translates 
domain exceptions (e.g., `NotFoundException`) into appropriate gRPC response statuses.

---

## Database Migrations

Schema management is handled by **Liquibase**. 
Changesets are applied automatically on startup.

## Logging

The application uses a custom `logback-spring.xml` configuration supporting 
Spring profile specific log levels and output formatting.

```
src/main/resources/
└── logback-spring.xml
```

---

## Shared Libraries

This service depends on three internal libraries:

| Library                | Purpose                                                  |
|------------------------|----------------------------------------------------------|
| `infrastructure-common`| Shared infrastructure utilities and base configurations  |
| `proto-common`         | Protobuf / gRPC service definitions                     |
| `rabbitmq-common`      | RabbitMQ connection management and event abstractions    |

These must be available in your local Maven repository or a private artifact 
registry before building.

---


## Docker

A unified Docker Compose setup is planned to orchestrate both the database 
and the service:

```bash
# Coming soon: single command to start everything
docker compose up -d
```

> **Current state:** The provided `docker-compose.yml` starts only the PostgreSQL database. Service containerization is in progress.

