# KerberAuth

A Burp Suite extension that adds Kerberos (SPNEGO/Negotiate) authentication to HTTP traffic for multiple users.

KerberAuth automatically acquires Kerberos TGTs and service tickets, then injects `Authorization: Negotiate` headers into requests — making it possible to test Kerberos-protected web applications with Burp Suite.

## Features

- **Multiple authentication strategies:**
  - **Reactive** — authenticates after receiving a `401 Negotiate` response
  - **Proactive** — adds Kerberos auth to all in-scope requests upfront
  - **Proactive (401)** — proactively authenticates to hosts that previously returned `401 Negotiate`
- **Multi-user support** — configure multiple credentials and select per-request via a custom header (e.g. PwnFox integration)
- **Scope management** — restrict authentication to specific hosts, the whole Kerberos domain, or custom patterns
- **Custom SPN overrides** — map hostnames to specific SPNs when auto-discovery doesn't work
- **DNS CNAME resolution** for SPN construction
- **Delegation support** via custom `krb5.conf`

## Configuration

All settings are accessible from the **KerberAuth** tab in Burp.

### 1. Domain Settings

Set the **Domain DNS name** and **KDC hostname**. These are used to construct the Kerberos realm and configure `krb5.realm`/`krb5.kdc` system properties.

### 2. Credentials

Add one or more users with their username and password. Passwords are stored in memory only by default — enable **Save passwords in project** to persist them across sessions.

Each user can have an optional **Header Selector** value. When a request contains the configured custom header (default: `X-PwnFox-Color`) with a matching value, that user's credentials are used instead of the default.

### 3. Delegation (krb5.conf)

Point to a `krb5.conf` file for Kerberos configuration.

### 4. Authentication Strategy

| Strategy | Behavior |
|---|---|
| **Reactive** | Waits for a `401 Negotiate` response, then authenticates and resends the request |
| **Proactive** | Adds `Authorization: Negotiate` to every in-scope request |
| **Proactive (401)** | Same as Proactive, but only for hosts that have previously returned `401 Negotiate` |

### 5. Scope

Control which hosts receive Kerberos authentication:

- **All hosts in scope** — authenticate to every request
- **All hosts in this Kerberos domain** (default) — only hosts matching the domain suffix
- **Hosts in scope list** — manually specified hostnames/patterns
- **Plain hostnames considered part of domain** — treat unqualified hostnames as domain members
- **Ignore NTLM servers** — skip hosts that also advertise NTLM

### 6. Custom SPN Overrides

Map hostnames to specific SPNs when automatic SPN construction or DNS resolution fails.

### 7. Logging

Set logging and alert verbosity independently (None / Normal / Verbose). Output goes to the extension's **Output** tab in Burp.

## Requirements

- Burp Suite Professional or Community (2025.x+)
- Java 21+

## Building

```bash
./gradlew jar
```

The JAR file is generated at `build/libs/kerberauth.jar`.

## Architecture

```
kerberauth/
├── KerberAuthExtension.java        # Entry point (BurpExtension)
├── config/Config.java              # Thread-safe configuration singleton
├── http/KerberosHttpHandler.java   # HTTP handler (intercepts traffic)
├── authenticator/                  # User authentication (JAAS)
├── kerberos/                       # GSS-API / token generation
├── cache/                          # Context and token caching
├── manager/UserManager.java        # User lifecycle management
├── model/UserEntry.java            # User model
├── ui/                             # Swing UI panels
└── util/                           # Domain and logging helpers
```

## Credits

Inspired by [Berserko](https://github.com/nccgroup/berserko), the original Burp extension for Kerberos authentication.
This extension rebuilds its functionalities with the Montoya API, cleans the code, and adds multi-user support.

## License

See [LICENSE](LICENSE) for details.