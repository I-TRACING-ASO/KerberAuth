---
applyTo: "**/*.java" 
---

This is a Burp Suite Extension for Kerberos Authentication using the Montoya API.

## Architecture

- **Main Entry Point**: `KerberAuthExtension` - implements `BurpExtension` interface (initializes `Config` + `UserManager`, registers the UI tab and the HTTP handler)
- **Core Packages / Components**:
  - `kerberauth.config.Config` - Global configuration singleton (strategy, logging, scope, krb5.conf, SPNs)
  - `kerberauth.http.KerberosHttpHandler` - Intercepts HTTP traffic and adds Kerberos tokens according to the selected strategy
  - `kerberauth.authenticator.KerberosAuthenticator` / `KerberosCallbackHandler` - Kerberos login/TGT acquisition helpers
  - `kerberauth.kerberos.*` - Kerberos/GSS-API primitives:
    - `KerberosManager`, `GssTokenGenerator`, `LoginContextFactory`
    - `CallableTokenAction`, `ContextTokenSpnTriple`, `TGTExpiredException`
  - `kerberauth.cache.CacheManager` / `ContextCache` - Caching of Kerberos/GSS contexts/tokens
  - `kerberauth.manager.UserManager` + `kerberauth.model.UserEntry` - User/credential model and management
  - `kerberauth.ui.KerberAuthTab` + settings panels - Extension UI (credentials, strategy, scope, delegation, logging, custom SPNs)
  - `kerberauth.util.DomainUtil` / `LogUtil` - Domain helpers and logging utilities
- **Build System**: Gradle with Kotlin DSL, Java 21 compatibility
- **Dependencies**: Montoya API 2025.7 (compile-only), no runtime dependencies
- **Extension Pattern**: Extension that initializes through `initialize(MontoyaApi api)` method

## Key Development Commands

```bash
./gradlew build    # Build and test the extension
./gradlew jar      # Create the extension JAR file
./gradlew clean    # Clean build artifacts
```

The built JAR file will be in `build/libs/` and can be loaded directly into Burp Suite.

## Extension Loading in Burp

1. Build the JAR using `./gradlew jar`
2. In Burp: Extensions > Installed > Add > Select the JAR file
3. For quick reloading during development: Ctrl/⌘ + click the Loaded checkbox

## Documentation Structure

- See @docs/bapp-store-requirements.md for BApp Store submission requirements
- See @docs/montoya-api-examples.md for code patterns and extension structure  
- See @docs/development-best-practices.md for development guidelines
- See @docs/resources.md for external documentation and links

## Current State

This is a Burp Extension allowing to authenticate to websites using Kerberos Authentication.
It supports:
- TGT acquisition via username/password
- Service ticket generation for HTTP services
- Multiple authentication strategies (Proactive, Reactive, Hybrid)
- Scope management for Kerberos authentication
- SPN resolution with DNS CNAME support