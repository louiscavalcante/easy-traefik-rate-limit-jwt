# Easy Traefik Rate Limit JWT Plugin Documentation

This document provides a comprehensive guide to using the Easy Traefik Rate Limit JWT Plugin, including configuration options, integration with Traefik's rate limiting, public routes, expiration bypass, and deployment using the Traefik Helm chart.

## Table of Contents

1. [Plugin Overview](#plugin-overview)
2. [Configuration Reference](#configuration-reference)
3. [Example Configurations](#example-configurations)
4. [Integration with Rate Limiting](#integration-with-rate-limiting)
5. [Public Routes](#public-routes)
6. [Expiration Bypass](#expiration-bypass)
7. [Deployment with Traefik Helm Chart](#deployment-with-traefik-helm-chart)
8. [Troubleshooting](#troubleshooting)

## Plugin Overview

The Easy Traefik Rate Limit JWT Plugin provides a flexible and robust way to validate JWT tokens for your services. It allows you to:

-   Validate JWT tokens from multiple sources (bearer tokens, headers, query parameters)
-   Check for required fields in the JWT payload
-   Return custom error messages for expired tokens and other errors with proper logging
-   Inject JWT payload fields as HTTP headers for downstream services
-   Define public routes that bypass JWT validation entirely
-   Define routes that bypass token expiration checks but still validate the signature
-   Integrate seamlessly with Traefik's rate limiting

## Configuration Reference

The plugin accepts the following configuration options:

### `JwtPayloadFields` (array of string, optional)

A list of fields that must be present in the JWT payload. If any of these fields are missing, the request will be rejected.

**Default:** `["exp"]`

**Example:**

```yaml
JwtPayloadFields:
    - exp
    - _id
    - role
```

### `Alg` (string, required)

The algorithm used to sign the JWT token. The plugin supports the following algorithms:

-   HS256, HS384, HS512 (HMAC with SHA-256/384/512)
-   RS256, RS384, RS512 (RSA with SHA-256/384/512)
-   PS256, PS384, PS512 (RSA-PSS with SHA-256/384/512)
-   ES256, ES384, ES512 (ECDSA with SHA-256/384/512)

**Default:** `"HS256"`

**Example:**

```yaml
Alg: HS256
```

### `Secret` (array of string, required)

The secret or secrets used to validate the JWT token. For HMAC algorithms (HS256, HS384, HS512), this is the secret key. For RSA and ECDSA algorithms, this would be the public key.

**Example:**

```yaml
Secret:
    - your-jwt-secret-key
```

### `Sources` (array of object, required)

A prioritized list of sources to look for the JWT token. The plugin will try each source in order until it finds a token.

Each source object has the following properties:

-   `type`: The type of source. Can be `bearer`, `header`, or `query`.
-   `key`: The key to use when looking for the token.

**Default:**

```yaml
Sources:
    - type: bearer
      key: Authorization
```

**Example:**

```yaml
Sources:
    - type: bearer
      key: Authorization # Will look for "Bearer <token>" in the Authorization header
    - type: header
      key: X-Auth-Token # Will look for the token directly in the X-Auth-Token header
    - type: query
      key: jwt # Will look for the token in the jwt query parameter
```

### `InjectNewHeaders` (map of objects, optional)

Configuration for injecting JWT payload fields or source values as HTTP headers for downstream services.

Each key in the map is the name of the header to set. The value is an object with:

-   `From`: An ordered list of sources to look for values. Can be `JwtPayloadFields` or `Sources`.
-   `Values`: The specific fields to look for in each source.

**Example:**

```yaml
InjectNewHeaders:
    X-User-ID:
        From:
            - JwtPayloadFields
        Values:
            - _id
    X-Rate-Limit-ID:
        From:
            - JwtPayloadFields
            - Sources
        Values:
            - _id
            - X-Mobile-ID
```

In this example:

-   The plugin will set the `X-User-ID` header to the value of the `_id` field in the JWT payload.
-   For the `X-Rate-Limit-ID` header, it will first try to use the `_id` field from the JWT payload. If that's not available, it will try to use the value of the `X-Mobile-ID` header.

### `ErrorMessage` (string, optional)

A custom message to return for all JWT validation errors (except expiration). This message will be shown to users when there's any issue with JWT validation, including missing tokens, invalid signatures, or missing required headers for public routes.

**Default:** `"An error occurred while processing the request"`

**Example:**

```yaml
ErrorMessage: 'Authentication failed. Please check your credentials and try again.'
```

### `ExpirationMessage` (string, optional)

A custom message to return specifically when the JWT token has expired. This is the only error that will have a custom message distinct from the general `ErrorMessage`.

**Default:** `"Token has expired"`

**Example:**

```yaml
ExpirationMessage: 'Your session has expired. Please log in again.'
```

### `RoutesToBypassTokenExpiration` (array of objects, optional)

A list of routes that should bypass token expiration checks. The token signature will still be validated, but expired tokens will be accepted for these routes.

Each route object has a `match` property that defines a Traefik route matcher expression.

**Example:**

```yaml
RoutesToBypassTokenExpiration:
    - match: Host(`api.example.com`) && Method(`PUT`) && PathPrefix(`/bypass`)
    - match: Host(`api.example.com`) && Method(`POST`) && PathPrefix(`/something/bypass`)
```

### `RoutesToBypassJwtValidation` (array of objects, optional)

A list of public routes that should bypass JWT validation entirely. For these routes, no JWT token is required.

Each route object has:

-   `match`: A Traefik route matcher expression
-   `InjectNewHeaders` (optional): Headers to inject for these public routes

For public routes, the header injection works differently:

-   `From`: The source type (currently only `Sources` is supported)
-   `Key`: The specific header or query parameter to look for

**Example:**

```yaml
RoutesToBypassJwtValidation:
    - match: Host(`api.example.com`) && Method(`GET`) && PathPrefix(`/public`)
      InjectNewHeaders:
          X-Rate-Limit-ID:
              From:
                  - Sources
                  - Sources
              Key:
                  - X-Mobile-ID
                  - X-User-ID
    - match: Host(`api.example.com`) && Method(`POST`) && PathPrefix(`/something/public`)
      InjectNewHeaders:
          X-Rate-Limit-ID:
              From:
                  - Sources
              Key:
                  - X-Mobile-ID
```

In this example:

-   For requests to `/public`, the plugin will try to use the value of the `X-Mobile-ID` header as the `X-Rate-Limit-ID` header. If that's not available, it will try to use the value of the `X-User-ID` header.
-   For requests to `/something/public`, it will only try to use the value of the `X-Mobile-ID` header.

## Example Configurations

### Basic JWT Validation

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
    name: jwt-auth
spec:
    plugin:
        easy-traefik-rate-limit-jwt:
            JwtPayloadFields:
                - exp
            Alg: HS256
            Secret:
                - your-jwt-secret-key
            Sources:
                - type: bearer
                  key: Authorization
```

### Advanced Configuration with Multiple Sources and Header Injection

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
    name: advanced-jwt-auth
spec:
    plugin:
        easy-traefik-rate-limit-jwt:
            JwtPayloadFields:
                - exp
                - _id
                - role
            Alg: HS256
            Secret:
                - your-jwt-secret-key
            Sources:
                - type: bearer
                  key: Authorization
                - type: header
                  key: X-Auth-Token
                - type: query
                  key: token
            InjectNewHeaders:
                X-User-ID:
                    From:
                        - JwtPayloadFields
                    Values:
                        - _id
                X-User-Role:
                    From:
                        - JwtPayloadFields
                    Values:
                        - role
            ExpirationMessage: 'Your session has expired. Please log in again.'
            ErrorMessage: 'An error occurred during authentication. Please try again.'
```

### Configuration with Public Routes and Expiration Bypass

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
    name: advanced-jwt-auth
spec:
    plugin:
        easy-traefik-rate-limit-jwt:
            JwtPayloadFields:
                - exp
                - _id
            Alg: HS256
            Secret:
                - your-jwt-secret-key
            Sources:
                - type: bearer
                  key: Authorization
            InjectNewHeaders:
                X-User-ID:
                    From:
                        - JwtPayloadFields
                    Values:
                        - _id
            RoutesToBypassTokenExpiration:
                - match: Host(`api.example.com`) && Method(`PUT`) && PathPrefix(`/refresh`)
            RoutesToBypassJwtValidation:
                - match: Host(`api.example.com`) && Method(`GET`) && PathPrefix(`/public`)
                  InjectNewHeaders:
                      X-Rate-Limit-ID:
                          From:
                              - Sources
                          Key:
                              - X-Mobile-ID
```

## Integration with Rate Limiting

One of the key features of this plugin is its ability to integrate with Traefik's rate limiting middleware. By extracting a unique identifier from the JWT payload or request headers and injecting it as a header, you can use that header for rate limiting based on a user identifier rather than IP address.

### Step 1: Configure the JWT Plugin to Inject a Rate Limit ID

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
    name: jwt-with-rate-limit-id
spec:
    plugin:
        easy-traefik-rate-limit-jwt:
            JwtPayloadFields:
                - exp
                - _id
            Alg: HS256
            Secret:
                - your-jwt-secret-key
            InjectNewHeaders:
                X-Rate-Limit-ID:
                    From:
                        - JwtPayloadFields
                    Values:
                        - _id
            Sources:
                - type: bearer
                  key: Authorization
            RoutesToBypassJwtValidation:
                - match: Host(`api.example.com`) && Method(`GET`) && PathPrefix(`/public`)
                  InjectNewHeaders:
                      X-Rate-Limit-ID:
                          From:
                              - Sources
                          Key:
                              - X-Mobile-ID
```

### Step 2: Configure Traefik's Rate Limiting Middleware

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
    name: rate-limit
spec:
    rateLimit:
        average: 100
        burst: 50
        period: 1m
        sourceCriterion:
            requestHeaderName: X-Rate-Limit-ID
```

### Step 3: Chain the Middlewares

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
    name: your-service
spec:
    entryPoints:
        - web
    routes:
        - match: Host(`your-service.example.com`)
          kind: Rule
          services:
              - name: your-service
                port: 80
          middlewares:
              - name: jwt-with-rate-limit-id
              - name: rate-limit
```

With this configuration, Traefik will:

1. Validate the JWT token for protected routes, or skip validation for public routes
2. Extract the user identifier (either from the JWT payload or from headers)
3. Inject it as the `X-Rate-Limit-ID` header
4. Use that header for rate limiting, so each user gets their own rate limit bucket

## Public Routes

Public routes are paths in your application that don't require JWT authentication. The plugin allows you to define these routes using the `RoutesToBypassJwtValidation` configuration.

For public routes, you can still inject headers based on request headers or query parameters. This is particularly useful for rate limiting based on a device identifier or other non-authenticated user identifier.

### Example Public Route Configuration

```yaml
RoutesToBypassJwtValidation:
    - match: Host(`api.example.com`) && Method(`GET`) && PathPrefix(`/public`)
      InjectNewHeaders:
          X-Rate-Limit-ID:
              From:
                  - Sources
                  - Sources
              Key:
                  - X-Mobile-ID
                  - X-Device-ID
```

In this example, for requests to `/public`:

1. The plugin will look for an `X-Mobile-ID` header in the request
2. If found, it will set `X-Rate-Limit-ID` to that value
3. If not found, it will look for an `X-Device-ID` header
4. This allows for rate limiting of public routes based on device or mobile identifiers

## Expiration Bypass

Some API routes, like token refresh endpoints, may need to accept expired tokens while still validating the token signature. The `RoutesToBypassTokenExpiration` configuration allows you to define these routes.

### Example Expiration Bypass Configuration

```yaml
RoutesToBypassTokenExpiration:
    - match: Host(`api.example.com`) && Method(`POST`) && PathPrefix(`/auth/refresh`)
    - match: Host(`api.example.com`) && Method(`GET`) && PathPrefix(`/auth/status`)
```

In this example:

1. POST requests to `/auth/refresh` will accept expired tokens, but will still validate the token signature
2. GET requests to `/auth/status` will also accept expired tokens
3. Other routes will require non-expired tokens

This is useful for refresh token endpoints or status check endpoints that need to work with expired tokens.

## Deployment with Traefik Helm Chart

To use this plugin with a Traefik installation managed by Helm, follow these steps:

### Step 1: Update values.yaml

Add the plugin to the `experimental.plugins` section in your values.yaml file:

```yaml
experimental:
    plugins:
        easy-traefik-rate-limit-jwt:
            moduleName: github.com/louiscavalcante/easy-traefik-rate-limit-jwt
            version: v0.0.1
```

### Step 2: Install or Upgrade Traefik

Install or upgrade your Traefik Helm release with the updated values:

```bash
# Install
helm install traefik traefik/traefik -f values.yaml

# Or upgrade
helm upgrade traefik traefik/traefik -f values.yaml
```

### Step 3: Create the Middleware

Create a Kubernetes resource for the middleware:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
    name: jwt-auth
spec:
    plugin:
        easy-traefik-rate-limit-jwt:
            JwtPayloadFields:
                - exp
                - _id
            Alg: HS256
            Secret:
                - your-jwt-secret-key
            Sources:
                - type: bearer
                  key: Authorization
            ExpirationMessage: 'Your token has expired. Please log in again.'
            ErrorMessage: 'Authentication error. Please try again later.'
```

Apply it to your cluster:

```bash
kubectl apply -f jwt-middleware.yaml
```

### Step 4: Use the Middleware in Your IngressRoutes

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
    name: your-service
spec:
    entryPoints:
        - websecure
    routes:
        - match: Host(`your-service.example.com`)
          kind: Rule
          services:
              - name: your-service
                port: 80
          middlewares:
              - name: jwt-auth
    tls: {}
```

## Troubleshooting

### Common Issues

#### 1. Token validation fails with "unexpected signing method"

Make sure the `Alg` parameter in your configuration matches the algorithm used to sign your JWT tokens.

#### 2. Token validation fails with "required field missing"

Check that your JWT tokens contain all the fields specified in the `JwtPayloadFields` parameter.

#### 3. The plugin doesn't find the JWT token

Check the `Sources` configuration and make sure the token is being sent in one of the configured sources.

#### 4. Public routes still require JWT validation

Make sure your route matcher expression in `RoutesToBypassJwtValidation` correctly matches your public routes. Check the Host, Method, and PathPrefix values.

#### 5. Expiration bypass not working

Verify that your route matcher expression in `RoutesToBypassTokenExpiration` correctly matches your routes. The token must still be a valid JWT with a valid signature.

### Debugging

To debug issues with the plugin, you can enable debug logging in Traefik:

```yaml
# In your Traefik configuration
logs:
    level: DEBUG
```

The plugin also logs errors with timestamps in UTC format, which should appear in your Traefik logs.

## Conclusion

The Easy Traefik Rate Limit JWT Plugin provides a flexible and robust way to validate JWT tokens, handle public routes, bypass token expiration, and integrate with other Traefik middlewares. By following this documentation, you should be able to configure the plugin to meet your specific needs.

If you encounter any issues or have suggestions for improvements, please file an issue on the [GitHub repository](https://github.com/louiscavalcante/easy-traefik-rate-limit-jwt).
