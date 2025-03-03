# Easy Traefik Rate Limit JWT Plugin

A flexible JWT validation middleware for Traefik v3+ that:

-   Validates JWT tokens from multiple sources (bearer, header, query)
-   Checks for required fields in the JWT payload
-   Provides customizable error messages for expired tokens and other errors
-   Injects JWT payload fields as HTTP headers for downstream services
-   Integrates seamlessly with Traefik's rate limiting
-   Supports public routes that bypass JWT validation
-   Allows specified routes to bypass token expiration checks
-   Logs errors with timestamps in UTC format

## Features

-   **Multiple JWT Sources**: Configure multiple places to look for the JWT token (Bearer token, header, query parameter)
-   **Required Fields**: Specify required fields in the JWT payload
-   **Custom Error Messages**: Configure separate messages for token expiration and all other validation errors
-   **Header Injection**: Inject JWT payload fields or header values as HTTP headers for downstream services
-   **Rate Limit Integration**: Seamless integration with Traefik's rate limiting middleware
-   **Public Routes**: Define routes that can bypass JWT validation entirely
-   **Expiration Bypass**: Define routes that ignore token expiration but still verify the signature
-   **Enhanced Error Logging**: Detailed error logging with timestamps in UTC format

## Installation

To use this plugin with Traefik v3+, add the following to your Traefik static configuration:

```yaml
experimental:
    plugins:
        easy-traefik-rate-limit-jwt:
            moduleName: github.com/louiscavalcante/easy-traefik-rate-limit-jwt
            version: v0.0.1
```

## Configuration

Create a middleware instance in your dynamic configuration:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
    name: jwt-rate-limit
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
                        - Sources
                    Values:
                        - _id
                        - X-Mobile-ID
            Sources:
                - type: bearer
                  key: Authorization
                - type: header
                  key: X-Mobile-ID
            ExpirationMessage: 'Token has expired, please log in again'
            ErrorMessage: 'Something bad happened, please try again later'
            RoutesToBypassTokenExpiration:
                - match: Host(`api.example.com`) && Method(`PUT`) && PathPrefix(`/bypass`)
            RoutesToBypassJwtValidation:
                - match: Host(`api.example.com`) && Method(`GET`) && PathPrefix(`/public`)
                  InjectNewHeaders:
                      X-Rate-Limit-ID:
                          From:
                              - Sources
                          Key:
                              - X-Mobile-ID
```

See the [plugin documentation](./plugin-docs.md) for detailed configuration options and examples.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](./LICENSE) file for details.
