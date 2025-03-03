// Package easy_traefik_rate_limit_jwt provides a Traefik plugin that validates JWT tokens
// and integrates with rate limiting while supporting public routes and token expiration bypass.
package easy_traefik_rate_limit_jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// Config holds the plugin configuration.
type Config struct {
	// Ordered for better memory alignment
	JwtPayloadFields            []string                   `json:"JwtPayloadFields,omitempty"`
	Sources                     []Source                   `json:"Sources,omitempty"`
	RoutesToBypassTokenExpiration []RouteMatch              `json:"RoutesToBypassTokenExpiration,omitempty"`
	RoutesToBypassJwtValidation  []PublicRouteMatch        `json:"RoutesToBypassJwtValidation,omitempty"`
	Secret                      []string                   `json:"Secret,omitempty"`
	InjectNewHeaders            map[string]HeaderValue     `json:"InjectNewHeaders,omitempty"`
	Alg                         string                     `json:"Alg,omitempty"`
	ExpirationMessage           string                     `json:"ExpirationMessage,omitempty"`
	ErrorMessage                string                     `json:"ErrorMessage,omitempty"`
}

// Source defines a source for JWT tokens
type Source struct {
	Type string `json:"type,omitempty"`
	Key  string `json:"key,omitempty"`
}

// RouteMatch defines a route matcher for bypassing token expiration
type RouteMatch struct {
	Match string `json:"match,omitempty"`
}

// PublicRouteMatch defines a route matcher for public routes with header injection
type PublicRouteMatch struct {
	Match            string                `json:"match,omitempty"`
	InjectNewHeaders map[string]PublicHeaderValue `json:"InjectNewHeaders,omitempty"`
}

// HeaderValue defines how to inject a header value
type HeaderValue struct {
	From   []string `json:"From,omitempty"`
	Values []string `json:"Values,omitempty"`
}

// PublicHeaderValue defines how to inject a header value for public routes
type PublicHeaderValue struct {
	From []string `json:"From,omitempty"`
	Key  []string `json:"Key,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		JwtPayloadFields:  []string{"exp"},
		Alg:               "HS256",
		Secret:            []string{},
		InjectNewHeaders:  map[string]HeaderValue{},
		Sources:           []Source{{Type: "bearer", Key: "Authorization"}},
		ExpirationMessage: "Token has expired",
		ErrorMessage:      "An error occurred while processing the request",
	}
}

// JwtPlugin is the JWT validation plugin.
type JwtPlugin struct {
	next   http.Handler
	config *Config
	name   string
}

// New creates a new JwtPlugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Validate configuration
	if len(config.Secret) == 0 {
		return nil, fmt.Errorf("JWT secret is required")
	}

	if config.Alg == "" {
		return nil, fmt.Errorf("JWT algorithm is required")
	}

	// Validate that the algorithm is supported
	supportedAlgs := map[string]bool{
		"RS256": true, "RS384": true, "RS512": true,
		"PS256": true, "PS384": true, "PS512": true,
		"ES256": true, "ES384": true, "ES512": true,
		"HS256": true, "HS384": true, "HS512": true,
	}

	if !supportedAlgs[config.Alg] {
		return nil, fmt.Errorf("unsupported JWT algorithm: %s", config.Alg)
	}

	if len(config.Sources) == 0 {
		return nil, fmt.Errorf("at least one source is required")
	}

	return &JwtPlugin{
		next:   next,
		config: config,
		name:   name,
	}, nil
}

// errorResponse sends a JSON error response and logs the error (except for expiration)
func (j *JwtPlugin) errorResponse(rw http.ResponseWriter, message string, err error, statusCode int, shouldLog bool) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(statusCode)
	
	// Use custom message if provided
	responseMsg := message
	if message == "" {
		responseMsg = j.config.ErrorMessage
	}
	
	response := map[string]string{"message": responseMsg}
	if encodeErr := json.NewEncoder(rw).Encode(response); encodeErr != nil {
		// Log encoding errors
		now := time.Now().UTC().Format(time.RFC3339)
		fmt.Fprintf(os.Stderr, "\033[90m%s\033[0m \033[31mERR\033[0m - Easy Traefik Rate Limit JWT Plugin: Error encoding JSON response: %v\n", now, encodeErr)
	}
	
	// Log the original error only if shouldLog is true (skip for expiration errors)
	if shouldLog {
		now := time.Now().UTC().Format(time.RFC3339)
		fmt.Fprintf(os.Stderr, "\033[90m%s\033[0m \033[31mERR\033[0m - Easy Traefik Rate Limit JWT Plugin: %v\n", now, err)
	}
}

// extractToken extracts the JWT token from the request using the configured sources
func (j *JwtPlugin) extractToken(req *http.Request) (string, map[string]string, error) {
	sourceValues := make(map[string]string)

	for _, source := range j.config.Sources {
		switch source.Type {
		case "bearer":
			authHeader := req.Header.Get(source.Key)
			if authHeader != "" {
				// Check if the header starts with "Bearer "
				if strings.HasPrefix(authHeader, "Bearer ") {
					token := strings.TrimPrefix(authHeader, "Bearer ")
					sourceValues[source.Key] = token
					return token, sourceValues, nil
				}
				sourceValues[source.Key] = authHeader
			}
		case "header":
			headerValue := req.Header.Get(source.Key)
			if headerValue != "" {
				sourceValues[source.Key] = headerValue
				// If this is the first source, try to use it as a token
				if len(sourceValues) == 1 {
					return headerValue, sourceValues, nil
				}
			}
		case "query":
			queryValue := req.URL.Query().Get(source.Key)
			if queryValue != "" {
				sourceValues[source.Key] = queryValue
				// If this is the first source, try to use it as a token
				if len(sourceValues) == 1 {
					return queryValue, sourceValues, nil
				}
			}
		}
	}

	// If we've collected source values but couldn't find a token
	if len(sourceValues) > 0 {
		return "", sourceValues, fmt.Errorf("JWT token not found in any of the sources")
	}

	return "", sourceValues, fmt.Errorf("JWT token not found in any of the sources")
}

// validateToken validates the JWT token
func (j *JwtPlugin) validateToken(tokenString string, ignoreExpiration bool) (map[string]interface{}, error) {
	// Use parser options for handling expired tokens
	parserOptions := []jwt.ParserOption{}
	if ignoreExpiration {
		parserOptions = append(parserOptions, jwt.WithoutClaimsValidation())
	}
	
	parser := jwt.NewParser(parserOptions...)
	
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		// Verify algorithm
		if t.Method.Alg() != j.config.Alg {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		
		return []byte(j.config.Secret[0]), nil
	}
	
	// Parse token with validation
	token, err := parser.Parse(tokenString, keyFunc)
	
	// Handle parse errors
	if err != nil {
		if strings.Contains(err.Error(), "token is expired") && !ignoreExpiration {
			return nil, fmt.Errorf("token is expired")
		} else if strings.Contains(err.Error(), "token is expired") && ignoreExpiration {
			// For routes that bypass expiration, we still want to proceed
		} else {
			return nil, err
		}
	}
	
	// Ensure token is valid
	if !token.Valid && !ignoreExpiration {
		return nil, fmt.Errorf("invalid token")
	}
	
	// Extract claims
	var claims map[string]interface{}
	jwtClaims, ok := token.Claims.(jwt.MapClaims)
	
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}
	
	// Convert JWT claims to map
	claims = make(map[string]interface{})
	for k, v := range jwtClaims {
		claims[k] = v
	}
	
	// Check required fields
	for _, field := range j.config.JwtPayloadFields {
		if _, exists := claims[field]; !exists {
			return nil, fmt.Errorf("required field %s missing from token payload", field)
		}
	}
	
	return claims, nil
}

// matchRoute checks if the request matches a route pattern
func (j *JwtPlugin) matchRoute(req *http.Request, pattern string) bool {
	// Simple implementation to check for Host, Method, and PathPrefix
	// In a real implementation, this would use a proper matcher
	segments := strings.Split(pattern, " && ")
	
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		
		if strings.HasPrefix(segment, "Host(") {
			host := strings.TrimSuffix(strings.TrimPrefix(segment, "Host(`"), "`)")
			if req.Host != host {
				return false
			}
		} else if strings.HasPrefix(segment, "Method(") {
			method := strings.TrimSuffix(strings.TrimPrefix(segment, "Method(`"), "`)")
			if req.Method != method {
				return false
			}
		} else if strings.HasPrefix(segment, "PathPrefix(") {
			prefix := strings.TrimSuffix(strings.TrimPrefix(segment, "PathPrefix(`"), "`)")
			if !strings.HasPrefix(req.URL.Path, prefix) {
				return false
			}
		}
	}
	
	return true
}

// injectHeaders injects headers based on token claims or source values
func (j *JwtPlugin) injectHeaders(req *http.Request, claims map[string]interface{}, sourceValues map[string]string) {
	for headerName, headerValue := range j.config.InjectNewHeaders {
		for i, value := range headerValue.Values {
			// Skip if there are no values for this header
			if len(headerValue.Values) == 0 {
				continue
			}

			// Check where to get the value from based on the From configuration
			if i < len(headerValue.From) {
				switch headerValue.From[i] {
				case "JwtPayloadFields":
					// Get the value from JWT payload
					if claimValue, ok := claims[value]; ok {
						// Convert the claim value to string
						var strValue string
						switch v := claimValue.(type) {
						case string:
							strValue = v
						case float64:
							strValue = fmt.Sprintf("%v", v)
						case bool:
							strValue = fmt.Sprintf("%v", v)
						default:
							// For complex types, convert to JSON
							jsonBytes, err := json.Marshal(v)
							if err == nil {
								strValue = string(jsonBytes)
							} else {
								strValue = fmt.Sprintf("%v", v)
							}
						}
						req.Header.Set(headerName, strValue)
						break
					}
				case "Sources":
					// Get the value from source values
					if sourceValue, ok := sourceValues[value]; ok {
						req.Header.Set(headerName, sourceValue)
						break
					}
				}
			}
		}
	}
}

// injectPublicHeaders injects headers for public routes
func (j *JwtPlugin) injectPublicHeaders(req *http.Request, publicRoute PublicRouteMatch) error {
	for headerName, headerConfig := range publicRoute.InjectNewHeaders {
		// Keep track if we found any valid header
		headerFound := false
		
		// Process each From and Key pair by position
		for i := 0; i < len(headerConfig.From); i++ {
			// Skip if there's no matching Key for this From
			if i >= len(headerConfig.Key) {
				continue
			}
			
			fromType := headerConfig.From[i]
			keyValue := headerConfig.Key[i]
			
			if fromType == "Sources" {
				// Get the value from the request headers or query
				headerValue := req.Header.Get(keyValue)
				if headerValue != "" {
					req.Header.Set(headerName, headerValue)
					headerFound = true
					break // Stop after finding the first valid value
				}
			}
			// Additional source types can be added here
		}
		
		// If we've gone through all options and haven't found a header,
		// return an error for the last option in the chain
		if !headerFound && len(headerConfig.From) > 0 {
			return fmt.Errorf("no valid header found for %s", headerName)
		}
	}
	
	return nil
}

// ServeHTTP implements the http.Handler interface.
func (j *JwtPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check if the request matches any public route
	for _, publicRoute := range j.config.RoutesToBypassJwtValidation {
		if j.matchRoute(req, publicRoute.Match) {
			// For public routes, inject headers if configured
			err := j.injectPublicHeaders(req, publicRoute)
			if err != nil {
				// Log and return the generic error message for public route errors
				j.errorResponse(rw, j.config.ErrorMessage, err, http.StatusBadRequest, true)
				return
			}
			
			// No JWT validation needed, proceed to next handler
			j.next.ServeHTTP(rw, req)
			return
		}
	}

	// Check if this route should bypass token expiration
	bypassExpiration := false
	for _, route := range j.config.RoutesToBypassTokenExpiration {
		if j.matchRoute(req, route.Match) {
			bypassExpiration = true
			break
		}
	}

	// Extract token from request
	tokenString, sourceValues, err := j.extractToken(req)
	if err != nil {
		// Log and return the generic error message for token extraction errors
		j.errorResponse(rw, j.config.ErrorMessage, err, http.StatusUnauthorized, true)
		return
	}

	// Validate token
	claims, err := j.validateToken(tokenString, bypassExpiration)
	if err != nil {
		// Only use the expiration message for expired tokens
		if err.Error() == "token is expired" {
			// Don't log expiration errors
			j.errorResponse(rw, j.config.ExpirationMessage, err, http.StatusUnauthorized, false)
			return
		}
		
		// For all other validation errors, log and return the generic message
		j.errorResponse(rw, j.config.ErrorMessage, err, http.StatusUnauthorized, true)
		return
	}

	// Inject headers if configured
	j.injectHeaders(req, claims, sourceValues)

	// Call the next handler
	j.next.ServeHTTP(rw, req)
}