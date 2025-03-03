package easy_traefik_rate_limit_jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// Create a synchronized writer for thread-safe logging
var (
	stderr io.Writer = os.Stderr
	logMu  sync.Mutex
)

// Config holds the plugin configuration
type Config struct {
	JwtPayloadFields              []string                    `json:"JwtPayloadFields,omitempty"`
	Alg                           string                      `json:"Alg,omitempty"`
	Secret                        []string                    `json:"Secret,omitempty"`
	Sources                       []Source                    `json:"Sources,omitempty"`
	InjectNewHeaders              map[string]HeaderValue      `json:"InjectNewHeaders,omitempty"`
	ExpirationMessage             string                      `json:"ExpirationMessage,omitempty"`
	ErrorMessage                  string                      `json:"ErrorMessage,omitempty"`
	RoutesToBypassTokenExpiration []RouteMatch                `json:"RoutesToBypassTokenExpiration,omitempty"`
	RoutesToBypassJwtValidation   []PublicRouteMatch          `json:"RoutesToBypassJwtValidation,omitempty"`
}

// Source defines a source to look for the JWT token
type Source struct {
	Type string `json:"type,omitempty"`
	Key  string `json:"key,omitempty"`
}

// HeaderValue defines header values to inject
type HeaderValue struct {
	From   []string `json:"From,omitempty"`
	Values []string `json:"Values,omitempty"`
}

// PublicHeaderValue defines header values to inject for public routes
type PublicHeaderValue struct {
	From []string `json:"From,omitempty"`
	Key  []string `json:"Key,omitempty"`
}

// RouteMatch contains a Traefik route matcher expression
type RouteMatch struct {
	Match string `json:"match,omitempty"`
}

// PublicRouteMatch contains a Traefik route matcher expression and headers to inject
type PublicRouteMatch struct {
	Match            string                       `json:"match,omitempty"`
	InjectNewHeaders map[string]PublicHeaderValue `json:"InjectNewHeaders,omitempty"`
}

// JwtPlugin implements the Traefik middleware interface
type JwtPlugin struct {
	next   http.Handler
	config *Config
	name   string
}

// CreateConfig creates a new config instance
func CreateConfig() *Config {
	return &Config{
		JwtPayloadFields:  []string{"exp"},
		Alg:               "HS256",
		ExpirationMessage: "Token has expired",
		ErrorMessage:      "An error occurred while processing the request",
	}
}

// New creates a new JWT middleware
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Validate configuration
	if len(config.Secret) == 0 {
		return nil, fmt.Errorf("JWT secret is required")
	}

	// Validate algorithm
	switch config.Alg {
	case "HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512", "PS256", "PS384", "PS512":
		// Supported algorithms
	default:
		return nil, fmt.Errorf("unsupported JWT algorithm: %s", config.Alg)
	}

	return &JwtPlugin{
		next:   next,
		config: config,
		name:   name,
	}, nil
}

// logError logs all errors except for token expiration
// Uses the format: 2025-03-03T22:21:11Z ERR - Easy Traefik Rate Limit JWT: <error-message-here>
// With timestamp in grey color and ERR in red color
func (p *JwtPlugin) logError(err error, isExpired bool) {
	// Don't log token expiration errors
	if isExpired {
		return
	}
	
	// Get current time in UTC
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	
	// Format the log message
	logMessage := fmt.Sprintf("\033[90m%s\033[0m \033[31mERR\033[0m - Easy Traefik Rate Limit JWT: %s\n", 
		timestamp, err.Error())
	
	// Use mutex to ensure thread-safe writing and avoid interleaved output
	logMu.Lock()
	defer logMu.Unlock()
	
	// Write directly to stderr with synchronized access
	_, writeErr := stderr.Write([]byte(logMessage))
	if writeErr != nil {
		// If we can't write to stderr, not much we can do except try one more direct attempt
		fmt.Fprintf(os.Stderr, "Failed to log error: %v\n", writeErr)
	}
	
	// For file-based stderr, this would ensure it's flushed to disk
	if f, ok := stderr.(*os.File); ok {
		if err := f.Sync(); err != nil {
			// If sync fails, try one more direct attempt to log the error
			fmt.Fprintf(os.Stderr, "Failed to sync error log: %v\n", err)
		}
	}
}

// ServeHTTP implements the http.Handler interface
func (p *JwtPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check if this is a public route that bypasses JWT validation
	for _, route := range p.config.RoutesToBypassJwtValidation {
		if p.matchRoute(req, route.Match) {
			// This is a public route, inject headers if configured
			if route.InjectNewHeaders != nil {
				err := p.injectPublicHeaders(req, route.InjectNewHeaders)
				if err != nil {
					p.logError(err, false)
					p.respondWithError(rw, http.StatusBadRequest, p.config.ErrorMessage)
					return
				}
			}
			
			// Skip JWT validation and proceed to the next handler
			p.next.ServeHTTP(rw, req)
			return
		}
	}

	// Check for expiration bypass routes before extracting token
	var bypassExpiration bool
	
	for _, route := range p.config.RoutesToBypassTokenExpiration {
		if p.matchRoute(req, route.Match) {
			bypassExpiration = true
			break
		}
	}
	
	// Extract token from request
	token, err := p.extractToken(req)
	if err != nil {
		p.logError(err, false)
		p.respondWithError(rw, http.StatusUnauthorized, p.config.ErrorMessage)
		return
	}

	// Parse token with special handling for expiration
	var claims jwt.MapClaims
	var parsedToken *jwt.Token
	
	if bypassExpiration {
		// For expiration bypass routes, use a custom parser that ignores expiration
		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		claims = jwt.MapClaims{}
		
		parsedToken, err = parser.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			// Validate the algorithm
			if token.Method.Alg() != p.config.Alg {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			
			// Return the appropriate key based on the algorithm
			switch p.config.Alg[:2] {
			case "HS":
				return []byte(p.config.Secret[0]), nil
			default:
				return []byte(p.config.Secret[0]), nil
			}
		})
	} else {
		// Standard token parsing for non-bypass routes
		parsedToken, claims, err = p.parseToken(token)
	}
	
	if err != nil {
		// Check if the error is due to an expired token
		if strings.Contains(err.Error(), "token is expired") {
			// If this route bypasses expiration, proceed anyway
			if bypassExpiration {
				// This check confirms we have a signature error, not another kind of error
				if !strings.Contains(err.Error(), "signature is invalid") {
					goto TOKEN_VALID
				}
			}
			
			// Token is expired and route doesn't bypass expiration or has other errors
			// Don't log expiration errors
			p.respondWithError(rw, http.StatusUnauthorized, p.config.ExpirationMessage)
			return
		}
		
		// Log other JWT errors (not expiration)
		p.logError(err, false)
		p.respondWithError(rw, http.StatusUnauthorized, p.config.ErrorMessage)
		return
	}

TOKEN_VALID:
	// Check if token is valid
	if !parsedToken.Valid {
		err := fmt.Errorf("invalid token")
		p.logError(err, false)
		p.respondWithError(rw, http.StatusUnauthorized, p.config.ErrorMessage)
		return
	}

	// Check for required fields in the JWT payload
	for _, field := range p.config.JwtPayloadFields {
		if field != "exp" { // "exp" is already checked by the JWT library
			if _, ok := claims[field]; !ok {
				err := fmt.Errorf("required field missing: %s", field)
				p.logError(err, false)
				p.respondWithError(rw, http.StatusUnauthorized, p.config.ErrorMessage)
				return
			}
		}
	}

	// Inject headers from JWT payload
	if p.config.InjectNewHeaders != nil {
		err := p.injectHeaders(req, claims)
		if err != nil {
			p.logError(err, false)
			p.respondWithError(rw, http.StatusInternalServerError, p.config.ErrorMessage)
			return
		}
	}

	// Token is valid, proceed to the next handler
	p.next.ServeHTTP(rw, req)
}

// extractToken extracts the JWT token from the request
func (p *JwtPlugin) extractToken(req *http.Request) (string, error) {
	// Try each source in order
	for _, source := range p.config.Sources {
		switch source.Type {
		case "bearer":
			authHeader := req.Header.Get(source.Key)
			if authHeader != "" {
				// Extract token from "Bearer <token>"
				parts := strings.Split(authHeader, " ")
				if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
					return parts[1], nil
				}
			}
		case "header":
			tokenHeader := req.Header.Get(source.Key)
			if tokenHeader != "" {
				return tokenHeader, nil
			}
		case "query":
			tokenQuery := req.URL.Query().Get(source.Key)
			if tokenQuery != "" {
				return tokenQuery, nil
			}
		}
	}

	return "", fmt.Errorf("no token found in specified sources")
}

// parseToken parses and validates the JWT token
func (p *JwtPlugin) parseToken(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	// Create a map to store claims
	claims := jwt.MapClaims{}

	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Validate the algorithm
		if token.Method.Alg() != p.config.Alg {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Return the appropriate key based on the algorithm
		switch p.config.Alg[:2] {
		case "HS":
			return []byte(p.config.Secret[0]), nil
		case "RS", "PS", "ES":
			// For asymmetric algorithms, the secret would be a public key
			// This is a simplified implementation
			return []byte(p.config.Secret[0]), nil
		default:
			return nil, fmt.Errorf("unsupported algorithm: %s", p.config.Alg)
		}
	})

	return token, claims, err
}

// injectHeaders injects headers from JWT payload
func (p *JwtPlugin) injectHeaders(req *http.Request, claims jwt.MapClaims) error {
	for headerName, headerCfg := range p.config.InjectNewHeaders {
		for i, fromType := range headerCfg.From {
			if i >= len(headerCfg.Values) {
				continue
			}
			
			value := headerCfg.Values[i]
			
			if fromType == "JwtPayloadFields" {
				if claimValue, ok := claims[value]; ok {
					// Convert claim value to string
					var strValue string
					switch v := claimValue.(type) {
					case string:
						strValue = v
					case float64:
						strValue = fmt.Sprintf("%v", v)
					case bool:
						strValue = fmt.Sprintf("%v", v)
					default:
						strValue = fmt.Sprintf("%v", v)
					}
					
					req.Header.Set(headerName, strValue)
					break
				}
			} else if fromType == "Sources" {
				headerValue := req.Header.Get(value)
				if headerValue != "" {
					req.Header.Set(headerName, headerValue)
					break
				}
			}
		}
	}
	
	return nil
}

// injectPublicHeaders injects headers for public routes
func (p *JwtPlugin) injectPublicHeaders(req *http.Request, headers map[string]PublicHeaderValue) error {
	for headerName, headerCfg := range headers {
		// Flag to track if we found a value for this header
		valueFound := false
		
		// Try each source in order until we find a value
		for i, fromType := range headerCfg.From {
			if i >= len(headerCfg.Key) {
				continue
			}
			
			key := headerCfg.Key[i]
			
			if fromType == "Sources" {
				headerValue := req.Header.Get(key)
				if headerValue != "" {
					req.Header.Set(headerName, headerValue)
					valueFound = true
					break
				}
			} else {
				return fmt.Errorf("unsupported source type for public routes: %s", fromType)
			}
		}
		
		// If we didn't find a value for this header, return an error
		if !valueFound {
			return fmt.Errorf("required header missing for public route: %s", headerName)
		}
	}
	
	return nil
}

// matchRoute checks if a request matches a Traefik route matcher expression
func (p *JwtPlugin) matchRoute(req *http.Request, matchExpr string) bool {
	// Split the expression by logical operators
	if strings.Contains(matchExpr, "&&") {
		exprs := strings.Split(matchExpr, "&&")
		for _, expr := range exprs {
			expr = strings.TrimSpace(expr)
			if !p.matchSingleExpression(req, expr) {
				return false
			}
		}
		return true
	} else if strings.Contains(matchExpr, "||") {
		exprs := strings.Split(matchExpr, "||")
		for _, expr := range exprs {
			expr = strings.TrimSpace(expr)
			if p.matchSingleExpression(req, expr) {
				return true
			}
		}
		return false
	}
	
	return p.matchSingleExpression(req, matchExpr)
}

// matchSingleExpression matches a single Traefik route matcher expression
func (p *JwtPlugin) matchSingleExpression(req *http.Request, expr string) bool {
	// Parse expressions like Host(`example.com`), Method(`GET`), PathPrefix(`/api`)
	if strings.HasPrefix(expr, "Host(") && strings.HasSuffix(expr, ")") {
		host := extractValue(expr)
		return req.Host == host
	} else if strings.HasPrefix(expr, "Method(") && strings.HasSuffix(expr, ")") {
		method := extractValue(expr)
		return req.Method == method
	} else if strings.HasPrefix(expr, "PathPrefix(") && strings.HasSuffix(expr, ")") {
		prefix := extractValue(expr)
		return strings.HasPrefix(req.URL.Path, prefix)
	}
	
	// Unsupported expression
	return false
}

// extractValue extracts the value from a Traefik expression like Function(`value`)
func extractValue(expr string) string {
	// Find the opening backtick
	start := strings.Index(expr, "`")
	if start == -1 {
		return ""
	}
	
	// Find the closing backtick - search from the position after start
	end := strings.LastIndex(expr, "`")
	if end == -1 || end <= start {
		return ""
	}
	
	return expr[start+1 : end]
}

// respondWithError sends an error response with the given status and message
func (p *JwtPlugin) respondWithError(rw http.ResponseWriter, status int, message string) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	
	response := map[string]string{
		"message": message,
	}
	
	err := json.NewEncoder(rw).Encode(response)
	if err != nil {
		// Log encoding error but don't attempt to write another response
		p.logError(fmt.Errorf("error encoding response: %v", err), false)
	}
}