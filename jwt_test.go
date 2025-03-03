package easy_traefik_rate_limit_jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// Constants for common test values
const (
	TestSecret    = "test-secret"
	TestUserID    = "user123"
	BearerPrefix  = "Bearer "
	TestMobileID  = "mobile456"
	TestRole      = "admin"
)

// Create a signed token with the given claims
func createToken(secret string, claims map[string]interface{}) (string, error) {
	// Create a map claims object
	mapClaims := make(jwt.MapClaims)
	
	// Add all provided claims to the map
	for k, v := range claims {
		mapClaims[k] = v
	}
	
	// Create a new token with HS256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mapClaims)
	
	// Sign the token with the secret
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	
	return tokenString, nil
}

// Create a test HTTP handler
func createTestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("test handler called"))
		if err != nil {
			// Not much we can do here in test code, but handle the error
			fmt.Printf("error writing response: %v\n", err)
		}
	})
}

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()
	assert.NotNil(t, config)
	assert.Equal(t, []string{"exp"}, config.JwtPayloadFields)
	assert.Equal(t, "HS256", config.Alg)
	assert.Equal(t, "Token has expired", config.ExpirationMessage)
	assert.Equal(t, "An error occurred while processing the request", config.ErrorMessage)
}

func TestNew(t *testing.T) {
	config := &Config{
		JwtPayloadFields: []string{"exp"},
		Alg:              "HS256",
		Secret:           []string{TestSecret},
		Sources:          []Source{{Type: "bearer", Key: "Authorization"}},
	}

	handler, err := New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.NoError(t, err)
	assert.NotNil(t, handler)
}

func TestMissingSecret(t *testing.T) {
	config := &Config{
		JwtPayloadFields: []string{"exp"},
		Alg:              "HS256",
		Secret:           []string{},
		Sources:          []Source{{Type: "bearer", Key: "Authorization"}},
	}

	_, err := New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT secret is required")
}

func TestInvalidAlgorithm(t *testing.T) {
	config := &Config{
		JwtPayloadFields: []string{"exp"},
		Alg:              "INVALID",
		Secret:           []string{TestSecret},
		Sources:          []Source{{Type: "bearer", Key: "Authorization"}},
	}

	_, err := New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported JWT algorithm")
}

func TestJWTValidation(t *testing.T) {
	expiration := time.Now().Add(time.Hour).Unix()

	// Create a token
	token, err := createToken(TestSecret, map[string]interface{}{
		"exp": expiration,
		"_id": TestUserID,
	})
	assert.NoError(t, err)

	// Configure the plugin
	config := &Config{
		JwtPayloadFields: []string{"exp", "_id"},
		Alg:              "HS256",
		Secret:           []string{TestSecret},
		Sources:          []Source{{Type: "bearer", Key: "Authorization"}},
		InjectNewHeaders: map[string]HeaderValue{
			"X-User-ID": {
				From:   []string{"JwtPayloadFields"},
				Values: []string{"_id"},
			},
		},
	}

	// Create the plugin
	plugin, err := New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.NoError(t, err)

	// Make a request with the token
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("Authorization", BearerPrefix+token)
	recorder := httptest.NewRecorder()

	// Handle the request
	plugin.ServeHTTP(recorder, req)

	// Check that the handler was called and the header was set
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, TestUserID, req.Header.Get("X-User-ID"))
}

func TestJWTValidationWithRole(t *testing.T) {
	expiration := time.Now().Add(time.Hour).Unix()

	// Create a token with role
	token, err := createToken(TestSecret, map[string]interface{}{
		"exp":  expiration,
		"_id":  TestUserID,
		"role": TestRole,
	})
	assert.NoError(t, err)

	// Configure the plugin with role header
	config := &Config{
		JwtPayloadFields: []string{"exp", "_id", "role"},
		Alg:              "HS256",
		Secret:           []string{TestSecret},
		Sources:          []Source{{Type: "bearer", Key: "Authorization"}},
		InjectNewHeaders: map[string]HeaderValue{
			"X-User-ID": {
				From:   []string{"JwtPayloadFields"},
				Values: []string{"_id"},
			},
			"X-User-Role": {
				From:   []string{"JwtPayloadFields"},
				Values: []string{"role"},
			},
		},
	}

	// Create the plugin
	plugin, err := New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.NoError(t, err)

	// Make a request with the token
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("Authorization", BearerPrefix+token)
	recorder := httptest.NewRecorder()

	// Handle the request
	plugin.ServeHTTP(recorder, req)

	// Check that the handler was called and both headers were set
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, TestUserID, req.Header.Get("X-User-ID"))
	assert.Equal(t, TestRole, req.Header.Get("X-User-Role"))
}

func TestMultiSourceHeaderInjection(t *testing.T) {
	// Configure the plugin with fallback header injection
	config := &Config{
		JwtPayloadFields: []string{"exp", "_id"},
		Alg:              "HS256",
		Secret:           []string{TestSecret},
		Sources:          []Source{{Type: "bearer", Key: "Authorization"}},
		InjectNewHeaders: map[string]HeaderValue{
			"X-Rate-Limit-ID": {
				From:   []string{"JwtPayloadFields", "Sources"},
				Values: []string{"_id", "X-Mobile-ID"},
			},
		},
	}

	// Create the plugin
	plugin, err := New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.NoError(t, err)

	// Create a request with the source header but no JWT
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("X-Mobile-ID", TestMobileID)
	recorder := httptest.NewRecorder()

	// This should fail as JWT validation is required
	plugin.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	// Now test with a valid token that includes the _id field
	expiration := time.Now().Add(time.Hour).Unix()
	token, err := createToken(TestSecret, map[string]interface{}{
		"exp": expiration,
		"_id": TestUserID,
	})
	assert.NoError(t, err)

	req = httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("Authorization", BearerPrefix+token)
	recorder = httptest.NewRecorder()

	// This should succeed and use the JWT payload
	plugin.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, TestUserID, req.Header.Get("X-Rate-Limit-ID"))
}

func TestRouteMatcher(t *testing.T) {
	plugin := JwtPlugin{
		config: &Config{},
	}

	// Test Host match
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Host = "example.com"
	assert.True(t, plugin.matchRoute(req, "Host(`example.com`)"))
	assert.False(t, plugin.matchRoute(req, "Host(`other.com`)"))

	// Test Method match
	req = httptest.NewRequest(http.MethodPost, "http://example.com/test", nil)
	req.Host = "example.com"
	assert.True(t, plugin.matchRoute(req, "Method(`POST`)"))
	assert.False(t, plugin.matchRoute(req, "Method(`GET`)"))

	// Test PathPrefix match
	req = httptest.NewRequest(http.MethodGet, "http://example.com/api/users", nil)
	req.Host = "example.com"
	assert.True(t, plugin.matchRoute(req, "PathPrefix(`/api`)"))
	assert.False(t, plugin.matchRoute(req, "PathPrefix(`/admin`)"))

	// Test combined match
	req = httptest.NewRequest(http.MethodPost, "http://example.com/api/users", nil)
	req.Host = "example.com"
	assert.True(t, plugin.matchRoute(req, "Host(`example.com`) && Method(`POST`) && PathPrefix(`/api`)"))
	assert.False(t, plugin.matchRoute(req, "Host(`example.com`) && Method(`GET`) && PathPrefix(`/api`)"))
}

func TestExpiredToken(t *testing.T) {
	expiration := time.Now().Add(-time.Hour).Unix() // Expired token

	// Create a token
	token, err := createToken(TestSecret, map[string]interface{}{
		"exp": expiration,
		"_id": TestUserID,
	})
	assert.NoError(t, err)

	// Configure the plugin
	config := &Config{
		JwtPayloadFields:   []string{"exp", "_id"},
		Alg:                "HS256",
		Secret:             []string{TestSecret},
		Sources:            []Source{{Type: "bearer", Key: "Authorization"}},
		ExpirationMessage:  "Custom token expired message",
		ErrorMessage:       "Custom error message",
	}

	// Create the plugin
	plugin, err := New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.NoError(t, err)

	// Make a request with the expired token
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("Authorization", BearerPrefix+token)
	recorder := httptest.NewRecorder()

	// Handle the request
	plugin.ServeHTTP(recorder, req)

	// Check that we got an unauthorized response with the custom message
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	var response map[string]string
	err = json.Unmarshal(recorder.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Custom token expired message", response["message"])
}

func TestBypassTokenExpiration(t *testing.T) {
	expiration := time.Now().Add(-time.Hour).Unix() // Expired token

	// Create a token
	token, err := createToken(TestSecret, map[string]interface{}{
		"exp": expiration,
		"_id": TestUserID,
	})
	assert.NoError(t, err)

	// Configure the plugin with expiration bypass route
	config := &Config{
		JwtPayloadFields: []string{"exp", "_id"},
		Alg:              "HS256",
		Secret:           []string{TestSecret},
		Sources:          []Source{{Type: "bearer", Key: "Authorization"}},
		RoutesToBypassTokenExpiration: []RouteMatch{
			{Match: "Host(`localhost`) && Method(`GET`) && PathPrefix(`/bypass`)"},
		},
	}

	// Create the plugin
	plugin, err := New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.NoError(t, err)

	// Make a request with the expired token to a bypass route
	req := httptest.NewRequest(http.MethodGet, "http://localhost/bypass", nil)
	req.Host = "localhost"
	req.Header.Set("Authorization", BearerPrefix+token)
	recorder := httptest.NewRecorder()

	// Handle the request
	plugin.ServeHTTP(recorder, req)

	// Check that the handler was called despite the token being expired
	assert.Equal(t, http.StatusOK, recorder.Code)

	// Try with a non-bypass route
	req = httptest.NewRequest(http.MethodGet, "http://localhost/normal", nil)
	req.Host = "localhost"
	req.Header.Set("Authorization", BearerPrefix+token)
	recorder = httptest.NewRecorder()

	// Handle the request
	plugin.ServeHTTP(recorder, req)

	// Should fail due to expired token
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestPublicRoutes(t *testing.T) {
	// Configure the plugin with public routes
	config := &Config{
		JwtPayloadFields: []string{"exp", "_id"},
		Alg:              "HS256",
		Secret:           []string{TestSecret},
		Sources:          []Source{{Type: "bearer", Key: "Authorization"}},
		RoutesToBypassJwtValidation: []PublicRouteMatch{
			{
				Match: "Host(`localhost`) && Method(`GET`) && PathPrefix(`/public`)",
				InjectNewHeaders: map[string]PublicHeaderValue{
					"X-Rate-Limit-ID": {
						From: []string{"Sources"},
						Key:  []string{"X-Mobile-ID"},
					},
				},
			},
		},
	}

	// Create the plugin
	plugin, err := New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.NoError(t, err)

	// Make a request to a public route with a header to inject
	req := httptest.NewRequest(http.MethodGet, "http://localhost/public", nil)
	req.Host = "localhost"
	req.Header.Set("X-Mobile-ID", TestMobileID)
	recorder := httptest.NewRecorder()

	// Handle the request
	plugin.ServeHTTP(recorder, req)

	// Check that the handler was called and the header was injected
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, TestMobileID, req.Header.Get("X-Rate-Limit-ID"))

	// Test multiple fallback headers
	config = &Config{
		JwtPayloadFields: []string{"exp", "_id"},
		Alg:              "HS256",
		Secret:           []string{TestSecret},
		Sources:          []Source{{Type: "bearer", Key: "Authorization"}},
		RoutesToBypassJwtValidation: []PublicRouteMatch{
			{
				Match: "Host(`localhost`) && Method(`GET`) && PathPrefix(`/public`)",
				InjectNewHeaders: map[string]PublicHeaderValue{
					"X-Rate-Limit-ID": {
						From: []string{"Sources", "Sources"},
						Key:  []string{"X-Missing-ID", "X-Mobile-ID"},
					},
				},
			},
		},
	}

	// Create the plugin
	plugin, err = New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.NoError(t, err)

	// Make a request to a public route with only the second header
	req = httptest.NewRequest(http.MethodGet, "http://localhost/public", nil)
	req.Host = "localhost"
	req.Header.Set("X-Mobile-ID", TestMobileID)
	recorder = httptest.NewRecorder()

	// Handle the request
	plugin.ServeHTTP(recorder, req)

	// Check that the second header was used
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, TestMobileID, req.Header.Get("X-Rate-Limit-ID"))
}

func TestMultipleSources(t *testing.T) {
	expiration := time.Now().Add(time.Hour).Unix()

	// Create a token
	token, err := createToken(TestSecret, map[string]interface{}{
		"exp": expiration,
		"_id": TestUserID,
	})
	assert.NoError(t, err)

	// Configure the plugin with multiple sources
	config := &Config{
		JwtPayloadFields: []string{"exp", "_id"},
		Alg:              "HS256",
		Secret:           []string{TestSecret},
		Sources: []Source{
			{Type: "bearer", Key: "Authorization"},
			{Type: "header", Key: "X-Auth-Token"},
			{Type: "query", Key: "token"},
		},
		InjectNewHeaders: map[string]HeaderValue{
			"X-User-ID": {
				From:   []string{"JwtPayloadFields"},
				Values: []string{"_id"},
			},
		},
	}

	// Create the plugin
	plugin, err := New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.NoError(t, err)

	// Test with bearer token
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req1.Header.Set("Authorization", BearerPrefix+token)
	recorder1 := httptest.NewRecorder()
	plugin.ServeHTTP(recorder1, req1)
	assert.Equal(t, http.StatusOK, recorder1.Code)
	assert.Equal(t, TestUserID, req1.Header.Get("X-User-ID"))

	// Test with custom header
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req2.Header.Set("X-Auth-Token", token)
	recorder2 := httptest.NewRecorder()
	plugin.ServeHTTP(recorder2, req2)
	assert.Equal(t, http.StatusOK, recorder2.Code)
	assert.Equal(t, TestUserID, req2.Header.Get("X-User-ID"))

	// Test with query parameter
	req3 := httptest.NewRequest(http.MethodGet, "http://localhost?token="+token, nil)
	recorder3 := httptest.NewRecorder()
	plugin.ServeHTTP(recorder3, req3)
	assert.Equal(t, http.StatusOK, recorder3.Code)
	assert.Equal(t, TestUserID, req3.Header.Get("X-User-ID"))
}

func TestErrorMessageConsistency(t *testing.T) {
	// Configure the plugin with custom error messages
	config := &Config{
		JwtPayloadFields:   []string{"exp", "_id"},
		Alg:                "HS256",
		Secret:             []string{TestSecret},
		Sources:            []Source{{Type: "bearer", Key: "Authorization"}},
		ExpirationMessage:  "Custom token expired message",
		ErrorMessage:       "Custom generic error message",
	}

	// Create the plugin
	plugin, err := New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.NoError(t, err)

	// Test 1: Missing token
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	recorder1 := httptest.NewRecorder()
	plugin.ServeHTTP(recorder1, req1)
	assert.Equal(t, http.StatusUnauthorized, recorder1.Code)
	
	var response1 map[string]string
	err = json.Unmarshal(recorder1.Body.Bytes(), &response1)
	assert.NoError(t, err)
	assert.Equal(t, "Custom generic error message", response1["message"], "Should use generic error message for missing token")

	// Test 2: Invalid signature
	// Create a token with a different secret
	tokenWithWrongSig, err := createToken("wrong-secret", map[string]interface{}{
		"exp": time.Now().Add(time.Hour).Unix(),
		"_id": TestUserID,
	})
	assert.NoError(t, err)
	
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req2.Header.Set("Authorization", BearerPrefix+tokenWithWrongSig)
	recorder2 := httptest.NewRecorder()
	plugin.ServeHTTP(recorder2, req2)
	assert.Equal(t, http.StatusUnauthorized, recorder2.Code)
	
	var response2 map[string]string
	err = json.Unmarshal(recorder2.Body.Bytes(), &response2)
	assert.NoError(t, err)
	assert.Equal(t, "Custom generic error message", response2["message"], "Should use generic error message for invalid signature")

	// Test 3: Missing required field
	tokenWithMissingField, err := createToken(TestSecret, map[string]interface{}{
		"exp": time.Now().Add(time.Hour).Unix(),
		// Missing "_id" field
	})
	assert.NoError(t, err)
	
	req3 := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req3.Header.Set("Authorization", BearerPrefix+tokenWithMissingField)
	recorder3 := httptest.NewRecorder()
	plugin.ServeHTTP(recorder3, req3)
	assert.Equal(t, http.StatusUnauthorized, recorder3.Code)
	
	var response3 map[string]string
	err = json.Unmarshal(recorder3.Body.Bytes(), &response3)
	assert.NoError(t, err)
	assert.Equal(t, "Custom generic error message", response3["message"], "Should use generic error message for missing required field")
}

func TestPublicRouteHeaderError(t *testing.T) {
	// Configure the plugin with public routes that require a specific header
	config := &Config{
		JwtPayloadFields: []string{"exp", "_id"},
		Alg:              "HS256",
		Secret:           []string{TestSecret},
		Sources:          []Source{{Type: "bearer", Key: "Authorization"}},
		ErrorMessage:     "Custom generic error message",
		RoutesToBypassJwtValidation: []PublicRouteMatch{
			{
				Match: "Host(`localhost`) && Method(`GET`) && PathPrefix(`/public`)",
				InjectNewHeaders: map[string]PublicHeaderValue{
					"X-Rate-Limit-ID": {
						From: []string{"Sources"},
						Key:  []string{"X-Required-Header"},
					},
				},
			},
		},
	}

	// Create the plugin
	plugin, err := New(context.Background(), createTestHandler(), config, "test-jwt-plugin")
	assert.NoError(t, err)

	// Make a request to a public route WITHOUT the required header
	req := httptest.NewRequest(http.MethodGet, "http://localhost/public", nil)
	req.Host = "localhost"
	// Intentionally NOT setting X-Required-Header
	recorder := httptest.NewRecorder()

	// Handle the request
	plugin.ServeHTTP(recorder, req)

	// Should fail with the generic error message
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	
	var response map[string]string
	err = json.Unmarshal(recorder.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Custom generic error message", response["message"], "Should use generic error message when header is missing for public route")
}