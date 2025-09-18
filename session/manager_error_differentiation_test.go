// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/session"
)

func TestSessionErrorDifferentiation(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/fake-session.schema.json")

	t.Run("case=no credentials provided", func(t *testing.T) {
		// Create a request without any session credentials
		req := testhelpers.NewTestHTTPRequest(t, "GET", "/sessions/whoami", nil)

		// Fetch session should return ErrNoCredentialsForSession
		_, err := reg.SessionManager().FetchFromRequest(ctx, req)
		require.Error(t, err)

		var noActiveSessionErr *session.ErrNoActiveSessionFound
		require.True(t, errors.As(err, &noActiveSessionErr))
		assert.True(t, noActiveSessionErr.CredentialsMissing(), "Should indicate credentials are missing")
		assert.False(t, noActiveSessionErr.SessionExisted(), "Should indicate session did not exist")
	})

	t.Run("case=invalid token provided", func(t *testing.T) {
		// Create a request with an invalid/non-existent session token
		req := testhelpers.NewTestHTTPRequest(t, "GET", "/sessions/whoami", nil)
		req.Header.Set("X-Session-Token", "invalid-token-that-does-not-exist")

		// Fetch session should return ErrNoActiveSessionFound (session not found)
		_, err := reg.SessionManager().FetchFromRequest(ctx, req)
		require.Error(t, err)

		var noActiveSessionErr *session.ErrNoActiveSessionFound
		require.True(t, errors.As(err, &noActiveSessionErr))
		assert.False(t, noActiveSessionErr.CredentialsMissing(), "Should indicate credentials were provided")
		assert.False(t, noActiveSessionErr.SessionExisted(), "Should indicate session did not exist")
	})

	t.Run("case=expired session", func(t *testing.T) {
		// Create an identity and session using the same pattern as existing tests
		i := identity.Identity{Traits: []byte("{}")}
		require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(ctx, &i))

		req := testhelpers.NewTestHTTPRequest(t, "GET", "/sessions/whoami", nil)
		s, err := session.NewActiveSession(req, &i, conf, time.Now(), identity.CredentialsTypePassword, identity.AuthenticatorAssuranceLevel1)
		require.NoError(t, err)

		// Manually expire the session by setting expiry to past
		s.ExpiresAt = time.Now().Add(-time.Hour)
		require.NoError(t, reg.SessionPersister().UpsertSession(ctx, s))

		// Create a request with the expired session token
		req2 := testhelpers.NewTestHTTPRequest(t, "GET", "/sessions/whoami", nil)
		req2.Header.Set("X-Session-Token", s.Token)

		// Fetch session should return ErrSessionIsInactive
		_, err = reg.SessionManager().FetchFromRequest(ctx, req2)
		require.Error(t, err)

		var noActiveSessionErr *session.ErrNoActiveSessionFound
		require.True(t, errors.As(err, &noActiveSessionErr))
		assert.False(t, noActiveSessionErr.CredentialsMissing(), "Should indicate credentials were provided")
		assert.True(t, noActiveSessionErr.SessionExisted(), "Should indicate session existed but was inactive")
	})

	t.Run("case=deactivated session", func(t *testing.T) {
		// Create an identity and session using the same pattern as existing tests
		i := identity.Identity{Traits: []byte("{}")}
		require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(ctx, &i))

		req := testhelpers.NewTestHTTPRequest(t, "GET", "/sessions/whoami", nil)
		s, err := session.NewActiveSession(req, &i, conf, time.Now(), identity.CredentialsTypePassword, identity.AuthenticatorAssuranceLevel1)
		require.NoError(t, err)

		// Manually deactivate the session
		s.Active = false
		require.NoError(t, reg.SessionPersister().UpsertSession(ctx, s))

		// Create a request with the deactivated session token
		req2 := testhelpers.NewTestHTTPRequest(t, "GET", "/sessions/whoami", nil)
		req2.Header.Set("X-Session-Token", s.Token)

		// Fetch session should return ErrSessionIsInactive
		_, err = reg.SessionManager().FetchFromRequest(ctx, req2)
		require.Error(t, err)

		var noActiveSessionErr *session.ErrNoActiveSessionFound
		require.True(t, errors.As(err, &noActiveSessionErr))
		assert.False(t, noActiveSessionErr.CredentialsMissing(), "Should indicate credentials were provided")
		assert.True(t, noActiveSessionErr.SessionExisted(), "Should indicate session existed but was inactive")
	})

	t.Run("case=valid active session", func(t *testing.T) {
		// Create an identity and session using the same pattern as existing tests
		i := identity.Identity{Traits: []byte("{}")}
		require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(ctx, &i))

		req := testhelpers.NewTestHTTPRequest(t, "GET", "/sessions/whoami", nil)
		s, err := session.NewActiveSession(req, &i, conf, time.Now(), identity.CredentialsTypePassword, identity.AuthenticatorAssuranceLevel1)
		require.NoError(t, err)

		// Persist the session to the database
		require.NoError(t, reg.SessionPersister().UpsertSession(ctx, s))

		// Create a request with the valid session token
		req2 := testhelpers.NewTestHTTPRequest(t, "GET", "/sessions/whoami", nil)
		req2.Header.Set("X-Session-Token", s.Token)

		// Fetch session should succeed
		fetchedSession, err := reg.SessionManager().FetchFromRequest(ctx, req2)
		require.NoError(t, err)
		assert.Equal(t, s.ID, fetchedSession.ID)
		assert.Equal(t, s.Token, fetchedSession.Token)
	})
}

func TestSessionErrorConstructorFunctions(t *testing.T) {
	t.Run("case=NewErrNoActiveSessionFound", func(t *testing.T) {
		err := session.NewErrNoActiveSessionFound()
		assert.False(t, err.CredentialsMissing())
		assert.False(t, err.SessionExisted())
	})

	t.Run("case=NewErrNoCredentialsForSession", func(t *testing.T) {
		err := session.NewErrNoCredentialsForSession()
		assert.True(t, err.CredentialsMissing())
		assert.False(t, err.SessionExisted())
	})

	t.Run("case=NewErrSessionIsInactive", func(t *testing.T) {
		err := session.NewErrSessionIsInactive()
		assert.False(t, err.CredentialsMissing())
		assert.True(t, err.SessionExisted())
	})
}

func TestSessionErrorDifferentiationInHandler(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/fake-session.schema.json")

	// Set up a test server using the same helper as other tests
	ts, _, _, _ := testhelpers.NewKratosServerWithCSRFAndRouters(t, reg)
	conf.MustSet(ctx, "public.base_url", ts.URL)

	t.Run("case=no credentials returns correct error", func(t *testing.T) {
		client := testhelpers.NewClientWithCookies(t)
		res, err := client.Get(ts.URL + session.RouteWhoami)
		require.NoError(t, err)
		defer res.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})

	t.Run("case=invalid token returns correct error", func(t *testing.T) {
		client := testhelpers.NewClientWithCookies(t)
		req, _ := http.NewRequest("GET", ts.URL+session.RouteWhoami, nil)
		req.Header.Set("X-Session-Token", "invalid-token")

		res, err := client.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})
}

func TestSessionErrorDifferentiationHTTPResponses(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/fake-session.schema.json")

	// Set up a test server using the same helper as other tests
	ts, _, _, _ := testhelpers.NewKratosServerWithCSRFAndRouters(t, reg)
	conf.MustSet(ctx, "public.base_url", ts.URL)

	t.Run("case=no credentials returns correct error message", func(t *testing.T) {
		client := testhelpers.NewClientWithCookies(t)
		res, err := client.Get(ts.URL + session.RouteWhoami)
		require.NoError(t, err)
		defer res.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

		// Parse the error response
		var errorResponse map[string]interface{}
		require.NoError(t, json.NewDecoder(res.Body).Decode(&errorResponse))

		// Check that the error contains the expected reason
		errorObj, ok := errorResponse["error"].(map[string]interface{})
		require.True(t, ok, "Error response should contain 'error' object")

		reason, ok := errorObj["reason"].(string)
		require.True(t, ok, "Error object should contain 'reason' field")
		assert.Equal(t, "No valid session credentials found in the request.", reason)
	})

	t.Run("case=invalid token returns correct error message", func(t *testing.T) {
		client := testhelpers.NewClientWithCookies(t)
		req, _ := http.NewRequest("GET", ts.URL+session.RouteWhoami, nil)
		req.Header.Set("X-Session-Token", "invalid-token-that-does-not-exist")

		res, err := client.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

		// Parse the error response
		var errorResponse map[string]interface{}
		require.NoError(t, json.NewDecoder(res.Body).Decode(&errorResponse))

		// Check that the error contains the expected reason
		errorObj, ok := errorResponse["error"].(map[string]interface{})
		require.True(t, ok, "Error response should contain 'error' object")

		reason, ok := errorObj["reason"].(string)
		require.True(t, ok, "Error object should contain 'reason' field")
		assert.Equal(t, "No valid session credentials found in the request.", reason)
	})

	t.Run("case=expired session returns correct error message", func(t *testing.T) {
		// Create an identity and session using the same pattern as existing tests
		i := identity.Identity{Traits: []byte("{}")}
		require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(ctx, &i))

		req := testhelpers.NewTestHTTPRequest(t, "GET", "/sessions/whoami", nil)
		s, err := session.NewActiveSession(req, &i, conf, time.Now(), identity.CredentialsTypePassword, identity.AuthenticatorAssuranceLevel1)
		require.NoError(t, err)

		// Manually expire the session by setting expiry to past
		s.ExpiresAt = time.Now().Add(-time.Hour)
		require.NoError(t, reg.SessionPersister().UpsertSession(ctx, s))

		// Create HTTP request with the expired session token
		client := testhelpers.NewClientWithCookies(t)
		req2, _ := http.NewRequest("GET", ts.URL+session.RouteWhoami, nil)
		req2.Header.Set("X-Session-Token", s.Token)

		res, err := client.Do(req2)
		require.NoError(t, err)
		defer res.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

		// Parse the error response
		var errorResponse map[string]interface{}
		require.NoError(t, json.NewDecoder(res.Body).Decode(&errorResponse))

		// Check that the error contains the expected reason
		errorObj, ok := errorResponse["error"].(map[string]interface{})
		require.True(t, ok, "Error response should contain 'error' object")

		reason, ok := errorObj["reason"].(string)
		require.True(t, ok, "Error object should contain 'reason' field")
		assert.Equal(t, "The session is inactive. Please log in again.", reason)
	})

	t.Run("case=deactivated session returns correct error message", func(t *testing.T) {
		// Create an identity and session using the same pattern as existing tests
		i := identity.Identity{Traits: []byte("{}")}
		require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(ctx, &i))

		req := testhelpers.NewTestHTTPRequest(t, "GET", "/sessions/whoami", nil)
		s, err := session.NewActiveSession(req, &i, conf, time.Now(), identity.CredentialsTypePassword, identity.AuthenticatorAssuranceLevel1)
		require.NoError(t, err)

		// Manually deactivate the session
		s.Active = false
		require.NoError(t, reg.SessionPersister().UpsertSession(ctx, s))

		// Create HTTP request with the deactivated session token
		client := testhelpers.NewClientWithCookies(t)
		req2, _ := http.NewRequest("GET", ts.URL+session.RouteWhoami, nil)
		req2.Header.Set("X-Session-Token", s.Token)

		res, err := client.Do(req2)
		require.NoError(t, err)
		defer res.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

		// Parse the error response
		var errorResponse map[string]interface{}
		require.NoError(t, json.NewDecoder(res.Body).Decode(&errorResponse))

		// Check that the error contains the expected reason
		errorObj, ok := errorResponse["error"].(map[string]interface{})
		require.True(t, ok, "Error response should contain 'error' object")

		reason, ok := errorObj["reason"].(string)
		require.True(t, ok, "Error object should contain 'reason' field")
		assert.Equal(t, "The session is inactive. Please log in again.", reason)
	})

	t.Run("case=valid session returns success", func(t *testing.T) {
		// Create an identity and session using the same pattern as existing tests
		i := identity.Identity{Traits: []byte("{}")}
		require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(ctx, &i))

		req := testhelpers.NewTestHTTPRequest(t, "GET", "/sessions/whoami", nil)
		s, err := session.NewActiveSession(req, &i, conf, time.Now(), identity.CredentialsTypePassword, identity.AuthenticatorAssuranceLevel1)
		require.NoError(t, err)

		// Persist the session to the database
		require.NoError(t, reg.SessionPersister().UpsertSession(ctx, s))

		// Create HTTP request with the valid session token
		client := testhelpers.NewClientWithCookies(t)
		req2, _ := http.NewRequest("GET", ts.URL+session.RouteWhoami, nil)
		req2.Header.Set("X-Session-Token", s.Token)

		res, err := client.Do(req2)
		require.NoError(t, err)
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode)

		// Parse the session response
		var sessionResponse map[string]interface{}
		require.NoError(t, json.NewDecoder(res.Body).Decode(&sessionResponse))

		// Check that the response contains session data
		assert.Contains(t, sessionResponse, "id")
		assert.Contains(t, sessionResponse, "identity")
	})
}
