package crypto

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

type TokenClaims struct {
	AgentID string
	Scopes  []string
	JTI     string
}

// IssueToken creates a PASETO v4 public token
func IssueToken(agentID string, scopes []string, ttl time.Duration, signingKey ed25519.PrivateKey, jti string) (string, error) {
	token := paseto.NewToken()
	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(time.Now().Add(ttl))
	
	if err := token.Set("agent_id", agentID); err != nil {
		return "", err
	}
	if err := token.Set("scopes", scopes); err != nil {
		return "", err
	}
	token.SetJti(jti)

	key, err := paseto.NewV4AsymmetricSecretKeyFromBytes(signingKey)
	if err != nil {
		return "", err
	}

	return token.V4Sign(key, nil), nil
}

// ValidateToken verifies a PASETO v4 public token
func ValidateToken(tokenString string, publicKey ed25519.PublicKey) (*TokenClaims, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	key, err := paseto.NewV4AsymmetricPublicKeyFromBytes(publicKey)
	if err != nil {
		return nil, err
	}

	token, err := parser.ParseV4Public(key, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	var claims TokenClaims
	if err := token.Get("agent_id", &claims.AgentID); err != nil {
		return nil, err
	}
	if err := token.Get("scopes", &claims.Scopes); err != nil {
		return nil, err
	}
	claims.JTI, _ = token.GetJti()

	return &claims, nil
}
