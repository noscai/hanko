package credential_usage

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type ServiceTokenClaims struct {
	UserID   string `json:"sub"`
	TenantID string `json:"tenant_id"`
	jwt.RegisteredClaims
}

func validateServiceToken(tokenString string, secret string, expectedIssuer string) (*ServiceTokenClaims, error) {
	if secret == "" {
		return nil, fmt.Errorf("service token secret not configured")
	}

	token, err := jwt.ParseWithClaims(tokenString, &ServiceTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse service token: %w", err)
	}

	claims, ok := token.Claims.(*ServiceTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid service token claims")
	}

	if claims.UserID == "" {
		return nil, fmt.Errorf("service token missing user_id (sub)")
	}

	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("service token issuer mismatch: expected %s, got %s", expectedIssuer, claims.Issuer)
	}

	return claims, nil
}
