package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"time"
)

const (
	TokenKindEmailVerify   = "email_verify"
	TokenKindPasswordReset = "password_reset"
	TokenKindMFARecovery   = "mfa_recovery"

	EmailVerifyTokenTTL   = 24 * time.Hour
	PasswordResetTokenTTL = 30 * time.Minute

	userTokenBytes = 32
)

func generateOpaqueToken() (string, error) {
	buf := make([]byte, userTokenBytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	defer clear(buf)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashUserToken(secret []byte, kind, token string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("user_token:"))
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte(":"))
	_, _ = mac.Write([]byte(token))
	return mac.Sum(nil)
}
