package auth

import (
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// generateTOTP creates a new TOTP secret/key for the given account.
func generateTOTP(issuer, account string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
}

// validateTOTP reports whether code is currently valid for secret.
func validateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}
