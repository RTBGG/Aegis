package store

import "context"

// GetPKI returns the stored cert+key PEM for a named keypair (e.g. "edge-ca").
// Returns ErrNotFound when absent.
func (s *Store) GetPKI(ctx context.Context, name string) (certPEM, keyPEM string, err error) {
	err = s.Pool.QueryRow(ctx,
		`SELECT cert_pem, key_pem FROM pki WHERE name=$1`, name).Scan(&certPEM, &keyPEM)
	return certPEM, keyPEM, err
}

// SavePKI stores a named keypair, keeping any existing row (first-writer wins,
// so concurrent control-plane boots converge on one CA).
func (s *Store) SavePKI(ctx context.Context, name, certPEM, keyPEM string) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO pki (name, cert_pem, key_pem) VALUES ($1,$2,$3)
		 ON CONFLICT (name) DO NOTHING`, name, certPEM, keyPEM)
	return err
}
