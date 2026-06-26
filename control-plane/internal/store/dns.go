package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) CreateRecord(ctx context.Context, r *DNSRecord) (*DNSRecord, error) {
	rows, err := s.Pool.Query(ctx,
		`INSERT INTO dns_records (domain_id, type, name, content, ttl, priority, proxied)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
		r.DomainID, r.Type, r.Name, r.Content, r.TTL, r.Priority, r.Proxied)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[DNSRecord])
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) ListRecords(ctx context.Context, domainID uuid.UUID) ([]DNSRecord, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT * FROM dns_records WHERE domain_id=$1 ORDER BY name, type`, domainID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[DNSRecord])
}

// ListProxiedRecords returns the proxied records for a domain (origins to proxy to).
func (s *Store) ListProxiedRecords(ctx context.Context, domainID uuid.UUID) ([]DNSRecord, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT * FROM dns_records WHERE domain_id=$1 AND proxied=true AND type IN ('A','AAAA','CNAME') ORDER BY name`,
		domainID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[DNSRecord])
}

func (s *Store) GetRecord(ctx context.Context, id uuid.UUID) (*DNSRecord, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM dns_records WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[DNSRecord])
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) UpdateRecord(ctx context.Context, r *DNSRecord) (*DNSRecord, error) {
	rows, err := s.Pool.Query(ctx,
		`UPDATE dns_records SET type=$2, name=$3, content=$4, ttl=$5, priority=$6, proxied=$7, updated_at=now()
		 WHERE id=$1 RETURNING *`,
		r.ID, r.Type, r.Name, r.Content, r.TTL, r.Priority, r.Proxied)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[DNSRecord])
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) DeleteRecord(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM dns_records WHERE id=$1`, id)
	return err
}
