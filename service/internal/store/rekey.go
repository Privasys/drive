package store

import (
	"context"
	"errors"
	"sort"
)

// Re-keying the identifiers Drive holds.
//
// Drive knows people by the subject its sign-in gives. When Drive moves from
// the IdP's legacy shared mode (the account id) to its own per-app subjects,
// every place Drive stored a person's identifier has to move with it, or a
// holder signs in to an empty Drive. The operator gets the mapping from the
// IdP (subjects for Drive's client, one per account) and applies it here, in
// one transaction.
//
// The append-only audit log is left as it was: it records who did what at
// the time, and rewriting history is not what a re-key is for.

// subjectColumns lists every column holding a person's identifier, with the
// form it is stored in (a "subject:" prefix for user grants).
var subjectColumns = []struct {
	table, column, prefix string
}{
	{"members", "user_sub", ""},
	{"grants", "subject", "subject:"},
	// A share the person opened through their assistant (assistantshares.go).
	{"grants", "subject", "assistant-for:"},
	{"grants", "created_by", ""},
	{"nodes", "created_by", ""},
	{"file_versions", "actor", ""},
	{"changes", "actor", ""},
	{"recoveries", "grantee_sub", ""},
	{"recoveries", "requested_by", ""},
	{"recovery_approvals", "approver_sub", ""},
	{"link_requests", "requester_sub", ""},
	{"link_requests", "decided_by", ""},
	{"access_events", "sub", ""},
}

// ListSubjects returns every distinct identifier Drive holds for a person
// (user grants without their prefix), for the operator to map.
func (s *Store) ListSubjects(ctx context.Context) ([]string, error) {
	seen := map[string]bool{}
	for _, c := range subjectColumns {
		rows, err := s.DB.QueryContext(ctx, s.q(`SELECT DISTINCT `+c.column+` FROM `+c.table+` WHERE `+c.column+` <> ''`))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				rows.Close()
				return nil, err
			}
			if c.prefix != "" {
				if len(v) <= len(c.prefix) || v[:len(c.prefix)] != c.prefix {
					continue
				}
				v = v[len(c.prefix):]
			}
			seen[v] = true
		}
		rows.Close()
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}

// RekeySubjects rewrites every identifier in mapping (old to new), in one
// transaction, and returns how many rows each column changed. A mapping that
// sends two identifiers to one, or onto an identifier already present, is
// refused: it would merge two people.
func (s *Store) RekeySubjects(ctx context.Context, mapping map[string]string) (map[string]int64, error) {
	if len(mapping) == 0 {
		return nil, errors.New("empty mapping")
	}
	targets := map[string]bool{}
	for old, nu := range mapping {
		if old == "" || nu == "" || old == nu {
			return nil, errors.New("mapping entries must be non-empty and change something")
		}
		if targets[nu] {
			return nil, errors.New("two identifiers map to one")
		}
		targets[nu] = true
	}
	existing, err := s.ListSubjects(ctx)
	if err != nil {
		return nil, err
	}
	for nu := range targets {
		// A chain (a to b, b to c) would move a's records onto c.
		if _, isSource := mapping[nu]; isSource {
			return nil, errors.New("an identifier is both renamed and a new name: " + nu)
		}
	}
	for _, e := range existing {
		if targets[e] {
			return nil, errors.New("a new identifier is already in use: " + e)
		}
	}
	for nu := range targets {
		if s.SubjectRetired(ctx, nu) {
			return nil, errors.New("a new identifier was retired by an earlier re-key: " + nu)
		}
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	counts := map[string]int64{}
	for _, c := range subjectColumns {
		for old, nu := range mapping {
			res, err := tx.ExecContext(ctx,
				s.q(`UPDATE `+c.table+` SET `+c.column+` = ? WHERE `+c.column+` = ?`),
				c.prefix+nu, c.prefix+old)
			if err != nil {
				return nil, err
			}
			n, _ := res.RowsAffected()
			counts[c.table+"."+c.column] += n
		}
	}
	// Retire the old identifiers in the same transaction. A session opened
	// before the switch keeps asserting one; without this Drive would see a
	// stranger and give them an empty personal Drive, beside the real one
	// and colliding with its vault key.
	for old := range mapping {
		if _, err := tx.ExecContext(ctx,
			s.q(`INSERT INTO retired_subjects (sub) VALUES (?) ON CONFLICT (sub) DO NOTHING`), old); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return counts, nil
}

// SubjectRetired reports whether a re-key retired this identifier.
func (s *Store) SubjectRetired(ctx context.Context, sub string) bool {
	if sub == "" {
		return false
	}
	var one int
	return s.DB.QueryRowContext(ctx, s.q(`SELECT 1 FROM retired_subjects WHERE sub = ?`), sub).Scan(&one) == nil
}
