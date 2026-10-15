package registry

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// moveTables are every table that holds a home's rows, parents first.
var moveTables = []string{"homes", "tombstones", "suspensions", "away", "push", "tokens"}

// moveChunk bounds the homes named in one statement.
const moveChunk = 200

// MoveTo copies the rows of every home that keep allows into the registry
// at path, which Open creates if it is not there. With drop, it then
// deletes them here. It returns how many homes it moved. It is for an
// operator moving homes to another shard; the service never calls it.
//
// What the destination holds is never made older: a home's roster is taken
// only when its rosterSeq is higher, other rows only when the destination
// lacks them, and a tombstone deletes the home it names. So the same call
// exports into an empty file and merges that file into a shard that has
// heard from the homes since. deploy/README.md, "Shards", has the order.
func (r *Registry) MoveTo(path string, keep func(home string) bool, drop bool) (int, error) {
	dst, err := Open(path)
	if err != nil {
		return 0, err
	}
	if err := dst.Close(); err != nil {
		return 0, err
	}
	ctx := context.Background()
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `ATTACH DATABASE ? AS dst`, "file:"+path); err != nil {
		return 0, err
	}
	defer func() { _, _ = conn.ExecContext(ctx, `DETACH DATABASE dst`) }()

	homes, err := movingHomes(ctx, conn, keep)
	if err != nil {
		return 0, err
	}
	columns := map[string]string{}
	for _, t := range moveTables {
		if columns[t], err = tableColumns(ctx, conn, t); err != nil {
			return 0, err
		}
	}
	moved := 0
	for len(homes) > 0 {
		chunk := homes[:min(len(homes), moveChunk)]
		homes = homes[len(chunk):]
		if err := moveChunkOf(ctx, conn, columns, chunk, drop); err != nil {
			return moved, err
		}
		if drop {
			for _, h := range chunk {
				r.forgetSuspensions(h)
			}
		}
		moved += len(chunk)
	}
	return moved, nil
}

// movingHomes is every home, live or purged, that keep allows.
func movingHomes(ctx context.Context, conn *sql.Conn, keep func(string) bool) ([]string, error) {
	rows, err := conn.QueryContext(ctx, `SELECT home FROM homes UNION SELECT home FROM tombstones`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var homes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		if keep(h) {
			homes = append(homes, h)
		}
	}
	return homes, rows.Err()
}

// moveChunkOf copies, and with drop deletes, one chunk of homes in one
// transaction.
func moveChunkOf(ctx context.Context, conn *sql.Conn, columns map[string]string, chunk []string, drop bool) error {
	args := make([]any, len(chunk))
	for i, h := range chunk {
		args[i] = h
	}
	in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",") + ")"
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, t := range moveTables {
		q := fmt.Sprintf(`INSERT OR IGNORE INTO dst.%s (%s) SELECT %s FROM main.%s WHERE home IN %s`, t, columns[t], columns[t], t, in)
		if t == "homes" {
			// WHERE true keeps SQLite from reading ON as a join.
			q = fmt.Sprintf(`INSERT INTO dst.homes (%s) SELECT %s FROM main.homes WHERE home IN %s AND true
				ON CONFLICT (home) DO UPDATE SET roster = excluded.roster, roster_seq = excluded.roster_seq,
					roster_ms = excluded.roster_ms, grant_id = excluded.grant_id
				WHERE excluded.roster_seq > dst.homes.roster_seq`, columns[t], columns[t], in)
		}
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("registry: moving %s: %w", t, err)
		}
	}
	// A home purged here meanwhile is purged there too; its rows go with it.
	if _, err := tx.ExecContext(ctx, `DELETE FROM dst.homes WHERE home IN (SELECT home FROM dst.tombstones) AND home IN `+in, args...); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM dst.suspensions WHERE home IN (SELECT home FROM dst.tombstones) AND home IN `+in, args...); err != nil {
		return err
	}
	if drop {
		// Children first, so the cascades find nothing left.
		for i := len(moveTables) - 1; i >= 0; i-- {
			if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM main.%s WHERE home IN %s`, moveTables[i], in), args...); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// tableColumns is a table's columns, comma separated, as this file has
// them, so a column added later lines up in both files.
func tableColumns(ctx context.Context, conn *sql.Conn, table string) (string, error) {
	rows, err := conn.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return "", err
		}
		cols = append(cols, c)
	}
	if len(cols) == 0 {
		return "", fmt.Errorf("registry: no table %s", table)
	}
	return strings.Join(cols, ", "), rows.Err()
}
