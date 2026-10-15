package oauth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// The authorization server's disk state, in a SQLite file of its own:
// clients that registered dynamically, consents in progress, the agents
// owners approved, and the hashes of tokens. No token, code or request id is
// stored as itself: each is a random secret held by its bearer, and the file
// keeps its SHA-256. Deleted rows are overwritten (secure_delete).

type store struct {
	db *sql.DB
}

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=secure_delete(ON)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS clients (
	client_id TEXT PRIMARY KEY,
	secret BLOB,
	auth_method TEXT NOT NULL,
	name TEXT NOT NULL,
	uri TEXT NOT NULL,
	redirect_uris TEXT NOT NULL,
	created_ms INTEGER NOT NULL,
	used_ms INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS requests (
	rid BLOB PRIMARY KEY,
	code TEXT NOT NULL UNIQUE,
	browser BLOB NOT NULL,
	client_id TEXT NOT NULL,
	client_name TEXT NOT NULL,
	client_host TEXT NOT NULL,
	verified INTEGER NOT NULL,
	redirect_uri TEXT NOT NULL,
	state TEXT NOT NULL,
	challenge TEXT NOT NULL,
	scope TEXT NOT NULL,
	resource TEXT NOT NULL,
	kid TEXT NOT NULL,
	agent_key BLOB NOT NULL UNIQUE,
	created_ms INTEGER NOT NULL,
	expires_ms INTEGER NOT NULL,
	status TEXT NOT NULL,
	home TEXT NOT NULL DEFAULT '',
	agent TEXT NOT NULL DEFAULT '',
	granted TEXT NOT NULL DEFAULT '',
	shard TEXT NOT NULL DEFAULT '',
	authz BLOB UNIQUE,
	authz_ms INTEGER NOT NULL DEFAULT 0,
	authz_used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS agents (
	home TEXT NOT NULL,
	agent TEXT NOT NULL,
	agent_key BLOB NOT NULL,
	kid TEXT NOT NULL,
	client_id TEXT NOT NULL,
	scope TEXT NOT NULL,
	shard TEXT NOT NULL,
	expires_ms INTEGER NOT NULL,
	created_ms INTEGER NOT NULL,
	PRIMARY KEY (home, agent)
);
CREATE TABLE IF NOT EXISTS tokens (
	hash BLOB PRIMARY KEY,
	kind TEXT NOT NULL,
	family BLOB NOT NULL,
	client_id TEXT NOT NULL,
	home TEXT NOT NULL,
	agent TEXT NOT NULL,
	scope TEXT NOT NULL,
	resource TEXT NOT NULL,
	expires_ms INTEGER NOT NULL,
	used INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY (home, agent) REFERENCES agents(home, agent) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS tokens_family ON tokens(family);
CREATE INDEX IF NOT EXISTS tokens_agent ON tokens(home, agent);`)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &store{db: db}, nil
}

func (s *store) close() error { return s.db.Close() }

func hash(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// --------------------------------------------------------------------------
// Clients registered dynamically
// --------------------------------------------------------------------------

type dcrClient struct {
	ID           string
	Secret       []byte // hash, nil for a public client
	AuthMethod   string
	Name         string
	URI          string
	RedirectURIs []string
}

func (s *store) putClient(c dcrClient, now time.Time) error {
	uris, _ := json.Marshal(c.RedirectURIs)
	_, err := s.db.Exec(`INSERT INTO clients (client_id, secret, auth_method, name, uri, redirect_uris, created_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, c.ID, c.Secret, c.AuthMethod, c.Name, c.URI, string(uris), now.UnixMilli())
	return err
}

func (s *store) client(id string) (dcrClient, bool, error) {
	var c dcrClient
	var uris string
	err := s.db.QueryRow(`SELECT client_id, secret, auth_method, name, uri, redirect_uris FROM clients WHERE client_id = ?`, id).
		Scan(&c.ID, &c.Secret, &c.AuthMethod, &c.Name, &c.URI, &uris)
	if errors.Is(err, sql.ErrNoRows) {
		return c, false, nil
	}
	if err != nil {
		return c, false, err
	}
	err = json.Unmarshal([]byte(uris), &c.RedirectURIs)
	return c, err == nil, err
}

func (s *store) clientUsed(id string, now time.Time) {
	_, _ = s.db.Exec(`UPDATE clients SET used_ms = ? WHERE client_id = ?`, now.UnixMilli(), id)
}

func (s *store) countClients() (n int) {
	_ = s.db.QueryRow(`SELECT count(*) FROM clients`).Scan(&n)
	return n
}

// --------------------------------------------------------------------------
// Consents in progress
// --------------------------------------------------------------------------

// Request statuses.
const (
	statusPending  = "pending"
	statusApproved = "approved"
	statusDenied   = "denied"
)

// consent is one authorization request, from the authorize page to the
// token it turns into.
type consent struct {
	// Code is the short code the page shows, for an owner to type on the
	// box's page. It finds the request and proves nothing.
	Code        string
	ClientID    string
	ClientName  string
	ClientHost  string
	Verified    bool // the client's name came from a document at its own https URL
	RedirectURI string
	State       string
	Challenge   string
	Scope       string
	Resource    string
	Kid         string
	AgentKey    []byte
	Created     time.Time
	Expires     time.Time
	Status      string
	Home        string
	Agent       string
	Granted     string
	Shard       string
}

const consentCols = `code, client_id, client_name, client_host, verified, redirect_uri, state, challenge, scope, resource,
	kid, agent_key, created_ms, expires_ms, status, home, agent, granted, shard`

func scanConsent(row interface{ Scan(...any) error }) (consent, error) {
	var c consent
	var verified int
	var created, expires int64
	err := row.Scan(&c.Code, &c.ClientID, &c.ClientName, &c.ClientHost, &verified, &c.RedirectURI, &c.State, &c.Challenge,
		&c.Scope, &c.Resource, &c.Kid, &c.AgentKey, &created, &expires, &c.Status, &c.Home, &c.Agent, &c.Granted, &c.Shard)
	c.Verified, c.Created, c.Expires = verified == 1, time.UnixMilli(created), time.UnixMilli(expires)
	return c, err
}

func (s *store) putConsent(rid, browser string, c consent) error {
	verified := 0
	if c.Verified {
		verified = 1
	}
	_, err := s.db.Exec(`INSERT INTO requests (rid, browser, `+consentCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hash(rid), hash(browser), c.Code, c.ClientID, c.ClientName, c.ClientHost, verified, c.RedirectURI, c.State,
		c.Challenge, c.Scope, c.Resource, c.Kid, c.AgentKey, c.Created.UnixMilli(), c.Expires.UnixMilli(), c.Status,
		c.Home, c.Agent, c.Granted, c.Shard)
	return err
}

func (s *store) consentByRID(rid string) (consent, bool, error) {
	return s.oneConsent(`SELECT `+consentCols+` FROM requests WHERE rid = ?`, hash(rid))
}

func (s *store) consentByCode(code string) (consent, bool, error) {
	return s.oneConsent(`SELECT `+consentCols+` FROM requests WHERE code = ?`, code)
}

func (s *store) oneConsent(q string, arg any) (consent, bool, error) {
	c, err := scanConsent(s.db.QueryRow(q, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return c, false, nil
	}
	return c, err == nil, err
}

// browserMatches reports whether a browser's cookie secret is the one the
// request was started with.
func (s *store) browserMatches(rid, browser string) bool {
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM requests WHERE rid = ? AND browser = ?`, hash(rid), hash(browser)).Scan(&n)
	return n == 1
}

// pendingByKey finds the pending consent for an agent key.
func (s *store) pendingByKey(key []byte, now time.Time) (ridHash []byte, c consent, ok bool, err error) {
	row := s.db.QueryRow(`SELECT rid, `+consentCols+` FROM requests WHERE agent_key = ? AND status = ? AND expires_ms > ?`,
		key, statusPending, now.UnixMilli())
	var verified int
	var created, expires int64
	err = row.Scan(&ridHash, &c.Code, &c.ClientID, &c.ClientName, &c.ClientHost, &verified, &c.RedirectURI, &c.State, &c.Challenge,
		&c.Scope, &c.Resource, &c.Kid, &c.AgentKey, &created, &expires, &c.Status, &c.Home, &c.Agent, &c.Granted, &c.Shard)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, c, false, nil
	}
	c.Verified, c.Created, c.Expires = verified == 1, time.UnixMilli(created), time.UnixMilli(expires)
	return ridHash, c, err == nil, err
}

// approve marks a consent approved for an agent of a home, and records the
// agent, in one transaction.
func (s *store) approve(ridHash []byte, c consent, agentExpires, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The page has as long again to hand its browser the code.
	res, err := tx.Exec(`UPDATE requests SET status = ?, home = ?, agent = ?, granted = ?, shard = ?, expires_ms = ?
		WHERE rid = ? AND status = ?`,
		statusApproved, c.Home, c.Agent, c.Granted, c.Shard, now.Add(RequestTTL).UnixMilli(), ridHash, statusPending)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errGone
	}
	if _, err := tx.Exec(`INSERT INTO agents (home, agent, agent_key, kid, client_id, scope, shard, expires_ms, created_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (home, agent) DO UPDATE SET agent_key = excluded.agent_key, kid = excluded.kid,
			client_id = excluded.client_id, scope = excluded.scope, shard = excluded.shard, expires_ms = excluded.expires_ms`,
		c.Home, c.Agent, c.AgentKey, c.Kid, c.ClientID, c.Granted, c.Shard, agentExpires.UnixMilli(), now.UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *store) deny(rid string) (consent, bool, error) {
	c, ok, err := s.consentByRID(rid)
	if err != nil || !ok || c.Status != statusPending {
		return c, false, err
	}
	res, err := s.db.Exec(`UPDATE requests SET status = ? WHERE rid = ? AND status = ?`, statusDenied, hash(rid), statusPending)
	if err != nil {
		return c, false, err
	}
	n, _ := res.RowsAffected()
	return c, n == 1, nil
}

// issueCode gives an approved consent a new authorization code, in place of
// any earlier one that was not used.
func (s *store) issueCode(rid, code string, expires time.Time) error {
	res, err := s.db.Exec(`UPDATE requests SET authz = ?, authz_ms = ? WHERE rid = ? AND status = ? AND authz_used = 0`,
		hash(code), expires.UnixMilli(), hash(rid), statusApproved)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errGone
	}
	return nil
}

// redeem spends an authorization code once. A code presented a second time
// is reported as reused, and the caller revokes what the first use got.
func (s *store) redeem(code string, now time.Time) (c consent, ridHash []byte, reused bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return c, nil, false, err
	}
	defer tx.Rollback()
	var used int
	var ms int64
	row := tx.QueryRow(`SELECT rid, authz_used, authz_ms, `+consentCols+` FROM requests WHERE authz = ?`, hash(code))
	var verified int
	var created, expires int64
	err = row.Scan(&ridHash, &used, &ms, &c.Code, &c.ClientID, &c.ClientName, &c.ClientHost, &verified, &c.RedirectURI,
		&c.State, &c.Challenge, &c.Scope, &c.Resource, &c.Kid, &c.AgentKey, &created, &expires, &c.Status, &c.Home,
		&c.Agent, &c.Granted, &c.Shard)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil, false, errGone
	}
	if err != nil {
		return c, nil, false, err
	}
	c.Verified, c.Created, c.Expires = verified == 1, time.UnixMilli(created), time.UnixMilli(expires)
	if used != 0 {
		return c, ridHash, true, errGone
	}
	if now.UnixMilli() >= ms {
		return c, ridHash, false, errGone
	}
	if _, err := tx.Exec(`UPDATE requests SET authz_used = 1 WHERE authz = ?`, hash(code)); err != nil {
		return c, nil, false, err
	}
	return c, ridHash, false, tx.Commit()
}

var errGone = errors.New("oauth: gone")

// --------------------------------------------------------------------------
// Agents and tokens
// --------------------------------------------------------------------------

// agentRow is an agent an owner approved, as the authorization server knows
// it.
type agentRow struct {
	Home     string
	Agent    string
	Key      []byte
	Kid      string
	ClientID string
	Scope    string
	Shard    string
	Expires  time.Time // zero when the box set no end
}

func (s *store) agent(home, agent string) (agentRow, bool, error) {
	var a agentRow
	var ms int64
	err := s.db.QueryRow(`SELECT home, agent, agent_key, kid, client_id, scope, shard, expires_ms FROM agents WHERE home = ? AND agent = ?`,
		home, agent).Scan(&a.Home, &a.Agent, &a.Key, &a.Kid, &a.ClientID, &a.Scope, &a.Shard, &ms)
	if errors.Is(err, sql.ErrNoRows) {
		return a, false, nil
	}
	if ms > 0 {
		a.Expires = time.UnixMilli(ms)
	}
	return a, err == nil, err
}

func (s *store) agentsOf(home string) ([]agentRow, error) {
	rows, err := s.db.Query(`SELECT home, agent, agent_key, kid, client_id, scope, shard, expires_ms FROM agents WHERE home = ?`, home)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []agentRow
	for rows.Next() {
		var a agentRow
		var ms int64
		if err := rows.Scan(&a.Home, &a.Agent, &a.Key, &a.Kid, &a.ClientID, &a.Scope, &a.Shard, &ms); err != nil {
			return nil, err
		}
		if ms > 0 {
			a.Expires = time.UnixMilli(ms)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// dropAgent deletes an agent and, by the foreign key, every token it holds.
func (s *store) dropAgent(home, agent string) error {
	_, err := s.db.Exec(`DELETE FROM agents WHERE home = ? AND agent = ?`, home, agent)
	return err
}

func (s *store) expiredAgents(now time.Time) ([]agentRow, error) {
	rows, err := s.db.Query(`SELECT home, agent, kid FROM agents WHERE expires_ms > 0 AND expires_ms <= ?`, now.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []agentRow
	for rows.Next() {
		var a agentRow
		if err := rows.Scan(&a.Home, &a.Agent, &a.Kid); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Token kinds.
const (
	kindAccess  = "access"
	kindRefresh = "refresh"
)

type tokenRow struct {
	Kind     string
	Family   []byte
	ClientID string
	Home     string
	Agent    string
	Scope    string
	Resource string
	Expires  time.Time
	Used     bool
}

func (s *store) putToken(tok string, t tokenRow) error {
	_, err := s.db.Exec(`INSERT INTO tokens (hash, kind, family, client_id, home, agent, scope, resource, expires_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, hash(tok), t.Kind, t.Family, t.ClientID, t.Home, t.Agent, t.Scope,
		t.Resource, t.Expires.UnixMilli())
	return err
}

func (s *store) token(tok string) (tokenRow, bool, error) {
	var t tokenRow
	var ms int64
	var used int
	err := s.db.QueryRow(`SELECT kind, family, client_id, home, agent, scope, resource, expires_ms, used FROM tokens WHERE hash = ?`,
		hash(tok)).Scan(&t.Kind, &t.Family, &t.ClientID, &t.Home, &t.Agent, &t.Scope, &t.Resource, &ms, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return t, false, nil
	}
	t.Expires, t.Used = time.UnixMilli(ms), used == 1
	return t, err == nil, err
}

// rotate spends a refresh token. False means it was spent before: a second
// use of one refresh token is theft or a bug, and the caller revokes its
// family.
func (s *store) rotate(tok string) (bool, error) {
	res, err := s.db.Exec(`UPDATE tokens SET used = 1 WHERE hash = ? AND kind = ? AND used = 0`, hash(tok), kindRefresh)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *store) revokeFamily(family []byte) error {
	_, err := s.db.Exec(`DELETE FROM tokens WHERE family = ?`, family)
	return err
}

func (s *store) revokeToken(tok string) error {
	t, ok, err := s.token(tok)
	if err != nil || !ok {
		return err
	}
	if t.Kind == kindRefresh {
		return s.revokeFamily(t.Family)
	}
	_, err = s.db.Exec(`DELETE FROM tokens WHERE hash = ?`, hash(tok))
	return err
}

// sweep deletes what has run out: tokens, and consents a while after they
// ended. It returns the key ids of consents that ended without approval,
// for the keys part to forget.
func (s *store) sweep(now time.Time) ([]string, error) {
	if _, err := s.db.Exec(`DELETE FROM tokens WHERE expires_ms <= ?`, now.UnixMilli()); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT kid FROM requests WHERE status != ? AND expires_ms <= ?`, statusApproved, now.UnixMilli())
	if err != nil {
		return nil, err
	}
	var kids []string
	for rows.Next() {
		var kid string
		if rows.Scan(&kid) == nil {
			kids = append(kids, kid)
		}
	}
	_ = rows.Close()
	_, err = s.db.Exec(`DELETE FROM requests WHERE expires_ms <= ?`, now.UnixMilli())
	return kids, err
}

// splitScope reads a space-separated scope parameter.
func splitScope(s string) []string { return strings.Fields(s) }
