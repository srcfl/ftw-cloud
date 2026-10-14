package registry

import (
	"database/sql"
	"time"

	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// APNs registrations. Each row binds one device token to one roster entry
// (device id and epoch) of one home. A row goes when its home goes (the
// foreign key cascades on purge and expiry), when a roster drops the device
// or moves its epoch, when the phone unregisters, when Apple says the token
// is gone, and after PushKeptWithoutBox without a roster from the box.

// PushKeptWithoutBox is how long registrations outlive the box's last
// roster. The box renews its roster every six hours while it is connected.
const PushKeptWithoutBox = 30 * 24 * time.Hour

// PushReg is one registration.
type PushReg struct {
	Home        string
	DeviceID    string
	Epoch       uint64
	Token       []byte
	Environment string
	Kind        string
	// App is the app the token belongs to, cloudwire.PushAppIPhone or
	// cloudwire.PushAppWatch; it picks the APNs topic.
	App string
	At  time.Time
}

func createPushTable(db *sql.DB) error {
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS push (
	home TEXT NOT NULL REFERENCES homes(home) ON DELETE CASCADE,
	device_id TEXT NOT NULL,
	epoch INTEGER NOT NULL,
	token BLOB NOT NULL,
	environment TEXT NOT NULL,
	kind TEXT NOT NULL,
	registered_ms INTEGER NOT NULL,
	PRIMARY KEY (home, token, kind)
);`); err != nil {
		return err
	}
	// A registry from before watches has no app column: its tokens are the
	// iPhone app's.
	var has int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('push') WHERE name = 'app'`).Scan(&has); err != nil {
		return err
	}
	if has == 0 {
		if _, err := db.Exec(`ALTER TABLE push ADD COLUMN app TEXT NOT NULL DEFAULT 'iphone'`); err != nil {
			return err
		}
	}
	return nil
}

// PushRegister keeps a device's token. A token already registered for the
// home moves to this device: a phone that paired again keeps its token.
func (r *Registry) PushRegister(reg PushReg) error {
	app := reg.App
	if app == "" {
		app = cloudwire.PushAppIPhone
	}
	_, err := r.db.Exec(`INSERT INTO push (home, device_id, epoch, token, environment, kind, app, registered_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (home, token, kind) DO UPDATE SET device_id = excluded.device_id, epoch = excluded.epoch,
			environment = excluded.environment, app = excluded.app, registered_ms = excluded.registered_ms`,
		reg.Home, reg.DeviceID, int64(reg.Epoch), reg.Token, reg.Environment, reg.Kind, app, reg.At.UnixMilli())
	return err
}

// PushUnregister forgets one of a device's tokens.
func (r *Registry) PushUnregister(home, deviceID string, token []byte) error {
	_, err := r.db.Exec(`DELETE FROM push WHERE home = ? AND device_id = ? AND token = ?`, home, deviceID, token)
	return err
}

// PushRegs returns a home's registrations of one kind.
func (r *Registry) PushRegs(home, kind string) ([]PushReg, error) {
	rows, err := r.db.Query(`SELECT device_id, epoch, token, environment, app, registered_ms FROM push
		WHERE home = ? AND kind = ? ORDER BY registered_ms`, home, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushReg
	for rows.Next() {
		reg := PushReg{Home: home, Kind: kind}
		var epoch, ms int64
		if err := rows.Scan(&reg.DeviceID, &epoch, &reg.Token, &reg.Environment, &reg.App, &ms); err != nil {
			return nil, err
		}
		reg.Epoch, reg.At = uint64(epoch), time.UnixMilli(ms)
		out = append(out, reg)
	}
	return out, rows.Err()
}

// PushGone forgets a token Apple says is gone, unless the phone registered
// it again after Apple last knew it valid.
func (r *Registry) PushGone(home string, token []byte, since time.Time) error {
	if since.IsZero() {
		_, err := r.db.Exec(`DELETE FROM push WHERE home = ? AND token = ?`, home, token)
		return err
	}
	_, err := r.db.Exec(`DELETE FROM push WHERE home = ? AND token = ? AND registered_ms <= ?`,
		home, token, since.UnixMilli())
	return err
}

// PushPrune keeps only the registrations keep allows: a device at its epoch,
// for one kind, as a new roster says.
func (r *Registry) PushPrune(home string, keep func(deviceID string, epoch uint64, kind string) bool) error {
	rows, err := r.db.Query(`SELECT DISTINCT device_id, epoch, kind FROM push WHERE home = ?`, home)
	if err != nil {
		return err
	}
	type entry struct {
		id    string
		epoch int64
		kind  string
	}
	var gone []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.epoch, &e.kind); err != nil {
			_ = rows.Close()
			return err
		}
		if !keep(e.id, uint64(e.epoch), e.kind) {
			gone = append(gone, e)
		}
	}
	_ = rows.Close()
	for _, e := range gone {
		if _, err := r.db.Exec(`DELETE FROM push WHERE home = ? AND device_id = ? AND epoch = ? AND kind = ?`,
			home, e.id, e.epoch, e.kind); err != nil {
			return err
		}
	}
	return nil
}

// PushExpire forgets the registrations of homes whose box has sent no
// roster for PushKeptWithoutBox, and returns how many went.
func (r *Registry) PushExpire(now time.Time) (int64, error) {
	cutoff := now.Add(-PushKeptWithoutBox).UnixMilli()
	res, err := r.db.Exec(`DELETE FROM push WHERE home IN (SELECT home FROM homes
		WHERE (roster_ms > 0 AND roster_ms < ?) OR (roster_ms = 0 AND created_ms < ?))`, cutoff, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
