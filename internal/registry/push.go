package registry

import (
	"database/sql"
	"time"
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
	At          time.Time
}

func createPushTable(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS push (
	home TEXT NOT NULL REFERENCES homes(home) ON DELETE CASCADE,
	device_id TEXT NOT NULL,
	epoch INTEGER NOT NULL,
	token BLOB NOT NULL,
	environment TEXT NOT NULL,
	kind TEXT NOT NULL,
	registered_ms INTEGER NOT NULL,
	PRIMARY KEY (home, token, kind)
);`)
	return err
}

// PushRegister keeps a device's token. A token already registered for the
// home moves to this device: a phone that paired again keeps its token.
func (r *Registry) PushRegister(reg PushReg) error {
	_, err := r.db.Exec(`INSERT INTO push (home, device_id, epoch, token, environment, kind, registered_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (home, token, kind) DO UPDATE SET device_id = excluded.device_id, epoch = excluded.epoch,
			environment = excluded.environment, registered_ms = excluded.registered_ms`,
		reg.Home, reg.DeviceID, int64(reg.Epoch), reg.Token, reg.Environment, reg.Kind, reg.At.UnixMilli())
	return err
}

// PushUnregister forgets one of a device's tokens.
func (r *Registry) PushUnregister(home, deviceID string, token []byte) error {
	_, err := r.db.Exec(`DELETE FROM push WHERE home = ? AND device_id = ? AND token = ?`, home, deviceID, token)
	return err
}

// PushRegs returns a home's registrations of one kind.
func (r *Registry) PushRegs(home, kind string) ([]PushReg, error) {
	rows, err := r.db.Query(`SELECT device_id, epoch, token, environment, registered_ms FROM push
		WHERE home = ? AND kind = ? ORDER BY registered_ms`, home, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushReg
	for rows.Next() {
		reg := PushReg{Home: home, Kind: kind}
		var epoch, ms int64
		if err := rows.Scan(&reg.DeviceID, &epoch, &reg.Token, &reg.Environment, &ms); err != nil {
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

// PushPrune keeps only the registrations whose device keep allows at its
// epoch, as a new roster says.
func (r *Registry) PushPrune(home string, keep func(deviceID string, epoch uint64) bool) error {
	rows, err := r.db.Query(`SELECT DISTINCT device_id, epoch FROM push WHERE home = ?`, home)
	if err != nil {
		return err
	}
	type entry struct {
		id    string
		epoch int64
	}
	var gone []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.epoch); err != nil {
			_ = rows.Close()
			return err
		}
		if !keep(e.id, uint64(e.epoch)) {
			gone = append(gone, e)
		}
	}
	_ = rows.Close()
	for _, e := range gone {
		if _, err := r.db.Exec(`DELETE FROM push WHERE home = ? AND device_id = ? AND epoch = ?`, home, e.id, e.epoch); err != nil {
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
