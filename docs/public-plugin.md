# Public plugin connection

The public FTW package connects to
`https://cloud.ftw.energy/mcp?profile=public`. This profile offers a fixed
tool set for public review. The base `/mcp` connection keeps the technical
tools used by existing private installations.

The query chooses the tool set, not the OAuth resource or the owner's
rights. The canonical OAuth resource remains `https://cloud.ftw.energy/mcp`.
Discovery, PKCE, owner approval, token audience, expiry and revocation use
the same OAuth service. The profile shares the same request and call limits,
agent sessions and Core checks. It adds no separate service or stored setting.

## Reviewed operations

The profile exposes these names in both supported MCP protocol families:

- `homes_list`
- `status`, `chargers_list`, `cars_list`
- `plan_get`, `plan_explain`, `history_query`
- `health_get`, `drivers_status`, `logs_tail`, `config_get`,
  `measurement_diagnostics`
- `ev_charge_now`, `goal_request`, `car_goal_request`, `requests_list`
- `setup_begin`, `setup_schema`, `setup_status`, `setup_discover`
- `setup_edit`, `setup_reset`, `setup_validate`, `setup_test`,
  `setup_connect`, `setup_commit`, `setup_restart`

It rejects every other tool, including a direct call to a name absent from
its listing. The list is explicit, so adding a technical tool does not add
it to the public package. Unknown, repeated and malformed profile choices
fail instead of falling back to the full tool set. Both `initialize` and
`server/discover` describe only the public operations.

The initial authentication challenge asks for live, plan, history and health
reads. Configure the package's default OAuth scopes to those same four.
Logs, redacted settings, diagnostics, setup and controls still need the
relevant owner grant. The profile never grants a right by itself.

## Tool annotations

Every tool sets `readOnlyHint`, `destructiveHint` and `openWorldHint` to
true or false, following the
[plugin guidelines](https://developers.openai.com/plugins/plugin-guidelines).
`internal/mcp/hints_test.go` holds the same table, so changing a hint means
changing that table and this one.

- **Read-only** means the tool changes nothing: not the box, its devices,
  its drafts or the owner's records.
- **Destructive** means a write that can overwrite, delete or cancel
  something, at once or when the owner approves it. A hold that ends by
  itself still counts.
- **Open world** means the tool reaches past the one home the owner
  granted: the local network, an address the user typed into the draft, or
  a vendor's service. Every other tool talks only to that home's box.

| Tool | Read-only | Destructive | Open world | Why |
|---|---|---|---|---|
| `homes_list` | true | false | false | Returns this connection's grant. It does not reach the box. |
| `status`, `chargers_list`, `cars_list`, `plan_get`, `plan_explain`, `history_query`, `health_get`, `logs_tail`, `drivers_status`, `config_get`, `measurement_diagnostics`, `requests_list` | true | false | false | Each asks the owner's box for data and returns it. Nothing on the box changes. |
| `setup_begin`, `setup_schema`, `setup_status` | true | false | false | Core serves these as GET reads of the setup schema, draft and guide. `setup_begin` needs the setup grant, so the client may ask the owner to approve it first; the tool itself changes nothing. |
| `setup_discover` | true | false | true | Scans the home's network and may fingerprint devices with reads. Core fails the call if the draft changed meanwhile. Open world: it probes whatever hosts answer, not a fixed list. |
| `ev_charge_now` | false | true | false | Overrides the plan at one charger for at most the grant's `holdS`; `stop` cancels this assistant's hold. Only chargers the box lists for this home. |
| `goal_request` | false | true | false | Stores a request that waits for the owner. Approved, it replaces the home's mode, planning style, solar-only setting or the car's charge level. |
| `car_goal_request` | false | true | false | Stores a request that waits for the owner. Approved, it replaces the car's schedule, or removes it with `clear`. |
| `setup_edit` | false | true | false | Changes the draft. A merge patch replaces whole arrays; JSON Patch can remove entries. |
| `setup_reset` | false | true | false | Discards the unfinished draft and starts a new one from live settings. |
| `setup_validate` | false | true | false | Saves Core's normalized copy of the draft as a new revision, in place of the stored one. |
| `setup_test` | false | true | true | Runs the draft's driver against the device or vendor service the draft names, with device writes and control blocked. A rotated vendor token replaces the old one in the draft, and the vendor can revoke the old one. Open world: the user supplies the address. |
| `setup_connect` | false | true | true | Starts a vendor sign-in (myUplink today) on the vendor's site. When it finishes, the vendor's token replaces the driver's token in the draft. Open world: a third-party service. |
| `setup_commit` | false | true | false | Replaces live settings with the draft the user confirmed. |
| `setup_restart` | false | true | false | Restarts Core to apply saved settings, which briefly stops control and readings. |
| `api_catalog`, `api_read` | true | false | false | Base `/mcp` only. GET reads of the box's own diagnostic API, from the paths the box lists. |

## Limits

`api_catalog` and `api_read` expose a general technical API. The public
profile excludes them because the directory's
[plugin guidelines](https://developers.openai.com/plugins/plugin-guidelines)
require each model-callable operation to appear as a separate reviewed tool.
The profile also excludes the `events_list` and `diag_run` operations that
Core does not yet serve.

`history_query` returns downsampled power readings. It does not establish
exact energy totals or savings. Skills and listing text must state that
limit. The profile cannot export backups or run arbitrary API requests.

The profile's URL must pass a real authenticated connection and scan in
the target host before submission. A source test does not prove portal
compatibility, public approval or a recorded demonstration. Keep reviewer
access on a dedicated simulated home, separate from a household.
