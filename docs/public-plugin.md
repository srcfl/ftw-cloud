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
- `health_get`, `drivers_status`, `logs_tail`, `config_get`
- `ev_charge_now`, `goal_request`, `requests_list`

It rejects every other tool, including a direct call to a name absent from
its listing. The list is explicit, so adding a technical tool does not add
it to the public package. Unknown, repeated and malformed profile choices
fail instead of falling back to the full tool set. Both `initialize` and
`server/discover` describe only the public operations.

The initial authentication challenge asks for live, plan, history and health
reads. Configure the package's default OAuth scopes to those same four.
Logs, redacted settings and controls still need the relevant owner grant.
The profile never grants a right by itself.

## Limits

`api_catalog` and `api_read` expose a general technical API. The public
profile excludes them because the directory's
[plugin guidelines](https://developers.openai.com/plugins/plugin-guidelines)
require each model-callable operation to appear as a separate reviewed tool.
The profile also excludes setup writes and the `events_list` and `diag_run`
operations that Core does not yet serve. Installation help remains a skill
that guides the owner through the maintained installer and local UI.

`history_query` returns downsampled power readings. It does not establish
exact energy totals or savings. Skills and listing text must state that
limit. The profile cannot export backups or run arbitrary API requests.

The profile's URL must pass a real authenticated connection and scan in
the target host before submission. A source test does not prove portal
compatibility, public approval or a recorded demonstration. Keep reviewer
access on a dedicated simulated home, separate from a household.
