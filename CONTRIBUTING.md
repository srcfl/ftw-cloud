# Contributing to FTW Cloud

Sourceful maintains this repository. Fredrik owns FTW's direction in
[the shared vision](https://github.com/srcfl/ftw/blob/master/VISION.md).
External PRs are welcome, preferably based on an
[issue](https://github.com/srcfl/ftw-cloud/issues). Small fixes need no
separate issue.

This service holds readable household data, so a change to what it stores,
logs, forwards or exposes needs a reason in the PR and a test that shows the
limit holds. Broad ideas may start as short Markdown PRs; mark proposed
behaviour as proposed. A wire change starts in `srcfl/ftw` (`go/protocol`)
and is paired with a PR here. Keep task breakdowns and agent scratch notes
out of the repository.

Work is agentic first: give people and agents a clear problem, scope,
reproducible test steps and actual results. Check agent output before
submitting it. Sourceful reviews and maintains changes. A contribution grants
no merge, release or deployment authority. See
[FTW's contribution guide](https://github.com/srcfl/ftw/blob/master/CONTRIBUTING.md).

## License of contributions

This repository is licensed under the GNU Affero General Public License,
version 3 only (AGPL-3.0-only); see [LICENSE](LICENSE). Contributions use the
same terms. Preserve third-party licenses and notices.

## Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
instead of a CLA. Sign off every commit with your real name and email:

```bash
git commit -s -m "fix(uplink): close on a frame over the limit"
```

The sign-off confirms that you wrote the contribution or have the right to
submit it under these terms. A sign-off does not assign copyright or grant
commercial relicensing rights.
