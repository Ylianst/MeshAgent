# Agent releases

Use version tags such as `1.2.0` for stable releases and `1.2.0-beta.1` for
beta builds. A `v` prefix is also accepted. These versions are independent of
MeshCentral's version and the agent's embedded build date and commit hash.

Pushing a version tag runs **Agent Release**. The workflow calls the existing
Linux, Windows, macOS and FreeBSD builds at that tag, collects the raw binaries
and creates a draft release only after every build succeeds. The expected
filenames are in `.github/release-files.json`. macOS includes a universal binary.

Manual runs must select an existing version tag. The workflow must first be
present on the default branch; see
[GitHub's manual workflow instructions](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).

Review the files and publish the draft. Do not replace published files or move
tags. A rerun cannot overwrite an existing release. Version tags with a suffix,
such as `1.2.0-beta.1`, create prerelease drafts. Keep the prerelease flag when
publishing beta builds. PR builds remain Actions artifacts.

Each release includes `agent-release.json`, containing its repository, tag,
source commit, asset names, sizes and full-file SHA384 checksums. Generate these
checksums after signing or changing any file. MeshCentral uses them to verify
downloads; its native update hash can differ after server signing.

The workflow uses the repository's `GITHUB_TOKEN` with write access confined to
the release job. Build jobs need only read access. Public release downloads do
not require a personal access token. MeshCentral requires a token to download
Actions artifacts, including PR builds.

## Existing MeshCentral binaries

Run **Actions > Migrate bundled agents > Run workflow** to preserve the files
from MeshCentral 1.2.6 without rebuilding them. Select one of these profiles;
the migration workflow handles the tag, so it does not need to be pushed manually.

- `legacy` prepares a draft `legacy-1.2.6` release with the 30 native default
  files, including older platforms, universal macOS and Windows MeshCmd.
- `september` prepares a `testing-sep2026` prerelease draft with the 13 September
  testing files.

Publish the legacy draft before releasing a MeshCentral version that removes
its bundled agents. Leave migration releases excluded from GitHub's latest
release selection and keep `testing-sep2026` marked as a prerelease. That tag
preserves the existing September binaries; new beta builds use version tags
such as `1.2.0-beta.1`.

Migration tags identify the packaging commit. `.github/release-migration.json`
and the release manifest record the source repository, archive commit, paths,
sizes and hashes of the preserved files.

MeshCentral can pin older platforms to this migration release while selecting
new builds for other platforms. Its scheduled checks report stable releases and
exclude prereleases. Administrators can import beta releases and install them
on selected devices. Publishing a release does not change server defaults or
deploy agents.
