# Release Process

How to create a new Agent Messenger release.

## Version Scheme

We follow [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking API changes
- **MINOR**: New features (backward-compatible)
- **PATCH**: Bug fixes

Current version is defined in `server/main.go` as `ServerVersion` and propagated to all packages.

## Pre-Release Checklist

1. **All tests passing**:
   ```bash
   cd server && go test -race ./...       # ~346 tests
   cd webchat && npx vitest run            # 115 tests
   cd sdk/js && npx vitest run             # 43 tests
   cd sdk/python && pytest tests/          # 50 tests
   cd linux && pytest                      # 40 tests
   cd plugins/openclaw && npm test         # 50 tests
   cd mobile/android && ./gradlew test     # 51 tests
   ```

2. **Integration tests passing**:
   ```bash
   go build -o /tmp/am-server ./server/.
   AM_INTEGRATION=1 AM_SERVER_BIN=/tmp/am-server \
     pytest sdk/python/tests/test_integration.py -v    # 20 tests
   AM_INTEGRATION=1 AM_SERVER_BIN=/tmp/am-server \
     npx vitest run sdk/js/src/__tests__/live-integration.test.ts  # 20 tests
   ```

3. **WebChat builds without errors**:
   ```bash
   cd webchat && npm run build
   ```

4. **CHANGELOG.md updated** with all changes since last release

5. **Version bumped** in all package files (see below)

## Version Bump Locations

When changing version from `X.Y.Z` to `A.B.C`, update these files:

| File | Field |
|------|-------|
| `server/main.go` | `ServerVersion = "A.B.C"` |
| `webchat/package.json` | `"version": "A.B.C"` |
| `sdk/js/package.json` | `"version": "A.B.C"` |
| `sdk/python/pyproject.toml` | `version = "A.B.C"` |
| `plugins/openclaw/package.json` | `"version": "A.B.C"` |
| `deploy/helm/agent-messenger/Chart.yaml` | `version: A.B.C` and `appVersion: "A.B.C"` |
| `CHANGELOG.md` | Add `[A.B.C] - YYYY-MM-DD` header |

## Release Steps

### 1. Create a Release Branch

```bash
git checkout main
git pull origin main
git checkout -b release/A.B.C
```

### 2. Update Version and Changelog

```bash
# Bump version in all files listed above
# Update CHANGELOG.md with all changes since last release
# Move unreleased items under the new version heading
```

### 3. Commit and Push

```bash
git add -A
git commit -m "chore: bump version to A.B.C"
git push origin release/A.B.C
```

### 4. Create a Pull Request

- Title: `Release A.B.C`
- Body: Summary of changes from CHANGELOG
- Wait for CI to pass

### 5. Merge and Tag

After PR is merged to `main`:

```bash
git checkout main
git pull origin main
git tag -a vA.B.C -m "Release A.B.C

Key changes:
- Feature 1
- Feature 2
- Bug fix 1"
git push origin vA.B.C
```

### 6. Create GitHub Release

1. Go to https://github.com/Joel-Claw/agent-messenger/releases/new
2. Select the tag `vA.B.C`
3. Title: `vA.B.C`
4. Copy the CHANGELOG entry as the description
5. If building Docker images, attach them as artifacts
6. Publish the release

### 7. Build Docker Image (Optional)

```bash
docker build -t agent-messenger:A.B.C ./server
docker tag agent-messenger:A.B.C agent-messenger:latest
docker tag agent-messenger:A.B.C ghcr.io/joel-claw/agent-messenger:A.B.C
docker push ghcr.io/joel-claw/agent-messenger:A.B.C
docker push ghcr.io/joel-claw/agent-messenger:latest
```

### 8. Update Helm Chart (Optional)

```bash
helm package deploy/helm/agent-messenger
# Upload agent-messenger-A.B.C.tgz to GitHub release or chart repository
```

## CHANGELOG Format

```markdown
# Changelog

## [Unreleased]

## [0.3.0] - 2026-05-15

### Added
- New feature description (#123)

### Changed
- Changed behavior description (#124)

### Fixed
- Bug fix description (#125)

### Security
- Security fix description
```

Group changes under: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.

## Hotfix Releases

For critical bug fixes:

```bash
git checkout main
git checkout -b hotfix/A.B.D   # Patch bump only
# Apply minimal fix
# Update version to A.B.D
git commit -m "fix: critical issue description"
git push origin hotfix/A.B.D
# Follow steps 4-8 above, but skip the full CHANGELOG update
# Add a brief entry under [A.B.D]
```

## Post-Release

1. Bump development version in `server/main.go` to `A.B.(D+1)-dev` or `(A+1).0.0-dev`
2. Update Helm chart `appVersion` to match
3. Create a new `[Unreleased]` section in CHANGELOG.md
4. Commit: `chore: start A.B.(D+1) development cycle`