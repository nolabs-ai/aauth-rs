#!/usr/bin/env bash
# Helper script to prepare a release for the aauth-rs workspace.
# Usage: ./scripts/prepare-release.sh [VERSION]
# If VERSION is provided (e.g., 0.1.2), it overrides the auto-detected version.
#
# All three crates (aauth-httpsig, aauth-httpsig-policy, aauth-core) are kept
# in lockstep at the same version number, and every *internal* dependency
# requirement between them is rewritten in the same pass — this is the step
# that was missed by hand during the 0.1.1 release, which left aauth-core
# published on crates.io while still declaring `aauth-httpsig = "0.1.0"` as
# its dependency, silently pulling in the old, unfixed httpsig.

set -euo pipefail

latest_tag() {
    git describe --tags --abbrev=0 2>/dev/null || true
}

show_bump_rationale() {
    local previous_tag="$1"
    local range=""

    if [[ -n "${previous_tag}" ]]; then
        range="${previous_tag}..HEAD"
        echo "Commits since ${previous_tag}:"
    else
        range="HEAD"
        echo "Commits considered for initial release:"
    fi

    local conventional_commits
    conventional_commits=$(git log --format='%s' "${range}" | grep -E '^[[:alpha:]]+(\([^)]*\))?!?: ' || true)

    if [[ -z "${conventional_commits}" ]]; then
        echo "  No conventional commits found in range; git-cliff selected the bump."
        return
    fi

    printf '%s\n' "${conventional_commits}" | sed 's/^/  - /'

    if printf '%s\n' "${conventional_commits}" | grep -Eq '^[[:alpha:]]+(\([^)]*\))?!: |BREAKING CHANGE'; then
        echo "Bump rationale: breaking change detected, so bumping major."
    elif printf '%s\n' "${conventional_commits}" | grep -Eq '^feat(\([^)]*\))?: '; then
        echo "Bump rationale: at least one feat commit detected, so bumping minor."
    elif printf '%s\n' "${conventional_commits}" | grep -Eq '^fix(\([^)]*\))?: '; then
        echo "Bump rationale: only fix-level changes detected, so bumping patch."
    else
        echo "Bump rationale: no feat or breaking commits detected; git-cliff selected the bump."
    fi
}

# Check if git-cliff is installed
if ! command -v git-cliff &> /dev/null; then
    echo "Error: git-cliff is not installed"
    echo "Install with: brew install git-cliff"
    exit 1
fi

# Get current version from the root workspace Cargo.toml (aauth-core).
# NOTE: if aauth-core, aauth-httpsig, and aauth-httpsig-policy have ever
# drifted out of lockstep (as happened during the 0.1.1 release), this
# script re-synchronizes all three to NEXT_VERSION regardless of what each
# one currently says.
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | head -1 | cut -d'"' -f2)
PREVIOUS_TAG=$(latest_tag)
echo "Current version (aauth-core): ${CURRENT_VERSION}"

# Determine next version: use argument if provided, otherwise auto-detect
if [[ -n "${1:-}" ]]; then
    NEXT_VERSION="${1#v}"
    NEXT_VERSION_WITH_V="v${NEXT_VERSION}"
else
    NEXT_VERSION_WITH_V=$(git cliff --bumped-version)
    NEXT_VERSION=${NEXT_VERSION_WITH_V#v}
fi
echo "Next version: ${NEXT_VERSION}"

if [[ -z "${1:-}" ]]; then
    show_bump_rationale "${PREVIOUS_TAG}"
fi

# Ask for confirmation
read -p "Bump version to ${NEXT_VERSION}? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted"
    exit 1
fi

echo "Updating crate versions..."

# aauth-httpsig (leaf crate, no internal deps to rewrite)
sed -i.bak -E "s/^version = \"[0-9]+\.[0-9]+\.[0-9]+\"/version = \"${NEXT_VERSION}\"/" \
    crates/httpsig/Cargo.toml
rm crates/httpsig/Cargo.toml.bak

# aauth-httpsig-policy (version + its dependency on aauth-httpsig)
sed -i.bak -E \
    -e "s/^version = \"[0-9]+\.[0-9]+\.[0-9]+\"/version = \"${NEXT_VERSION}\"/" \
    -e "s/(package = \"aauth-httpsig\", version = \")[0-9]+\.[0-9]+\.[0-9]+(\")/\1${NEXT_VERSION}\2/" \
    crates/httpsig-policy/Cargo.toml
rm crates/httpsig-policy/Cargo.toml.bak

# aauth-core / workspace root (version + its dependencies on both sub-crates)
sed -i.bak -E \
    -e "s/^version = \"[0-9]+\.[0-9]+\.[0-9]+\"/version = \"${NEXT_VERSION}\"/" \
    -e "s/(package = \"aauth-httpsig\", version = \")[0-9]+\.[0-9]+\.[0-9]+(\")/\1${NEXT_VERSION}\2/" \
    -e "s/(package = \"aauth-httpsig-policy\", version = \")[0-9]+\.[0-9]+\.[0-9]+(\")/\1${NEXT_VERSION}\2/" \
    Cargo.toml
rm Cargo.toml.bak

# Update Cargo.lock to reflect the new versions
echo "Updating Cargo.lock..."
cargo check --quiet --workspace

# Sanity check: every crate must now agree, and no internal dependency may
# still point at a stale version — this is exactly the class of mistake
# that broke the 0.1.1 release.
echo "Verifying every crate and internal dependency landed on ${NEXT_VERSION}..."
for f in crates/httpsig/Cargo.toml crates/httpsig-policy/Cargo.toml Cargo.toml; do
    actual=$(grep '^version = ' "$f" | head -1 | cut -d'"' -f2)
    if [[ "$actual" != "$NEXT_VERSION" ]]; then
        echo "error: $f package version is '$actual', expected '$NEXT_VERSION'"
        exit 1
    fi
done
if grep -RnE 'package = "aauth-httpsig(-policy)?", version = "[0-9]+\.[0-9]+\.[0-9]+"' Cargo.toml crates/httpsig-policy/Cargo.toml \
    | grep -v "\"${NEXT_VERSION}\""; then
    echo "error: an internal dependency requirement was not updated to ${NEXT_VERSION}"
    exit 1
fi
echo "OK: all crates and internal dependencies agree on ${NEXT_VERSION}."

# Generate changelog (git cliff expects the tag WITH 'v' prefix)
echo "Generating CHANGELOG.md..."
touch CHANGELOG.md
git cliff --unreleased --tag "${NEXT_VERSION_WITH_V}" --prepend CHANGELOG.md

echo ""
echo "Release prepared!"
echo ""
echo "Next steps:"
echo "1. Review the changes in CHANGELOG.md"
echo "2. Commit: git add Cargo.toml crates/*/Cargo.toml Cargo.lock CHANGELOG.md && git commit -m 'chore: release v${NEXT_VERSION}'"
echo "3. Open a PR, get it merged to main"
echo "4. On main: git tag v${NEXT_VERSION} && git push origin v${NEXT_VERSION}"
echo "   (pushing the tag kicks off .github/workflows/release.yml, which"
echo "   publishes aauth-httpsig, aauth-httpsig-policy, then aauth-core to"
echo "   crates.io in that order, waiting for each to be indexed before"
echo "   publishing the next one that depends on it.)"
