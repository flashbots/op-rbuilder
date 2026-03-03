#!/usr/bin/env bash
#
# prepare-release.sh - Automated release preparation script for op-rbuilder
#
# DESCRIPTION:
#   This script automates the process of preparing a new stable release by:
#   1. Creating a release branch (release/v{VERSION})
#   2. Bumping the version in Cargo.toml
#   3. Generating a changelog from conventional commits using release-plz
#   4. Committing the changes
#   5. Pushing the branch to remote
#   6. Opening a GitHub pull request with the "release" label
#
# USAGE:
#   ./scripts/prepare-release.sh <version>
#
#   Example:
#     ./scripts/prepare-release.sh 0.3.4
#
# PREREQUISITES:
#   - Must be run from the repository root directory
#   - Must be on the 'main' branch with a clean working directory
#   - GitHub CLI (gh) must be installed and authenticated
#   - release-plz will be installed automatically if not present
#
# WORKFLOW:
#   After this script completes:
#   1. Review the auto-generated changelog in the PR
#   2. Edit the changelog if needed (add breaking changes section, clarify items)
#   3. Test the release candidate on testnet/devnet
#   4. Get approval and merge the PR
#   5. When the PR is merged, release-plz.yaml workflow will automatically:
#      - Create a git tag (op-rbuilder/v{VERSION})
#      - Trigger the release workflow to build binaries and Docker images
#
# VERSION FORMAT:
#   Version must follow semantic versioning: X.Y.Z (e.g., 0.3.4)
#   - Patch (0.3.2 → 0.3.3): Bug fixes, refactors, minor improvements
#   - Minor (0.3.3 → 0.4.0): New features, everything else
#   - Major (0.4.0 → 1.0.0): Unused, we're not at 1.0 yet
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
error() {
    echo -e "${RED}❌ Error: $1${NC}" >&2
    exit 1
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]] || [[ ! -d ".git" ]]; then
    error "Must be run from the repository root"
fi

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    error "GitHub CLI (gh) is not installed. Install it from https://cli.github.com/"
fi

# Check if on main branch
CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" != "main" ]]; then
    error "Must be on main branch (currently on: $CURRENT_BRANCH)"
fi

# Check for uncommitted changes
if [[ -n $(git status --porcelain) ]]; then
    error "Working directory has uncommitted changes. Please commit or stash them first."
fi

# Get version argument
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.3.4"
    exit 1
fi

VERSION="$1"

# Validate version format
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    error "Invalid version format: $VERSION (expected: X.Y.Z, e.g., 0.3.4)"
fi

# Check if version tag already exists
if git tag -l | grep -q "^op-rbuilder/v${VERSION}$"; then
    error "Tag op-rbuilder/v${VERSION} already exists"
fi

# Get current version
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
info "Current version: ${CURRENT_VERSION}"
info "New version: ${VERSION}"

# Confirm with user
echo ""
read -p "Create release branch for v${VERSION}? (y/N) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Update from remote
info "Fetching latest changes from remote..."
git fetch origin main
git pull origin main

# Create release branch
BRANCH="release/v${VERSION}"
info "Creating branch: ${BRANCH}"
git checkout -b "${BRANCH}"
success "Branch created"

# Update version in Cargo.toml
info "Updating version in Cargo.toml..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml
else
    # Linux
    sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml
fi

# Verify change
NEW_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
if [[ "$NEW_VERSION" != "$VERSION" ]]; then
    error "Failed to update version in Cargo.toml"
fi
success "Version updated to ${VERSION}"

# Commit version bump
git add Cargo.toml
git commit -m "chore: bump version to ${VERSION}"
success "Version bump committed"

# Check if release-plz is installed
if ! command -v release-plz &> /dev/null; then
    info "Installing release-plz..."
    cargo install release-plz --locked
fi

# Generate changelog
info "Generating changelog with release-plz..."
if release-plz update; then
    success "Changelog generated"

    # Commit changelog if changed
    if [[ -n $(git status --porcelain) ]]; then
        git add -A
        git commit -m "chore: update CHANGELOG for v${VERSION}"
        success "Changelog committed"
    else
        info "No changelog changes"
    fi
else
    error "Failed to generate changelog"
fi

# Push branch
info "Pushing branch to remote..."
git push -u origin "${BRANCH}"
success "Branch pushed"

# Create PR
info "Creating pull request..."
PR_URL=$(gh pr create \
    --title "Release v${VERSION}" \
    --label "release" \
    --body "## Release v${VERSION}

### Pre-merge Checklist
- [ ] Changelog reviewed and edited for clarity
- [ ] Breaking changes documented (if any)
- [ ] Tested on testnet/devnet
- [ ] All CI checks passing

### What happens on merge?
- Tag \`op-rbuilder/v${VERSION}\` will be automatically created
- Release workflow will build binaries and Docker images
- GitHub release will be published

### Notes
Add any breaking changes or migration notes here.

---
*Generated by scripts/prepare-release.sh*")

success "Pull request created: ${PR_URL}"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}🎉 Release PR ready!${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Next steps:"
echo "1. Review the auto-generated changelog"
echo "2. Edit CHANGELOG.md if needed (add breaking changes, clarify items)"
echo "3. Test on testnet/devnet"
echo "4. Get approval and merge"
echo "5. Release will be automatically published!"
echo ""
echo "PR: ${PR_URL}"
