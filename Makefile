# Makefile for version bumping and local development

.PHONY: bump-patch bump-minor bump-major sync-version install help tag-release test lint

# Default target
help:
	@echo "Available targets:"
	@echo "  bump-patch  - Bump patch version (x.x.X) for both backend and frontend"
	@echo "  bump-minor  - Bump minor version (x.X.x) for both backend and frontend"
	@echo "  bump-major  - Bump major version (X.x.x) for both backend and frontend"
	@echo "  install     - Fetch Rust crates and run npm install in the frontend"
	@echo "  test        - Run backend tests"
	@echo "  lint        - Run rustfmt and clippy checks"
	@echo "  tag-release - Create and push git tag for current version"

# The frontend package.json is the source of truth; Cargo.toml follows it.
sync-version:
	@V=$$(cd frontend && node -p "require('./package.json').version") && \
	awk -v v="$$V" '!d && /^version = / { print "version = \"" v "\""; d=1; next } { print }' backend/Cargo.toml > backend/Cargo.toml.tmp && \
	mv backend/Cargo.toml.tmp backend/Cargo.toml && \
	(cd backend && cargo update --workspace --offline >/dev/null 2>&1 || cargo update --workspace >/dev/null) && \
	echo "Backend version synced to $$V"

# Bump patch version (x.x.X)
bump-patch:
	@echo "Bumping patch version..."
	@cd frontend && npm version patch --no-git-tag-version
	@$(MAKE) --no-print-directory sync-version
	@echo "✅ Patch version bumped successfully!"

# Bump minor version (x.X.x)
bump-minor:
	@echo "Bumping minor version..."
	@cd frontend && npm version minor --no-git-tag-version
	@$(MAKE) --no-print-directory sync-version
	@echo "✅ Minor version bumped successfully!"

# Bump major version (X.x.x)
bump-major:
	@echo "Bumping major version..."
	@cd frontend && npm version major --no-git-tag-version
	@$(MAKE) --no-print-directory sync-version
	@echo "✅ Major version bumped successfully!"

# Install dependencies
install:
	@echo "Fetching backend crates..."
	@cd backend && cargo fetch --locked
	@echo "📦 Installing frontend dependencies..."
	@cd frontend && npm install
	@echo "✅ Dependencies installed successfully!"

# Show current versions
show-versions:
	@echo "Current versions:"
	@echo "Backend: $(shell cd backend && cargo pkgid | sed 's/.*[#@]//')"
	@echo "Frontend: $(shell cd frontend && node -p "require('./package.json').version")"

test:
	@cd backend && cargo test --locked

lint:
	@cd backend && cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings

tag-release:
	@VERSION=$$(cd frontend && node -p "require('./package.json').version") && \
	echo "Creating signed tag for version $$VERSION..." && \
	git tag -s "$$VERSION" -m "Release $$VERSION" && \
	git push origin --follow-tags && \
	echo "Signed tag $$VERSION created and pushed"

# Backend dev mode: serves the SPA from backend/dev_frontend (NODE_ENV=development disables the
# reverse-proxy/HTTPS requirement and the Secure cookie flag).
bdev:
	@echo "Running backend in development mode..."
	@cd backend && NODE_ENV=development cargo run

fdev:
	@echo "Running frontend in development mode..."
	@cd frontend && npm run start:dev
