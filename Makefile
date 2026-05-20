.PHONY: desktop-install desktop-dev desktop-build desktop-check

PNPM := corepack pnpm@11.1.3
DESKTOP_DIR := apps/shk-desktop

desktop-install:
	$(PNPM) --dir $(DESKTOP_DIR) install

desktop-dev:
	$(PNPM) --dir $(DESKTOP_DIR) install
	$(PNPM) --dir $(DESKTOP_DIR) tauri dev

desktop-build:
	$(PNPM) --dir $(DESKTOP_DIR) build
	cargo check -p shk-desktop

desktop-check:
	$(PNPM) --dir $(DESKTOP_DIR) fmt:check
	$(PNPM) --dir $(DESKTOP_DIR) lint
	$(PNPM) --dir $(DESKTOP_DIR) build
	cargo check -p shk-desktop
