# Mantishack convenience targets. See ./install.sh for the real work.
.DEFAULT_GOAL := help
VENV := .venv
PY := $(VENV)/bin/python

.PHONY: help install minimal doctor run update deps clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install: ## Full install (venv, deps, semgrep, claude, PATH link, doctor)
	@./install.sh

minimal: ## Python deps + Semgrep only
	@./install.sh --minimal --yes

deps: ## (Re)install pinned Python deps (semgrep stays isolated - use ./install.sh)
	@test -d $(VENV) || python3 -m venv $(VENV)
	@$(PY) -m pip uninstall -y semgrep >/dev/null 2>&1 || true
	@$(PY) -m pip install --upgrade pip >/dev/null
	@$(PY) -m pip install -r requirements.txt

doctor: ## Verify the install is ready
	@./bin/mantishack-doctor

run: ## Activate the venv and launch the interactive agent
	@. $(VENV)/bin/activate && exec ./bin/mantishack

update: ## Pull latest and reinstall deps
	@git pull --ff-only && $(MAKE) deps && $(MAKE) doctor

clean: ## Remove the local virtualenv
	@rm -rf $(VENV) && echo "removed $(VENV)"
