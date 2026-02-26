SHELL := /bin/bash

.PHONY: schema-verify

schema-verify:
	python3 scripts/verify_schema_sync.py
