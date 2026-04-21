SHELL := /bin/bash

.PHONY: schema-verify native-demos clean-native-demos

schema-verify:
	python3 scripts/verify_schema_sync.py

native-demos:
	$(MAKE) -C tool-app/demo_apps/native_echo

clean-native-demos:
	$(MAKE) -C tool-app/demo_apps/native_echo clean
