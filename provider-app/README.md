# provider-app

`provider-app/` contains provider runtime code and provider manifests.

## Structure

- `provider_service.py`
  Generic UDS provider runtime.
- `providers/*.py`
  Provider implementations exposing `HANDLERS`.
- `manifests/*.json`
  Canonical provider manifests.
- `schemas/*.json`
  Optional input schemas referenced by manifests.

## Canonical Manifest Shape

Provider-level fields:

- `provider_id`
- `display_name`
- `provider_type`
- `trust_class`
- `auth_mode`
- `broker_domain`
- `endpoint`
- `mode`
- `provider_impl`
- `actions`

Action-level fields:

- `action_id`
- `action_name`
- `capability_domain`
- `description`
- `risk_level`
- `side_effect`
- `auth_required`
- `executor_type`
- `validation_policy`
- `parameter_schema_id`
- `input_schema` or `input_schema_path`
- `intent_tags`
- `examples`
- `arg_hints`
- `selection_priority`
- `handler`

## Current Providers

- `providers/settings_provider.py`
- `providers/file_manager_provider.py`
- `providers/calculator_provider.py`
- `providers/utility_provider.py`
- `providers/notes_provider.py`

## Run

```bash
bash scripts/run_provider_services.sh
```

Provider runtime registration is not required. `mcpd` autoloads manifests from `provider-app/manifests/` at startup.
