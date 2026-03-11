# tool-app

App-level tool implementations executed by `mcpd`.

## Structure

- `tool-app/app_service.py`: generic resident UDS server.
- `tool-app/apps/*.py`: app modules, each exposing:
  - `HANDLERS: Dict[str, Callable[[Any], Dict[str, Any]]]`
- `tool-app/manifests/*.json`:
  - app-level fields (`app_id`, `app_impl`, `endpoint`, ...)
  - tool entries use `handler` key to reference `HANDLERS`.

`mcpd` dispatches requests by app `endpoint` and `tool_id`; `app_service.py` resolves `tool_id -> handler` and periodically registers the manifest to `mcpd`.

## Current App Modules

- `apps/settings_app.py`
- `apps/file_manager_app.py`
- `apps/calculator_app.py`
- `apps/utility_app.py`
