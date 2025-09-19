### Generated OpenAPI Types (internal/api-gen)

This directory contains types generated from `docs/api-spec.yaml` using `oapi-codegen` (types-only generation).

How to regenerate:

```bash
task api-spec:refresh
```
this will pull down the latest changes and regenerate types.

Alternatively: 

```bash
task api-spec:pull
```
this will just pull down the latest changes.

```bash
task api-spec:gen
```
this regenerate types.

CI also runs a drift check:

```bash
task api-spec:check
```

Notes:
- The generated types follow the spec exactly (field names, optionality, enums).
- Do not edit generated files manually.
