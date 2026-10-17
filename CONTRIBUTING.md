# Contributing

Everything under `rhel8/`, `rhel9/` and `rhel10/` is **generated** - do not edit them by hand.

| You want to... | Edit |
|---|---|
| Fix or improve how a control is implemented | `tools/cis_impl.py` (matched by control **title**) |
| Change shared helpers / data maps (sysctl values, services, file modes) | `tools/cis_lib.py` |
| Change defaults, prelim, handlers, report | `tools/generate.py` |
| Change apply.sh, settings.yml, per-OS README | `tools/bundle.py` |
| Add a new benchmark release | run `tools/extract_benchmark.py` on your licensed PDF |

Then run:

```bash
python3 tools/generate.py      # regenerate rhel8/ rhel9/ rhel10/
make lint syntax               # yamllint, ansible-lint, syntax check
```

CI fails if generated files are out of date (`python3 tools/generate.py --check`).

**Never commit CIS PDFs or copy benchmark prose.** Only IDs, titles and profile levels are stored.

Commit messages: `rhel9: 5.1.20 handle Match blocks` style - version, control ID, summary.
