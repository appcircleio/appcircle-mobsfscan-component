# Appcircle _MobSF Scan_ component

Runs [mobsfscan](https://github.com/MobSF/mobsfscan), MobSF's source code static analysis
(SAST) engine, against the cloned repository. It covers Java, Kotlin, Android XML, Swift and
Objective-C source code and reports findings with file, line, rule id, severity and
CWE / OWASP MASVS references.

The scope of this component is source code only. Compiled artifact (APK / IPA) analysis is
handled by the separate MobSF binary scan step.

`mobsfscan` is LGPL-3.0-or-later, so it is not shipped inside Appcircle. The step installs the
pinned version with pip at runtime, into an isolated virtualenv under `$AC_STEP_TEMP` that is
discarded when the step ends. **Docker is not required**, the only runner requirement is
`python3` with the `venv` module.

## Required Inputs

- `AC_REPOSITORY_DIR`: Repository Directory. Specifies the cloned repository directory.
- `AC_MOBSFSCAN_VERSION`: mobsfscan Version. The `mobsfscan` version installed with pip.
  Pinned (default `1.0.0`) so builds stay reproducible instead of silently following the
  latest release.

## Optional Inputs

- `AC_MOBSFSCAN_SOURCE_PATH`: Source Path. Path of the source code to scan. A relative value is
  resolved against the cloned repository directory. Defaults to the repository root.
- `AC_MOBSFSCAN_SCAN_TYPE`: Scan Type. `auto` (default), `android` or `ios`. `auto` detects the
  platform from the source code, the explicit values force a rule set.
- `AC_MOBSFSCAN_OUTPUT_FORMATS`: Output Formats. Comma separated list of `sarif`, `json`,
  `html`, `sonarqube` and `gitlab-sast`. Defaults to `sarif,json`.
- `AC_MOBSFSCAN_SEVERITY_THRESHOLD`: Severity Threshold. `error` (default), `warning`, `info` or
  `none`. The build fails when a finding at or above this severity is reported, `none` makes the
  step report only.
- `AC_MOBSFSCAN_CONFIG_PATH`: Config File Path. Path of the `.mobsf` YAML config for rule
  tuning. A relative value is resolved against the source path. When empty, a `.mobsf` file at
  the scan root is picked up by `mobsfscan` automatically.
- `AC_MOBSFSCAN_SAVE_REPORT`: Save Report. Report files are copied into the artifacts folder
  when set to `true` (default).
- `AC_MOBSFSCAN_TIMEOUT`: Scan Timeout. Timeout in seconds for a single `mobsfscan` run,
  default `900`. The step terminates the scan and fails when it is exceeded, so a stuck scan
  never hangs the build.
- `AC_MOBSFSCAN_EXTRA_PARAMETERS`: Scanner Parameters. Extra command line parameters, for
  example `-mp thread`. See [Extra parameters](#extra-parameters) for how the value is split.
- `AC_MOBSFSCAN_PIP_INDEX_URL`: Pip Index URL. Alternative Python package index. The value is
  masked in the build log because it may carry credentials.
- `AC_MOBSFSCAN_PIP_FIND_LINKS`: Pip Find Links. Directory or URL holding the `mobsfscan`
  wheels for an air gapped install. When set, pip runs with `--no-index`.

## Outputs

| Output | Description |
| --- | --- |
| `AC_MOBSFSCAN_JSON_REPORT_PATH` | Path of the JSON report, when `json` is a requested format. |
| `AC_MOBSFSCAN_SARIF_REPORT_PATH` | Path of the SARIF 2.1.0 report, when `sarif` is a requested format. |
| `AC_MOBSFSCAN_REPORT_DIR` | Directory holding the generated reports. |
| `AC_MOBSFSCAN_FINDING_COUNT` | Total number of findings. |
| `AC_MOBSFSCAN_ERROR_COUNT` | Number of `ERROR` severity findings. |
| `AC_MOBSFSCAN_WARNING_COUNT` | Number of `WARNING` severity findings. |
| `AC_MOBSFSCAN_INFO_COUNT` | Number of `INFO` severity findings. |
| `AC_MOBSFSCAN_HIGHEST_SEVERITY` | Highest reported severity, or `NONE`. |

## How the step decides success or failure

`mobsfscan` exits non-zero both when it finds something and when it breaks, so the exit code
alone cannot tell a failed build from a failed tool. The step therefore runs `mobsfscan` with
`--no-fail` and makes the decision itself, from the JSON report:

1. **Findings at or above the threshold** — the step fails, and the reports are still published.
2. **Findings below the threshold, or `none`** — the step succeeds, and the reports are published.
3. **No parseable report, or a non-zero exit code** — `mobsfscan` itself failed. The step fails
   with a different message, so a tool problem is never read as a policy violation.

Severities are `ERROR`, `WARNING` and `INFO`. The JSON report is always generated because the
threshold decision is made from it, but it is only published as an artifact when `json` is one
of the requested output formats.

Findings come in two shapes and the console summary keeps them apart:

- **findings** — a rule matched a specific file and line.
- **missing best practices** — informational rules such as "this app does not use certificate
  pinning". They carry no file location and are always `INFO`, which is why a threshold of
  `info` fails on virtually every project.

## Reports

Reports are written under `$AC_STEP_TEMP` and, when `AC_MOBSFSCAN_SAVE_REPORT` is `true`,
copied to `$AC_OUTPUT_DIR/mobsfscan_output/`:

| Format | Filename |
| --- | --- |
| `json` | `mobsfscan.json` |
| `sarif` | `mobsfscan.sarif` |
| `html` | `mobsfscan.html` |
| `sonarqube` | `mobsfscan-sonarqube.json` |
| `gitlab-sast` | `mobsfscan-gitlab-sast.json` |

`mobsfscan` accepts a single `-o`, so **each requested format needs its own scan run**. A run
takes a few seconds on a small project but scales with the size of the source tree, so request
only the formats you consume.

Use the `appcircle_export_build_artifacts` step after this one to publish the reports.

## Rule tuning with `.mobsf`

Place a `.mobsf` YAML file at the scan root, or point `AC_MOBSFSCAN_CONFIG_PATH` at one:

```yaml
ignore-filenames:
  - BuildConfig.java
ignore-paths:
  - app/src/test
ignore-rules:
  - android_logging
  - hardcoded_api_key
severity-filter:
  - ERROR
  - WARNING
severity-overrides:
  android_webview_debug: ERROR
```

- `ignore-filenames`, `ignore-paths`, `ignore-rules` — drop matching files, paths and rules.
- `severity-filter` — keep only the listed severities in the report.
- `severity-overrides` — remap a rule's severity, as a `rule_id: SEVERITY` mapping.

`mobsfscan` also ignores `.git`, `.svn`, `__MACOSX`, `fixtures` and `spec` paths, and `.apk`,
`.zip` and `.ipa` files, by default.

A single finding can be suppressed inline on the matching source line:

```java
private static final String KEY = "abc123"; // mobsf-ignore: hardcoded_secret, hardcoded_api_key
```

## Extra parameters

`AC_MOBSFSCAN_EXTRA_PARAMETERS` is split with shell word rules and each token is passed to
`mobsfscan` as a separate argument. The value is **never** handed to a shell, so quoting works
for arguments that contain spaces, while shell syntax such as `&&`, `|`, `$(...)` or `>` has no
effect. Do not pass `-o`, `--json`, `--sarif`, `--type` or `-c` here, the step manages those
from its own inputs.

## Offline and air gapped runners

The step needs to reach a Python package index to install `mobsfscan`. On a runner without
outbound access, mirror the `mobsfscan` wheels and its dependencies (including `semgrep`) and
set `AC_MOBSFSCAN_PIP_FIND_LINKS` to that directory, or set `AC_MOBSFSCAN_PIP_INDEX_URL` to an
internal index. When the install fails because of the network, the step reports that explicitly
instead of surfacing a raw pip error.

## Notes on the runtime install

- The virtualenv is created under `$AC_STEP_TEMP` and never touches the system Python. A global
  or `--user` install is rejected by PEP 668 managed interpreters on macOS runners, and would
  leak into the pinned runner toolchain from the Android container, where the step runs as root.
- `mobsfscan` shells out to `semgrep` for its pattern matching rules, so the virtualenv's `bin`
  directory is placed on `PATH` for the scan. Without it, `mobsfscan` reports
  `semgrep not found` and only the informational best practice rules run. The step treats that
  as an installation failure rather than a clean result.
- The installed version is compared against the pinned one and a mismatch is logged as a
  warning.
- The install is the dominant cost of the step. `mobsfscan` pulls in `semgrep`, so a cold
  install measured at **2 to 3 minutes**, while the scan itself takes seconds on a small
  project. Mirroring the wheels and pointing `AC_MOBSFSCAN_PIP_FIND_LINKS` at them cuts it to
  roughly 20 seconds, and caching the virtualenv through the cache step is the next step if the
  install cost matters for a workflow.

## Development

The test suite uses minitest from the Ruby standard library, no Bundler and no gems:

```bash
ruby tests/test_main.rb
```

The end to end tests run `main.rb` the way the runner does, against the deliberately insecure
samples under `tests/sample_projects`. They need `python3` and a reachable package index, and are
opt in:

```bash
MOBSFSCAN_E2E=1 ruby tests/test_main.rb
```

Each of those tests builds a fresh virtualenv, and installing `mobsfscan` from pypi.org takes
minutes. Point them at a local wheel directory instead to cut that down, which also exercises
the air gapped install path:

```bash
python3 -m pip download mobsfscan==1.0.0 -d /tmp/mobsfscan-wheelhouse
```

```bash
MOBSFSCAN_E2E=1 MOBSFSCAN_WHEELHOUSE=/tmp/mobsfscan-wheelhouse ruby tests/test_main.rb
```

The tests that cover the install itself, a pinned version, a bad pin and an unreachable index,
ignore `MOBSFSCAN_WHEELHOUSE` and always go to the configured index.
