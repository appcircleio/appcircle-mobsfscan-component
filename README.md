# Appcircle _MobSF Scan_ component

Runs [mobsfscan](https://github.com/MobSF/mobsfscan), MobSF's source code static analysis
(SAST) engine, against the cloned repository. It covers Java, Kotlin, Android XML, Swift and
Objective-C source code and reports findings with file, line, rule id, severity and
CWE / OWASP MASVS references.

The scope of this component is source code only. Compiled artifact (APK / IPA) analysis is
handled by the separate MobSF binary scan step.

## Scan modes

`AC_MOBSFSCAN_SCAN_MODE` picks how the source is analysed:

| Mode | Engine | Needs on the runner | Adds |
| --- | --- | --- | --- |
| `light` (default) | `mobsfscan` CLI, installed at runtime | `python3` only | Rule matches with file, line, CWE and MASVS |
| `advance` | MobSF provisioned on the runner | A MobSF installation | Manifest and certificate analysis, tracker detection and the AppSec security score |

In `advance` mode the step zips the source, hands the archive to
`mobsf-control.sh --action scan` and reads the report it writes. That script sources
`mobsf.env`, starts MobSF on demand, uploads, scans and removes the scan record afterwards, so
the step never talks to the MobSF REST API and leaves nothing behind on a shared runner.

**Advance falls back to light rather than failing the build.** Asking for `advance` on a runner
that cannot serve it still produces a scan, with a warning naming the reason:

- no `appcircle-mobsf-manifest.json` under the installation prefix,
- `mobsf-control.sh` not found,
- the control script reporting an incomplete installation (exit code `3`),
- the source layout not being one MobSF reads (below),
- a report with no `appsec` section to gate on.

Only a genuine MobSF runtime failure (exit code `1`) fails the build.

### Source layout required by advance mode

MobSF accepts a source archive only when an Android or iOS project sits at its root or exactly
one level down. The step checks this before archiving anything, so an unsupported tree falls
back to the light scan instead of returning `This ZIP Format is not supported`:

| Layout | Detected by |
| --- | --- |
| Android Studio | `app/src/main/AndroidManifest.xml` plus `app/src/main/java` or `.../kotlin` |
| Eclipse | `AndroidManifest.xml` beside `src/` |
| iOS | a `*.xcodeproj` |

Point `AC_MOBSFSCAN_SOURCE_PATH` at the project root, not the repository root, when they differ
— in a React Native or Flutter repository that is `android/`.

`.git`, `node_modules`, `Pods`, `Carthage`, `build`, `.gradle`, `.idea` and `DerivedData` are
left out of the archive, since MobSF does not read them and they dominate its size.

Two MobSF behaviours worth knowing: an **iOS source archive** makes MobSF answer with a redirect
marker instead of a report, so advance mode falls back for iOS source; and MobSF's own decompile
and SAST timeouts are 1000 seconds each, which is why `AC_MOBSFSCAN_ADVANCE_TIMEOUT` defaults to
`1800`.

`mobsfscan` is LGPL-3.0-or-later, so it is not shipped inside Appcircle. The step installs the
pinned version with pip at runtime, into an isolated virtualenv under the step's temp directory,
which the runner discards when the build ends. **Docker is not required**, the only runner
requirement is `python3` with the `venv` module.

The temp directory is `$AC_STEP_TEMP` when the step runs as a marketplace component. A Custom
Script does not get that variable, so the step then falls back to
`$AC_TEMP_DIR/appcircle_mobsfscan`.

## Required Inputs

- `AC_REPOSITORY_DIR`: Repository Directory. Specifies the cloned repository directory.
- `AC_MOBSFSCAN_VERSION`: mobsfscan Version. The `mobsfscan` version installed with pip.
  Pinned (default `1.0.0`) so builds stay reproducible instead of silently following the
  latest release.

## Optional Inputs

- `AC_MOBSFSCAN_SCAN_MODE`: Scan Mode. A dropdown of `light` (default) and `advance`. See
  [Scan modes](#scan-modes).
- `AC_MOBSFSCAN_ADVANCE_TIMEOUT`: Advance Scan Timeout. Timeout in seconds for the MobSF scan,
  default `1800`.
- `AC_MOBSFSCAN_MOBSF_PREFIX`: MobSF Installation Prefix. Where MobSF is installed on the runner.
  When empty the step looks at `MOBSF_HOME`, then `/usr/local/appcircle/mobsf` and
  `/opt/appcircle/mobsf`.
- `AC_MOBSFSCAN_MOBSF_CONTROL`: MobSF Control Script Path. Path of `mobsf-control.sh`, which
  ships with the runner package. When empty the step looks under the installation prefix, the
  runner scripts directory and `PATH`.
- `AC_MOBSFSCAN_SOURCE_PATH`: Source Path. Path of the source code to scan. A relative value is
  resolved against the cloned repository directory. Defaults to the repository root.
- `AC_MOBSFSCAN_SCAN_TYPE`: Scan Type. A dropdown of `auto` (default), `android` and `ios`.
  `auto` detects the platform from the source code, the explicit values force a rule set.
- `AC_MOBSFSCAN_OUTPUT_FORMATS`: Output Format. A dropdown of `sarif` (default), `json`, `html`,
  `sonarqube` and `gitlab-sast`. The step form offers one format because each one costs its own
  scan run. Setting the variable to a comma separated list, for example `sarif,json`, still
  produces several.
- `AC_MOBSFSCAN_SEVERITY_THRESHOLD`: Severity Threshold. A dropdown of `error` (default),
  `warning`, `info` and `none`. The build fails when a finding at or above this severity is
  reported, `none` makes the step report only.
- `AC_MOBSFSCAN_CONFIG_PATH`: Config File Path. Path of the `.mobsf` YAML config for rule
  tuning. A relative value is resolved against the source path. When empty, a `.mobsf` file at
  the scan root is picked up by `mobsfscan` automatically.
- `AC_MOBSFSCAN_SAVE_REPORT`: Save Report. A dropdown of `true` (default) and `false`. Report
  files are copied into the artifacts folder when set to `true`.
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
| `AC_MOBSFSCAN_SCAN_MODE_USED` | Which scan ran, `light` or `advance`. |
| `AC_MOBSFSCAN_MOBSF_REPORT_PATH` | Path of the MobSF JSON report, advance mode only. |
| `AC_MOBSFSCAN_SECURITY_SCORE` | MobSF AppSec security score, advance mode only. |

## How the step decides success or failure

`mobsfscan` exits non-zero both when it finds something and when it breaks, so the exit code
alone cannot tell a failed build from a failed tool. The step therefore runs `mobsfscan` with
`--no-fail` and makes the decision itself, from the JSON report:

1. **Findings at or above the threshold** — the step fails, and the reports are still published.
2. **Findings below the threshold, or `none`** — the step succeeds, and the reports are published.
3. **No parseable report, or a non-zero exit code** — `mobsfscan` itself failed. The step fails
   with a different message, so a tool problem is never read as a policy violation.

Advance mode uses the same gate. MobSF grades findings as `high / warning / info / secure /
hotspot`, which the step maps onto `ERROR / WARNING / INFO`; `secure` is a passed check and
`hotspot` needs manual review, so neither counts towards the threshold.

Severities are `ERROR`, `WARNING` and `INFO`. The JSON report is always generated because the
threshold decision is made from it, but it is only published as an artifact when `json` is one
of the requested output formats.

Findings come in two shapes and the console summary keeps them apart:

- **findings** — a rule matched a specific file and line.
- **missing best practices** — informational rules such as "this app does not use certificate
  pinning". They carry no file location and are always `INFO`, which is why a threshold of
  `info` fails on virtually every project.

## Reports

Reports are written under the step's temp directory and, when `AC_MOBSFSCAN_SAVE_REPORT` is
`true`, copied to `$AC_OUTPUT_DIR/mobsfscan_output/`:

| Format | Filename |
| --- | --- |
| `json` | `mobsfscan.json` |
| `sarif` | `mobsfscan.sarif` |
| `html` | `mobsfscan.html` |
| `sonarqube` | `mobsfscan-sonarqube.json` |
| `gitlab-sast` | `mobsfscan-gitlab-sast.json` |

`mobsfscan` accepts a single `-o`, so **each requested format needs its own scan run**. A run
takes a few seconds on a small project but scales with the size of the source tree, which is why
the step form offers a single format and defaults to `sarif`. Request more only where you consume
them, by setting `AC_MOBSFSCAN_OUTPUT_FORMATS` to a comma separated list.

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

- The virtualenv is created under the step's temp directory and never touches the system Python. A global
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

The test suite requires the [RSpec](https://rspec.info) gem and the Ruby standard library. No
Gemfile or Bundler needed:

```bash
ruby test/test_main.rb
```

A pass/fail summary is printed at the end of each run.

The end to end examples run `main.rb` the way the runner does, against the deliberately insecure
samples under `test/sample_projects`. They need `python3` and a reachable package index, and are
opt in:

```bash
MOBSFSCAN_E2E=1 ruby test/test_main.rb
```

Each of those examples builds a fresh virtualenv, and installing `mobsfscan` from pypi.org takes
minutes. Point them at a local wheel directory instead to cut that down, which also exercises
the air gapped install path:

```bash
python3 -m pip download mobsfscan==1.0.0 -d /tmp/mobsfscan-wheelhouse
```

```bash
MOBSFSCAN_E2E=1 MOBSFSCAN_WHEELHOUSE=/tmp/mobsfscan-wheelhouse ruby test/test_main.rb
```

The examples that cover the install itself, a pinned version, a bad pin and an unreachable index,
ignore `MOBSFSCAN_WHEELHOUSE` and always go to the configured index.
