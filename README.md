# Appcircle _MobSF Scan_ component

Runs MobSF static analysis on mobile source code: Java, Kotlin, Android XML, Swift and
Objective-C. Findings carry file, line, rule id, severity and CWE / OWASP MASVS references.

Two scan modes:

- **light** runs the [mobsfscan](https://github.com/MobSF/mobsfscan) CLI, installed at runtime
  with pip into a throwaway virtualenv. The only runner requirement is `python3`, and Docker is
  never needed.
- **advance** sends a zip of the source to the MobSF installation provisioned on the runner,
  which adds manifest, certificate and AppSec score analysis. When the runner has no usable
  MobSF, the step says why and runs the light scan instead of failing the build.

Neither tool is shipped inside Appcircle: `mobsfscan` is installed at runtime and MobSF comes
from the runner.

## Required Input Variables

- `AC_REPOSITORY_DIR`: Repository Directory. Specifies the cloned repository directory.
- `AC_MOBSFSCAN_VERSION`: mobsfscan Version. The `mobsfscan` version to install with pip,
  pinned (default `1.0.0`) so that builds stay reproducible.

## Optional Input Variables

- `AC_MOBSFSCAN_SCAN_MODE`: Scan Mode. `light` (default) or `advance`.
- `AC_MOBSFSCAN_SOURCE_PATH`: Source Path. Defaults to the repository root. A relative value is
  resolved against the cloned repository directory.
- `AC_MOBSFSCAN_SCAN_TYPE`: Scan Type. `auto` (default), `android` or `ios`.
- `AC_MOBSFSCAN_OUTPUT_FORMATS`: Output Format. `sarif` (default), `json`, `html`, `sonarqube`
  or `gitlab-sast`. Each format costs its own scan run, so the form offers one; the variable
  also accepts a comma separated list.
- `AC_MOBSFSCAN_SEVERITY_THRESHOLD`: Severity Threshold. `error` (default), `warning`, `info` or
  `none`. The build fails when a finding at or above this severity is reported, and `none` makes
  the step report only.
- `AC_MOBSFSCAN_CONFIG_PATH`: Config File Path. Path of the `.mobsf` config for rule tuning.
  When empty, a `.mobsf` file at the scan root is picked up automatically.
- `AC_MOBSFSCAN_SAVE_REPORT`: Save Report. Copies the reports into the artifacts folder when
  `true` (default).
- `AC_MOBSFSCAN_TIMEOUT`: Scan Timeout. Seconds for a single mobsfscan run, default `900`.
- `AC_MOBSFSCAN_ADVANCE_TIMEOUT`: Advance Scan Timeout. Seconds for the MobSF scan, default
  `1800`.
- `AC_MOBSFSCAN_EXTRA_PARAMETERS`: Scanner Parameters. Extra mobsfscan parameters, split with
  shell word rules and passed as separate arguments, never through a shell.
- `AC_MOBSFSCAN_PIP_INDEX_URL`: Pip Index URL. Alternative package index, masked in the logs.
- `AC_MOBSFSCAN_PIP_FIND_LINKS`: Pip Find Links. Wheel directory for an air gapped install,
  which makes pip run with `--no-index`.

## Output Variables

- `AC_MOBSFSCAN_SCAN_MODE_USED`: Which scan ran, `light` or `advance`.
- `AC_MOBSFSCAN_REPORT_DIR`: Directory holding the generated reports.
- `AC_MOBSFSCAN_SARIF_REPORT_PATH` / `AC_MOBSFSCAN_JSON_REPORT_PATH`: Report paths, when that
  format was requested.
- `AC_MOBSFSCAN_MOBSF_REPORT_PATH` / `AC_MOBSFSCAN_SECURITY_SCORE`: MobSF report path and
  AppSec score, set only when the advance scan ran.
- `AC_MOBSFSCAN_FINDING_COUNT`, `AC_MOBSFSCAN_ERROR_COUNT`, `AC_MOBSFSCAN_WARNING_COUNT`,
  `AC_MOBSFSCAN_INFO_COUNT`, `AC_MOBSFSCAN_HIGHEST_SEVERITY`: Finding counts and the highest
  reported severity, or `NONE`.

Reports are copied to `$AC_OUTPUT_DIR/mobsfscan_output/`, so add Export Build Artifacts after
this step. They are published on the failing path too.

## Running tests

Requires the [RSpec](https://rspec.info) gem and the Ruby standard library. No Gemfile or
Bundler needed.

```bash
ruby test/test_main.rb
```

The end to end examples run `main.rb` the way the runner does and need `python3` plus a package
index. They are opt in, and a local wheel directory keeps them from installing from pypi.org on
every example:

```bash
MOBSFSCAN_E2E=1 MOBSFSCAN_WHEELHOUSE=/tmp/mobsfscan-wheelhouse ruby test/test_main.rb
```

## Contributing

Source: https://github.com/appcircleio/appcircle-mobsfscan-component
