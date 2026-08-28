# Appcircle _MobSF Source Code Scan_ component

Runs MobSF static analysis on mobile source code: Java, Kotlin, Android XML, Swift and
Objective-C. Findings carry file, line, rule id, severity and CWE / OWASP MASVS references.

Two scan modes:

- **light** runs the [mobsfscan](https://github.com/MobSF/mobsfscan) CLI, installed at runtime
  with pip into a throwaway virtualenv. The only runner requirement is `python3`, and Docker is
  never needed.
- **advance** sends a zip of the source to the MobSF installation provisioned on the runner,
  which adds manifest, certificate and AppSec score analysis. MobSF reports **JSON only**, so
  the Output Format field does not apply in this mode. When the runner has no usable MobSF, the
  step says why and runs the light scan instead of failing the build.

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
  or `gitlab-sast` — exactly the formats `mobsfscan` itself emits (`--sarif`, `--json`,
  `--html`, `--sonarqube`, `--gitlab-sast`). Each format costs its own scan run, so the form
  offers one; the variable also accepts a comma separated list. It applies to the **light**
  scan only: the advance scan reports JSON, which is all MobSF offers here.
- `AC_MOBSFSCAN_SEVERITY_THRESHOLD`: Fail Build On. `critical` (default), `normal`, `low` or
  `none`. The pipeline breaks when the report holds a finding at the selected level **or worse**,
  so `low` is the strictest setting and `critical` the loosest. `none` only reports. The levels
  map onto what the engines report: `critical` is mobsfscan `ERROR` and MobSF `high`, `normal` is
  `WARNING` / `warning`, `low` is `INFO` / `info`. MobSF `secure` and `hotspot` entries never
  break the pipeline.
- `AC_MOBSFSCAN_MIN_SCORE`: Minimum Security Score. Breaks the pipeline when MobSF's score out
  of 100 falls below this. Empty (default) disables the check. Only the **advance** scan reports
  a score; a light scan has nothing to compare against, so the check is skipped and the summary
  says so. See [The two gates](#the-two-gates).
- `AC_MOBSFSCAN_CONFIG_PATH`: Config File Path. Path of the `.mobsf` config for rule tuning.
  When empty, a `.mobsf` file at the scan root is picked up automatically.
- `AC_MOBSFSCAN_SAVE_REPORT`: Save Report. Copies the reports into the artifacts folder when
  `true` (default).
- `AC_MOBSFSCAN_TIMEOUT`: Scan Timeout. Seconds for a single mobsfscan run, default `900`.
- `AC_MOBSFSCAN_ADVANCE_TIMEOUT`: Advance Scan Timeout. Seconds for the MobSF scan, default
  `1800`.
- `AC_MOBSFSCAN_EXTRA_PARAMETERS`: Scanner Parameters. Extra mobsfscan parameters, split with
  shell word rules and passed as separate arguments, never through a shell.

## The two gates

Two independent gates decide the build, and **both are evaluated on every scan**:

| Gate | Input | Reads |
| --- | --- | --- |
| Level gate | `AC_MOBSFSCAN_SEVERITY_THRESHOLD` (Fail Build On) | the findings |
| Score gate | `AC_MOBSFSCAN_MIN_SCORE` (Minimum Security Score) | the MobSF score out of 100 |

They are not chained, so neither one gates the other:

- Either gate on its own breaks the pipeline. The build fails as soon as one of them is breached,
  whatever the other says.
- `Fail Build On = none` disables the level gate only. The score gate stays in force, so a score
  below the minimum still breaks the build.
- A score comfortably above the minimum does not excuse a finding at or above the selected level,
  and a clean level gate does not excuse a low score.
- The score gate is skipped when the report carries no score, which is every **light** scan.
  Setting Minimum Security Score without switching to `advance` therefore changes nothing, and
  the summary line says so.

Whichever gate breaks the build, the reports are published first, so the findings stay
downloadable on the failing path.

## Output Variables

- `AC_MOBSFSCAN_SCAN_MODE_USED`: Which scan ran, `light` or `advance`.
- `AC_MOBSFSCAN_SECURITY_SCORE`: The score out of 100, set only when the advance scan ran.
- `AC_MOBSFSCAN_FINDING_COUNT`, `AC_MOBSFSCAN_CRITICAL_COUNT`, `AC_MOBSFSCAN_NORMAL_COUNT`,
  `AC_MOBSFSCAN_LOW_COUNT`: Finding counts per level.
- `AC_MOBSFSCAN_WORST_LEVEL`: `critical`, `normal`, `low`, or `none`.

No report path is exported: the reports are written straight into `$AC_OUTPUT_DIR` under a fixed
name, so a following step already knows where they are.

## Reports

Each report is published directly into `$AC_OUTPUT_DIR`, under its own name and unarchived, so
add Export Build Artifacts after this step:

| Format | File |
| --- | --- |
| `sarif` | `mobsf-source-code-analyze.sarif` |
| `json` | `mobsf-source-code-analyze.json` |
| `html` | `mobsf-source-code-analyze.html` |
| `sonarqube` | `mobsf-source-code-analyze.sonarqube.json` |
| `gitlab-sast` | `mobsf-source-code-analyze.gitlab-sast.json` |

The advance scan publishes `mobsf-source-code-analyze.json`. Reports are published on the
failing path too.

## The build log

The light scan names what it is about to do, then walks three numbered stages, then closes with
a summary in the same words the form uses, ending in the verdict:

```
------------------------------------------------------
MobSF Source Code Scan - light scan
  Scanner               mobsfscan 1.0.0 CLI
  Source path           /repository
  Rule set              auto (detected from the source)
  Report format(s)      sarif
  Config                `.mobsf` at the scan root, when present
  Fail build on         critical
------------------------------------------------------

[1/3] Installing the scanner
[2/3] Scanning the source code
[3/3] Grading the findings
------------------------------------------------------
MobSF Source Code Scan Summary - light scan
  Critical              6 finding(s)
  Normal                3 finding(s)
  Low                   1 finding(s)
  Total                 10 finding(s)
  Worst level found     Critical
  Fail build on         critical
  Minimum score         not set
  Verdict               pipeline breaks
------------------------------------------------------
```

## Air gapped runners

The step has no package index inputs. `pip` reads its own configuration, so set `PIP_INDEX_URL`
for an internal index, or `PIP_NO_INDEX` with `PIP_FIND_LINKS` for a mirrored wheel directory,
from an Environment Variable group or the runner's `pip.conf`. A credentialed index URL belongs
there rather than in a step field, and the step scrubs whatever those variables hold from the
build log. When the install fails for lack of network, the step says so and names these
variables instead of surfacing a raw pip error.

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
