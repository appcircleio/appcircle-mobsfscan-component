# Advance scan mode for the Appcircle mobsfscan component.
#
# Drives the MobSF installation the runner was provisioned with (PL-398): it
# locates the install, zips the checked out source and hands it to
# mobsf-control.sh, then normalizes the AppSec report onto the same summary
# shape the light scan produces.
#
# Loaded by main.rb, and it uses the helpers defined there (run_command,
# abort_script, env_default, parse_report, build_summary). Both files must be
# listed under `files:` in component.yaml or the runner never receives this one.

###### Advance Mode Defaults & Constants
DEFAULT_ADVANCE_TIMEOUT = 1800

# The control script is given the scan timeout and enforces it itself, so the
# step's own bound on the script sits just above it. Without the margin the two
# race, and which one fires first decides whether the build sees the script's
# own message or a bare timeout.
CONTROL_TIMEOUT_MARGIN = 60

# Archiving is bounded separately from the scan: a large repository is slow to
# zip but that is not a stuck scan. It used to borrow VENV_TIMEOUT, which said
# nothing about what was being waited for.
ARCHIVE_TIMEOUT = 900

# Provisioning (PL-398) puts MobSF here: macOS first, then Linux.
DEFAULT_MOBSF_PREFIXES = ["/usr/local/appcircle/mobsf", "/opt/appcircle/mobsf"]
MOBSF_MANIFEST_FILE = "appcircle-mobsf-manifest.json"
MOBSF_CONTROL_SCRIPT = "mobsf-control.sh"
# The same base name the light scan publishes under, so the artifact reads the
# same whichever mode ran. Kept literal: main.rb defines REPORT_BASENAME after
# it requires this file.
MOBSF_REPORT_FILENAME = "mobsf-source-code-analyze.json"
SOURCE_ZIP_FILENAME = "mobsf-source.zip"

# mobsf-control.sh exit codes that the step reacts to.
MOBSF_EXIT_USAGE = 2
MOBSF_EXIT_NOT_PROVISIONED = 3

# MobSF grades findings as high/warning/info/secure/hotspot. Only the first
# three are failures, and they map onto the severities the gate already uses.
# `secure` is a passed check and `hotspot` needs manual review, so neither
# counts towards the threshold.
MOBSF_SEVERITY_MAP = {"high" => "ERROR", "warning" => "WARNING", "info" => "INFO"}
MOBSF_NON_FINDING_BUCKETS = ["secure", "hotspot"]

# Kept out of the uploaded zip: MobSF never looks at them and they dominate
# the archive size.
ZIP_EXCLUDE_DIRS = [".git", ".svn", ".hg", "node_modules", "Pods", "Carthage",
                    "build", ".gradle", ".idea", "DerivedData", "__MACOSX"]

###### Advance Mode Inputs
def get_advance_timeout()
  return get_positive_number_input("AC_MOBSFSCAN_ADVANCE_TIMEOUT", DEFAULT_ADVANCE_TIMEOUT,
                                   "advance timeout")
end

###### MobSF Discovery (Advance Mode)
# The installation prefix comes from MOBSF_HOME, then the well known
# provisioning paths. Returns nil when none of them hold a manifest.
def get_mobsf_prefix()
  candidates = []
  mobsf_home = env_default("MOBSF_HOME", nil)
  candidates.push(mobsf_home) if mobsf_home != nil
  candidates.concat(DEFAULT_MOBSF_PREFIXES)

  candidates.each do |prefix|
    return prefix if File.file?("#{prefix}/#{MOBSF_MANIFEST_FILE}")
  end

  return nil
end

def read_mobsf_manifest(prefix)
  path = "#{prefix}/#{MOBSF_MANIFEST_FILE}"
  begin
    return JSON.parse(File.read(path))
  rescue JSON::ParserError, Errno::ENOENT => e
    puts "@@[warning] The MobSF manifest at #{path} could not be read: #{e.message}"
    return nil
  end
end

def get_mobsf_control(prefix)
  get_mobsf_control_candidates(prefix).each do |candidate|
    return candidate if File.file?(candidate)
  end

  return nil
end

# mobsf-control.sh ships with the runner package rather than under the MobSF
# installation prefix, and the runner directory is not exposed as a build
# variable. A dev macOS runner has MobSF at /usr/local/appcircle/mobsf and the
# script one level up, so every ancestor of the prefix and of the step's own
# working directory is checked for a scripts/ directory.
def get_mobsf_control_candidates(prefix)
  candidates = ["#{prefix}/#{MOBSF_CONTROL_SCRIPT}"]

  roots = [prefix, $step_temp, env_default("AC_TEMP_DIR", nil), env_default("AC_RUNNER_DIR", nil)]
  roots.compact.each do |root|
    ancestor_directories(root).each do |dir|
      candidates.push("#{dir}/scripts/#{MOBSF_CONTROL_SCRIPT}")
    end
  end

  ENV["PATH"].to_s.split(File::PATH_SEPARATOR).each do |dir|
    next if dir.empty?

    candidates.push("#{dir}/#{MOBSF_CONTROL_SCRIPT}")
  end

  return candidates.uniq
end

# The path itself and each of its parents, bounded so a pathological path
# cannot spin.
def ancestor_directories(path, limit = 12)
  directories = []
  current = File.expand_path(path)
  limit.times do
    directories.push(current)
    parent = File.dirname(current)
    break if parent == current

    current = parent
  end

  return directories
end

# Replicates MobSF's own valid_source_code(): the archive is accepted only when
# an Android or iOS project sits at its root or exactly one level down.
# Returning nil here means MobSF would answer "This ZIP Format is not supported",
# so the step can fall back before paying for a zip and an upload.
def detect_source_layout(path)
  layout = detect_source_layout_at(path)
  return layout if layout != nil

  Dir.glob("#{path}/*").each do |entry|
    next unless File.directory?(entry)

    layout = detect_source_layout_at(entry)
    return layout if layout != nil
  end

  return nil
end

def detect_source_layout_at(path)
  if File.file?("#{path}/AndroidManifest.xml") && File.exist?("#{path}/src")
    return "eclipse"
  end

  if File.file?("#{path}/app/src/main/AndroidManifest.xml") &&
     (File.exist?("#{path}/app/src/main/java") || File.exist?("#{path}/app/src/main/kotlin"))
    return "studio"
  end

  return "ios" unless Dir.glob("#{path}/*.xcodeproj").empty?

  return nil
end

###### Source Archive (Advance Mode)
# python3 is already a requirement of this step, so zipfile is used rather than
# depending on a `zip` binary being present on every runner image.
def create_source_zip(source_path, zip_path)
  puts "Archiving #{source_path} for MobSF"
  # Written to a file rather than passed with -c: an inline script turns the
  # logged command into a dozen lines of escaped Python.
  script_path = "#{File.dirname(zip_path)}/mobsf_archive.py"
  script = <<~PYTHON
    import os, sys, zipfile
    source, target, excluded = sys.argv[1], sys.argv[2], set(sys.argv[3].split(","))
    count = 0
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for root, dirs, files in os.walk(source):
            dirs[:] = [d for d in dirs if d not in excluded]
            for name in files:
                full = os.path.join(root, name)
                if os.path.islink(full):
                    continue
                archive.write(full, os.path.relpath(full, source))
                count += 1
    print(count)
  PYTHON

  begin
    FileUtils.mkdir_p(File.dirname(script_path))
    File.write(script_path, script)
  rescue Exception => e
    abort_script(e)
  end

  stdout_str, stderr_str, exit_code = run_command(
    ["python3", script_path, source_path, zip_path, ZIP_EXCLUDE_DIRS.join(",")], true, ARCHIVE_TIMEOUT)

  unless exit_code == 0
    abort_script("The source code could not be archived for MobSF.\n#{stderr_str}")
  end

  size_mb = (File.size(zip_path).to_f / (1024 * 1024)).round(1)
  puts "Archived #{stdout_str.strip} file(s), #{size_mb} MB"

  return zip_path
end

###### Advance Scan
def get_advance_scan_command(control_script, prefix, zip_path, report_path, timeout)
  return [control_script, "--action", "scan",
          "--file", zip_path,
          "--prefix", prefix,
          "--output", report_path,
          "--scan-timeout", "#{timeout}"]
end

# Translates the control script's documented exit codes into an actionable line.
def get_advance_failure_message(exit_code, stderr_str)
  case exit_code
  when MOBSF_EXIT_NOT_PROVISIONED
    return "MobSF is installed but the installation is incomplete. Run `setup-mobsf.sh --action status` on the runner."
  when MOBSF_EXIT_USAGE
    return "The MobSF control script rejected the arguments the step passed. This is a step bug, please report it."
  else
    return "The MobSF scan failed.\n#{stderr_str}"
  end
end

# MobSF grades into high/warning/info/secure/hotspot. This normalizes the
# appsec section onto the same summary shape the light mode produces, so the
# console summary, the threshold gate and the step outputs stay shared.
def summarize_mobsf_report(report)
  appsec = report["appsec"] != nil ? report["appsec"] : {}
  findings = new_severity_counter()
  MOBSF_SEVERITY_MAP.each do |mobsf_severity, severity|
    findings[severity] += bucket_length(appsec, mobsf_severity)
  end

  summary = build_summary(findings, new_severity_counter())
  extras = {}
  MOBSF_NON_FINDING_BUCKETS.each { |bucket| extras[bucket] = bucket_length(appsec, bucket) }

  summary[:extras] = extras
  summary[:security_score] = appsec["security_score"]
  summary[:trackers] = appsec["total_trackers"]

  return summary
end

# Locates the provisioned MobSF and scans with it. Returns the summary, or nil
# when this runner cannot serve an advance scan, which sends the step to the
# light scan rather than failing the build.
def try_advance_scan()
  puts "Advance scan requested, looking for a MobSF installation on this runner"
  prefix = get_mobsf_prefix()
  if prefix == nil
    puts "@@[warning] No MobSF installation found (looked for #{MOBSF_MANIFEST_FILE} under " \
         "#{DEFAULT_MOBSF_PREFIXES.join(", ")})."
    return nil
  end

  manifest = read_mobsf_manifest(prefix)
  puts "Found MobSF #{manifest["mobsfVersion"]} at #{prefix}" if manifest != nil

  control = get_mobsf_control(prefix)
  if control == nil
    puts "@@[warning] MobSF is installed at #{prefix} but #{MOBSF_CONTROL_SCRIPT} was not found " \
         "in the #{get_mobsf_control_candidates(prefix).length} locations searched under " \
         "#{[prefix, $step_temp].compact.join(", ")} and PATH. It ships with the runner package, " \
         "so this runner may predate it."
    return nil
  end

  return run_advance_scan(prefix, control, "#{$report_path}/#{MOBSF_REPORT_FILENAME}")
end

# Runs the advance scan. Returns the summary, or nil when the runner cannot
# serve it, in which case the caller falls back to the light scan.
def run_advance_scan(prefix, control_script, report_path)
  layout = detect_source_layout($source_path)
  if layout == nil
    puts "@@[warning] #{$source_path} does not look like an Android or iOS project MobSF can read " \
         "(it expects `app/src/main/AndroidManifest.xml`, `AndroidManifest.xml` plus `src/`, " \
         "or a `.xcodeproj`, at the root or one level down)."
    return nil
  end
  puts "Detected #{layout} source layout"

  zip_path = "#{$step_temp}/#{SOURCE_ZIP_FILENAME}"
  create_source_zip($source_path, zip_path)

  command = get_advance_scan_command(control_script, prefix, zip_path, report_path, $advance_timeout)
  stdout_str, stderr_str, exit_code = run_command(command, true,
                                                 $advance_timeout + CONTROL_TIMEOUT_MARGIN)
  puts stdout_str unless stdout_str.strip.empty?

  unless exit_code == 0
    if exit_code == MOBSF_EXIT_NOT_PROVISIONED
      puts "@@[warning] #{get_advance_failure_message(exit_code, stderr_str)}"
      return nil
    end
    abort_script(get_advance_failure_message(exit_code, stderr_str))
  end

  report = parse_report(report_path)

  # An iOS source archive makes MobSF answer with a redirect marker instead of
  # a report, so there is nothing to gate on.
  if report["appsec"] == nil
    puts "@@[warning] MobSF returned no `appsec` section for this source archive" \
         "#{report["type"] != nil ? " (type: #{report["type"]})" : ""}, so there is nothing to gate on."
    return nil
  end

  return summarize_mobsf_report(report)
end

