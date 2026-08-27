require 'json'
require 'open3'
require 'pathname'
require 'fileutils'
require 'shellwords'

require_relative 'mobsf'

###### Defaults & Constants
DEFAULT_MOBSFSCAN_VERSION = "1.0.0"
DEFAULT_OUTPUT_FORMATS = "sarif"
DEFAULT_SCAN_TYPE = "auto"
DEFAULT_SEVERITY_THRESHOLD = "critical"
DEFAULT_SCAN_TIMEOUT = 900
INSTALL_TIMEOUT = 1800
VENV_TIMEOUT = 300
VERSION_TIMEOUT = 120

# mobsfscan 1.0.0 requires Python 3.10+. Older pins accept older interpreters,
# so a lower version is only a warning and pip gets the final say.
RECOMMENDED_PYTHON = [3, 10]

SEVERITIES = ["ERROR", "WARNING", "INFO"]
SEVERITY_RANK = {"INFO" => 1, "WARNING" => 2, "ERROR" => 3}
# The gate is expressed in the vocabulary the step form offers, mapped onto the
# severities the two engines report. `none` never fails the build.
SEVERITY_THRESHOLDS = ["critical", "normal", "low", "none"]
THRESHOLD_SEVERITY = {"critical" => "ERROR", "normal" => "WARNING", "low" => "INFO"}
# Both engines grade internally as ERROR/WARNING/INFO. The build log speaks the
# same words the step form offers instead, so the level a user picked and the
# level they read back are the same.
SEVERITY_LABEL = {"ERROR" => "Critical", "WARNING" => "Normal", "INFO" => "Low"}

SCAN_TYPES = ["auto", "android", "ios"]

###### Scan Mode
SCAN_MODES = ["light", "advance"]
DEFAULT_SCAN_MODE = "light"

# mobsfscan takes a single -o, so every output format needs its own run.
OUTPUT_FORMATS = {
  "json" => {:flag => "--json", :filename => "mobsfscan.json"},
  "sarif" => {:flag => "--sarif", :filename => "mobsfscan.sarif"},
  "html" => {:flag => "--html", :filename => "mobsfscan.html"},
  "sonarqube" => {:flag => "--sonarqube", :filename => "mobsfscan-sonarqube.json"},
  "gitlab-sast" => {:flag => "--gitlab-sast", :filename => "mobsfscan-gitlab-sast.json"}
}

NETWORK_ERROR_PATTERNS = [
  "Temporary failure in name resolution",
  "Name or service not known",
  "nodename nor servname provided",
  "Network is unreachable",
  "Connection refused",
  "Read timed out",
  "Failed to establish a new connection",
  "ProxyError",
  "SSLError",
  "CERTIFICATE_VERIFY_FAILED",
  "retries exceeded"
]

###### Enviroment Variable Check
def env_has_key(key)
  return (ENV[key] != nil && ENV[key] != "") ? ENV[key] : abort("Missing #{key}.")
end

def env_default(key, default)
  return (ENV[key] != nil && ENV[key] != "") ? ENV[key].strip : default
end

# The virtualenv and the reports live here, and the runner discards it when the
# build ends, so the step has no cleanup to do.
def get_step_temp()
  step_temp = env_default("AC_STEP_TEMP", nil)
  return step_temp if step_temp != nil

  temp_dir = env_default("AC_TEMP_DIR", nil)
  if temp_dir == nil
    abort("Missing AC_STEP_TEMP or AC_TEMP_DIR.")
  end

  return "#{temp_dir}/appcircle_mobsfscan"
end

if __FILE__ == $PROGRAM_NAME

#step_temp - AC_STEP_TEMP is set for a marketplace component. A Custom Script
#            does not get it, so the documented AC_TEMP_DIR is the fallback and
#            the step keeps its files in its own folder under it.
$step_temp = get_step_temp()

$repository_path = env_has_key("AC_REPOSITORY_DIR")
$output_path = ENV["AC_OUTPUT_DIR"]
$env_file_path = ENV["AC_ENV_FILE_PATH"]

$venv_path = "#{$step_temp}/mobsfscan-venv"
$report_path = "#{$step_temp}/mobsfscan_reports"

#mobsfscan_version - Pinned on purpose, never "latest", so builds stay reproducible
$mobsfscan_version = env_default("AC_MOBSFSCAN_VERSION", DEFAULT_MOBSFSCAN_VERSION)

#save_report - Options: true, false
$save_report = env_default("AC_MOBSFSCAN_SAVE_REPORT", "true") != "false"

end # if __FILE__ == $PROGRAM_NAME

###### Abort Function
def abort_script(error)
  abort("@@[error] #{error}")
end

###### Log Masking
# An internal package index is configured through pip's own environment
# variables, and such a URL often embeds credentials, so whatever it holds is
# scrubbed from the command log and from pip's own output.
MASKED_ENV_KEYS = ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"]

def mask_secrets(text)
  masked = "#{text}"
  MASKED_ENV_KEYS.each do |key|
    secret = env_default(key, nil)
    masked = masked.gsub(secret, "***") if secret != nil
  end

  return masked
end

###### Run Command Function
# The command is an argv array and is never handed to a shell, so user supplied
# paths and free form parameters cannot be reinterpreted as shell syntax.
# Returns stdout, stderr and the exit code.
def run_command(command, skip_abort, timeout = nil, environment = {})
  puts "@@[command] #{mask_secrets(command.shelljoin)}"

  stdout_str = ""
  stderr_str = ""
  status = nil

  begin
    Open3.popen3(environment, *command, :pgroup => true) do |stdin, stdout, stderr, wait_thr|
      stdin.close
      readers = [
        Thread.new { stdout.each_line { |line| stdout_str += line } },
        Thread.new { stderr.each_line { |line| stderr_str += line } }
      ]

      if timeout != nil && wait_thr.join(timeout) == nil
        kill_process_group(wait_thr.pid)
        readers.each { |reader| reader.kill }
        abort_script("`#{File.basename(command[0])}` exceeded the #{timeout} second timeout and was terminated.")
      end

      readers.each { |reader| reader.join }
      status = wait_thr.value
    end
  rescue Errno::ENOENT
    abort_script("#{command[0]} was not found on this runner.")
  end

  unless status.success?
    abort_script(mask_secrets(stderr_str)) unless skip_abort
  end

  return stdout_str, stderr_str, status.exitstatus
end

# A stuck scan must never hang the build, so the whole process group goes down.
def kill_process_group(pid)
  begin
    Process.kill("TERM", -pid)
    sleep 3
    Process.kill("KILL", -pid)
  rescue Errno::ESRCH, Errno::EPERM
    return
  end
end

###### Input Parsing
def get_source_path()
  configured = env_default("AC_MOBSFSCAN_SOURCE_PATH", $repository_path)
  if (Pathname.new configured).absolute?
    source_path = File.expand_path(configured)
  else
    source_path = File.expand_path((Pathname.new $repository_path).join(configured))
  end

  unless File.exist?(source_path)
    abort_script("The source path to scan does not exist: #{source_path}")
  end

  return source_path
end

# Every enumerated input is read the same way: the value is lower cased and
# has to be one of the options the step form offers.
def get_enum_input(key, default, allowed, label)
  value = env_default(key, default).downcase
  unless allowed.include?(value)
    abort_script("Invalid #{label} `#{value}`. Supported values: #{allowed.join(", ")}.")
  end

  return value
end

def get_positive_number_input(key, default, label)
  configured = env_default(key, "#{default}")
  number = configured.to_i
  unless number > 0
    abort_script("Invalid #{label} `#{configured}`. A positive number of seconds is expected.")
  end

  return number
end

#scan_type - Options: auto, android, ios
def get_scan_type()
  return get_enum_input("AC_MOBSFSCAN_SCAN_TYPE", DEFAULT_SCAN_TYPE, SCAN_TYPES, "scan type")
end

#severity_threshold - Options: critical, normal, low, none
def get_severity_threshold()
  return get_enum_input("AC_MOBSFSCAN_SEVERITY_THRESHOLD", DEFAULT_SEVERITY_THRESHOLD,
                        SEVERITY_THRESHOLDS, "severity threshold")
end

#scan_mode - Options: light, advance
def get_scan_mode()
  return get_enum_input("AC_MOBSFSCAN_SCAN_MODE", DEFAULT_SCAN_MODE, SCAN_MODES, "scan mode")
end

def get_scan_timeout()
  return get_positive_number_input("AC_MOBSFSCAN_TIMEOUT", DEFAULT_SCAN_TIMEOUT, "timeout")
end

#output_formats - Options: sarif, json, html, sonarqube, gitlab-sast
def get_output_formats()
  configured = env_default("AC_MOBSFSCAN_OUTPUT_FORMATS", DEFAULT_OUTPUT_FORMATS).downcase
  formats = []
  configured.split(",").each do |format|
    format = format.strip
    next if format == ""

    formats.push(format) unless formats.include?(format)
  end

  unknown = formats - OUTPUT_FORMATS.keys
  unless unknown.empty?
    abort_script("Unsupported output format(s): #{unknown.join(", ")}. " \
                 "Supported values: #{OUTPUT_FORMATS.keys.join(", ")}.")
  end
  abort_script("At least one output format is required.") if formats.empty?

  return formats
end

# When the config input is empty, mobsfscan discovers a `.mobsf` file at the
# scan root on its own, so -c is deliberately not passed.
def get_config_path(source_path)
  configured = env_default("AC_MOBSFSCAN_CONFIG_PATH", nil)
  return nil if configured == nil

  if (Pathname.new configured).absolute?
    config_path = File.expand_path(configured)
  else
    config_path = File.expand_path((Pathname.new source_path).join(configured))
  end

  unless File.file?(config_path)
    abort_script("The mobsfscan config file does not exist: #{config_path}")
  end

  return config_path
end

# Free form parameters are split with shell word rules and passed as separate
# argv entries, they are never re-evaluated by a shell.
def get_extra_parameters()
  extra = env_default("AC_MOBSFSCAN_EXTRA_PARAMETERS", nil)
  return [] if extra == nil

  begin
    return Shellwords.split(extra)
  rescue ArgumentError => e
    abort_script("The extra parameters input could not be parsed: #{e.message}")
  end
end

###### Python & mobsfscan Installation
def get_python_executable()
  stdout_str, stderr_str, exit_code = run_command(["python3", "-V"], true)
  unless exit_code == 0
    abort_script("python3 was not found on this runner. mobsfscan needs python3 and pip to be installed.")
  end

  version = "#{stdout_str}#{stderr_str}"[/(\d+)\.(\d+)(?:\.(\d+))?/]
  puts "Using python3 #{version}"

  if version != nil
    major_minor = version.split(".")[0, 2].map { |part| part.to_i }
    if (major_minor <=> RECOMMENDED_PYTHON) < 0
      puts "@@[warning] Python #{version} is older than #{RECOMMENDED_PYTHON.join(".")}, " \
           "which recent mobsfscan releases require. The install may fail."
    end
  end

  return "python3"
end

# The virtualenv is isolated on purpose: a global or --user install is rejected
# by PEP 668 managed interpreters on macOS runners, and inside the Android
# container the step runs as root, where it would leak into the pinned runner
# toolchain. AC_STEP_TEMP is discarded when the step ends, so there is no cleanup.
def create_virtualenv(python, venv_path)
  FileUtils.rm_rf(venv_path)
  stdout_str, stderr_str, exit_code = run_command([python, "-m", "venv", venv_path], true, VENV_TIMEOUT)
  unless exit_code == 0
    abort_script("Could not create a Python virtualenv at #{venv_path}. " \
                 "Make sure the `venv` module is available for python3.\n#{stderr_str}")
  end

  return venv_path
end

# mobsfscan shells out to `semgrep`, so the virtualenv's bin directory has to be
# on PATH for the pattern matching rules to run at all.
def venv_environment(venv_path)
  return {
    "PATH" => "#{venv_path}/bin#{File::PATH_SEPARATOR}#{ENV["PATH"]}",
    "VIRTUAL_ENV" => venv_path,
    "PYTHONPATH" => nil,
    "PYTHONHOME" => nil,
    "PIP_DISABLE_PIP_VERSION_CHECK" => "1"
  }
end

def get_pip_install_command(venv_path, version)
  command = ["#{venv_path}/bin/pip", "install", "--no-input", "--disable-pip-version-check",
             "mobsfscan==#{version}"]

  return command
end

def get_install_failure_message(version, output)
  if NETWORK_ERROR_PATTERNS.any? { |pattern| output.include?(pattern) }
    return "mobsfscan could not be installed because this runner has no usable outbound network " \
           "access to the Python package index. Point pip at an internal index or an offline " \
           "wheel directory with PIP_INDEX_URL, or PIP_NO_INDEX together with PIP_FIND_LINKS, " \
           "from an Environment Variable group."
  elsif output.include?("Requires-Python") || output.include?("requires a different Python")
    return "mobsfscan #{version} is not compatible with the python3 version on this runner. " \
           "Pin an older mobsfscan version or use a newer Python."
  elsif output.include?("No matching distribution") || output.include?("Could not find a version")
    return "mobsfscan #{version} was not found on the configured package index. " \
           "Check the pinned version and the index configuration."
  else
    return "Installing mobsfscan #{version} failed."
  end
end

def install_mobsfscan(venv_path, version)
  puts "Installing mobsfscan #{version} into an isolated virtualenv"
  command = get_pip_install_command(venv_path, version)
  stdout_str, stderr_str, exit_code = run_command(command, true, INSTALL_TIMEOUT, venv_environment(venv_path))

  unless exit_code == 0
    # pip echoes the index URL back on failure, so the message is masked too.
    message = get_install_failure_message(version, "#{stdout_str}#{stderr_str}")
    abort_script(mask_secrets("#{message}\n#{stderr_str}"))
  end

  verify_installed_version(venv_path, version)
end

# `mobsfscan --version` writes through its logger, so the version lands on
# stderr rather than stdout.
def verify_installed_version(venv_path, requested)
  stdout_str, stderr_str, exit_code = run_command(["#{venv_path}/bin/mobsfscan", "--version"], true,
                                                  VERSION_TIMEOUT, venv_environment(venv_path))
  installed = "#{stdout_str}\n#{stderr_str}"[/mobsfscan:?\s+v?(\d+\.\d+(?:\.\d+)?)/, 1]
  puts "mobsfscan #{installed != nil ? installed : "version unknown"} is ready"
  return if installed == nil || installed == requested

  puts "@@[warning] Requested mobsfscan #{requested} but #{installed} is installed."
end

###### Scan
def get_scan_command(format, output_file)
  command = ["#{$venv_path}/bin/mobsfscan", OUTPUT_FORMATS[format][:flag],
             "--type", $scan_type, "-o", output_file]

  if $config_path != nil
    command.push("-c")
    command.push($config_path)
  end

  # The step decides success or failure by parsing the JSON report, so the tool
  # is told never to fail. A non zero exit code then means mobsfscan itself
  # broke, not that it found something.
  command.push("--no-fail")
  command.concat($extra_parameters)
  command.push($source_path)

  return command
end

def run_scan(format)
  output_file = "#{$report_path}/#{OUTPUT_FORMATS[format][:filename]}"
  command = get_scan_command(format, output_file)
  stdout_str, stderr_str, exit_code = run_command(command, true, $scan_timeout, venv_environment($venv_path))

  unless exit_code == 0
    abort_script("mobsfscan failed while producing the #{format} report.\n#{stderr_str}")
  end

  return output_file
end

###### Report Parsing & Severity Threshold
def parse_report(path)
  unless File.file?(path)
    abort_script("mobsfscan did not produce a report at #{path}.")
  end

  begin
    return JSON.parse(File.read(path))
  rescue JSON::ParserError => e
    abort_script("The mobsfscan JSON report at #{path} could not be parsed: #{e.message}")
  end
end

# A silently semgrep-less install reports only best practice rules, which would
# otherwise look like a clean project.
def check_scan_errors(report)
  errors = report["errors"] != nil ? report["errors"] : []
  return if errors.empty?

  errors.each { |error| puts "@@[warning] mobsfscan reported: #{error}" }
  return unless errors.any? { |error| "#{error}".include?("semgrep not found") }

  abort_script("semgrep is missing from the mobsfscan installation, so only best practice rules " \
               "ran. This is an installation problem, not a clean scan result.")
end

# File level matches and "missing best practice" rules are counted separately:
# best practice rules carry no file location and always report on a project.
def summarize_report(report)
  findings = new_severity_counter()
  best_practices = new_severity_counter()

  results = report["results"] != nil ? report["results"] : {}
  results.each_value do |detail|
    severity = detail["metadata"] != nil ? detail["metadata"]["severity"] : nil
    severity = "INFO" unless SEVERITIES.include?(severity)
    files = detail["files"] != nil ? detail["files"] : []

    if files.empty?
      best_practices[severity] += 1
    else
      findings[severity] += files.length
    end
  end

  return build_summary(findings, best_practices)
end

def new_severity_counter()
  counter = {}
  SEVERITIES.each { |severity| counter[severity] = 0 }
  return counter
end

def bucket_length(appsec, bucket)
  return appsec[bucket] != nil ? appsec[bucket].length : 0
end

# Both modes report through the same shape, so the console summary, the
# threshold gate and the step outputs are shared.
def build_summary(findings, best_practices)
  totals = {}
  total = 0
  highest = nil
  SEVERITIES.each do |severity|
    totals[severity] = findings[severity] + best_practices[severity]
    total += totals[severity]
    highest = severity if highest == nil && totals[severity] > 0
  end

  return {
    :findings => findings,
    :best_practices => best_practices,
    :totals => totals,
    :total => total,
    :highest => highest
  }
end

def print_summary_line(label, value)
  puts "  #{label.ljust(22)}#{value}"
end

def print_summary(title, summary, threshold)
  puts "------------------------------------------------------"
  puts title
  print_summary_line("Security score", "#{summary[:security_score]} / 100") if summary[:security_score] != nil

  SEVERITIES.each do |severity|
    value = "#{summary[:findings][severity]} finding(s)"
    if summary[:extras] == nil && summary[:best_practices][severity] > 0
      value += " + #{summary[:best_practices][severity]} missing best practice(s)"
    end
    print_summary_line(SEVERITY_LABEL[severity], value)
  end

  if summary[:extras] != nil
    print_summary_line("Passed checks", "#{summary[:extras]["secure"]}")
    print_summary_line("Needs review", "#{summary[:extras]["hotspot"]}")
  end

  print_summary_line("Total", "#{summary[:total]} finding(s)")
  print_summary_line("Worst level found", summary[:highest] != nil ? SEVERITY_LABEL[summary[:highest]] : "none")
  print_summary_line("Fail build on", threshold == "none" ? "none (report only)" : threshold)
  print_summary_line("Verdict", is_threshold_exceeded(summary, threshold) ? "pipeline breaks" : "pipeline continues")
  puts "------------------------------------------------------"
end

# Fails the build when the report holds a finding at or above the selected
# level, so picking `low` is the strictest setting and `critical` the loosest.
# A stricter selection can never let a worse finding through.
def is_threshold_exceeded(summary, threshold)
  return false if threshold == "none"

  severity = THRESHOLD_SEVERITY[threshold]
  abort_script("Unknown severity threshold `#{threshold}`.") if severity == nil

  minimum = SEVERITY_RANK[severity]
  return SEVERITIES.any? { |severity| SEVERITY_RANK[severity] >= minimum && summary[:totals][severity] > 0 }
end

###### Report Publishing & Environment Variables
def copy_reports(report_path, filenames)
  if $output_path == nil
    puts "@@[warning] AC_OUTPUT_DIR is not set, the reports are not published as artifacts."
    return nil
  end

  export_path = (Pathname.new $output_path).join("mobsfscan_output").to_s
  begin
    FileUtils.mkdir_p(export_path)
    filenames.each do |filename|
      source = "#{report_path}/#{filename}"
      next unless File.file?(source)

      puts "Copying #{filename} to #{export_path}"
      FileUtils.cp(source, "#{export_path}/#{filename}")
    end
  rescue Exception => e
    abort_script(e)
  end

  return export_path
end

def write_environment_variables(values)
  if $env_file_path == nil
    puts "@@[warning] AC_ENV_FILE_PATH is not set, the step outputs are not exported."
    return
  end

  begin
    open($env_file_path, 'a') { |f|
      values.each { |key, value| f.puts "#{key}=#{value}" }
    }
  rescue Exception => e
    abort_script(e)
  end
end

# Both modes finish the same way: print the summary, publish the reports,
# export the outputs and apply the severity gate. Never returns.
def publish_and_finish(mode, summary, filenames, formats)
  advance = mode == "advance"
  tool = advance ? "MobSF" : "mobsfscan"
  print_summary(advance ? "MobSF Advance Scan Summary" : "mobsfscan Summary",
                summary, $severity_threshold)

  export_path = $save_report ? copy_reports($report_path, filenames) : nil
  report_dir = export_path != nil ? export_path : $report_path

  outputs = get_step_outputs(summary, report_dir, formats)
  if advance
    outputs["AC_MOBSFSCAN_SCAN_MODE_USED"] = "advance"
    outputs["AC_MOBSFSCAN_MOBSF_REPORT_PATH"] = "#{report_dir}/#{MOBSF_REPORT_FILENAME}"
    outputs["AC_MOBSFSCAN_SECURITY_SCORE"] =
      summary[:security_score] != nil ? summary[:security_score] : ""
  end
  write_environment_variables(outputs)

  if is_threshold_exceeded(summary, $severity_threshold)
    abort_script("#{tool} found a `#{$severity_threshold}` finding or worse, which breaks the " \
                 "pipeline. The reports are still published as artifacts.")
  end

  puts "#{tool} found nothing at or above `#{$severity_threshold}`, the pipeline continues."
  exit 0
end

def get_step_outputs(summary, report_dir, formats)
  outputs = {
    "AC_MOBSFSCAN_FINDING_COUNT" => summary[:total],
    "AC_MOBSFSCAN_CRITICAL_COUNT" => summary[:totals]["ERROR"],
    "AC_MOBSFSCAN_NORMAL_COUNT" => summary[:totals]["WARNING"],
    "AC_MOBSFSCAN_LOW_COUNT" => summary[:totals]["INFO"],
    "AC_MOBSFSCAN_WORST_LEVEL" => summary[:highest] != nil ? SEVERITY_LABEL[summary[:highest]].downcase : "none"
  }

  # Only the JSON path is exported. MobSF itself reports as JSON or PDF, and the
  # other formats are produced for external tools that are handed the artifact
  # folder rather than a variable.
  if formats.include?("json")
    outputs["AC_MOBSFSCAN_JSON_REPORT_PATH"] = "#{report_dir}/#{OUTPUT_FORMATS["json"][:filename]}"
  end

  return outputs
end

###############################################################

if __FILE__ == $PROGRAM_NAME

$source_path = get_source_path()
$scan_type = get_scan_type()
$severity_threshold = get_severity_threshold()
$output_formats = get_output_formats()
$scan_timeout = get_scan_timeout()
$config_path = get_config_path($source_path)
$extra_parameters = get_extra_parameters()
$scan_mode = get_scan_mode()

FileUtils.mkdir_p($step_temp)
FileUtils.mkdir_p($report_path)

### Advance mode uses the MobSF installation provisioned on the runner and
### scans a zip of the source, falling back to the light scan whenever the
### runner cannot serve it.
if $scan_mode == "advance"
  $advance_summary = try_advance_scan()
  publish_and_finish("advance", $advance_summary, [MOBSF_REPORT_FILENAME], []) if $advance_summary != nil
  puts "@@[warning] Falling back to the light scan."
end

puts "Scanning #{$source_path} (type: #{$scan_type}, formats: #{$output_formats.join(", ")})"
if $config_path != nil
  puts "Using mobsfscan config #{$config_path}"
else
  puts "No explicit config, a `.mobsf` file at the scan root is picked up automatically"
end

create_virtualenv(get_python_executable(), $venv_path)
install_mobsfscan($venv_path, $mobsfscan_version)

### JSON is always produced, it is the report the threshold decision is made
### from. It is only published as an artifact when the user asked for it.
scan_formats = ["json"]
$output_formats.each { |format| scan_formats.push(format) unless scan_formats.include?(format) }
scan_formats.each { |format| run_scan(format) }

$report = parse_report("#{$report_path}/#{OUTPUT_FORMATS["json"][:filename]}")
check_scan_errors($report)

publish_and_finish("light", summarize_report($report),
                   $output_formats.map { |format| OUTPUT_FORMATS[format][:filename] },
                   $output_formats)

end # if __FILE__ == $PROGRAM_NAME
