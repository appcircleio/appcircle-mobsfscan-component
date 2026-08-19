require 'json'
require 'open3'
require 'pathname'
require 'fileutils'
require 'shellwords'
require 'English'

###### Defaults & Constants
DEFAULT_MOBSFSCAN_VERSION = "1.0.0"
DEFAULT_OUTPUT_FORMATS = "sarif,json"
DEFAULT_SCAN_TYPE = "auto"
DEFAULT_SEVERITY_THRESHOLD = "error"
DEFAULT_SCAN_TIMEOUT = 900
INSTALL_TIMEOUT = 1800
VENV_TIMEOUT = 300
VERSION_TIMEOUT = 120

# mobsfscan 1.0.0 requires Python 3.10+. Older pins accept older interpreters,
# so a lower version is only a warning and pip gets the final say.
RECOMMENDED_PYTHON = [3, 10]

SEVERITIES = ["ERROR", "WARNING", "INFO"]
SEVERITY_RANK = {"INFO" => 1, "WARNING" => 2, "ERROR" => 3}
SEVERITY_THRESHOLDS = ["none", "info", "warning", "error"]
SCAN_TYPES = ["auto", "android", "ios"]

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

#pip_index_url - Masked in the logs, it may carry credentials
$pip_index_url = env_default("AC_MOBSFSCAN_PIP_INDEX_URL", nil)

#pip_find_links - Directory or URL of the wheels for an air gapped install
$pip_find_links = env_default("AC_MOBSFSCAN_PIP_FIND_LINKS", nil)

end # if __FILE__ == $PROGRAM_NAME

###### Abort Function
def abort_script(error)
  abort("@@[error] #{error}")
end

###### Log Masking
# The pip index URL may embed credentials, so it never reaches the build log.
def mask_secrets(text)
  masked = "#{text}"
  return masked if $pip_index_url == nil

  return masked.gsub($pip_index_url, "***")
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

#scan_type - Options: auto, android, ios
def get_scan_type()
  scan_type = env_default("AC_MOBSFSCAN_SCAN_TYPE", DEFAULT_SCAN_TYPE).downcase
  unless SCAN_TYPES.include?(scan_type)
    abort_script("Invalid scan type `#{scan_type}`. Supported values: #{SCAN_TYPES.join(", ")}.")
  end

  return scan_type
end

#severity_threshold - Options: none, info, warning, error
def get_severity_threshold()
  threshold = env_default("AC_MOBSFSCAN_SEVERITY_THRESHOLD", DEFAULT_SEVERITY_THRESHOLD).downcase
  unless SEVERITY_THRESHOLDS.include?(threshold)
    abort_script("Invalid severity threshold `#{threshold}`. Supported values: #{SEVERITY_THRESHOLDS.join(", ")}.")
  end

  return threshold
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

def get_scan_timeout()
  configured = env_default("AC_MOBSFSCAN_TIMEOUT", "#{DEFAULT_SCAN_TIMEOUT}")
  timeout = configured.to_i
  unless timeout > 0
    abort_script("Invalid timeout `#{configured}`. A positive number of seconds is expected.")
  end

  return timeout
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

  if $pip_find_links != nil
    command.push("--no-index")
    command.push("--find-links")
    command.push($pip_find_links)
  end

  if $pip_index_url != nil
    command.push("--index-url")
    command.push($pip_index_url)
  end

  return command
end

def get_install_failure_message(version, output)
  if NETWORK_ERROR_PATTERNS.any? { |pattern| output.include?(pattern) }
    return "mobsfscan could not be installed because this runner has no usable outbound network " \
           "access to the Python package index. Provide an internal index with the pip index URL " \
           "input, or an offline wheel directory with the pip find-links input."
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
  findings = {}
  best_practices = {}
  totals = {}
  SEVERITIES.each do |severity|
    findings[severity] = 0
    best_practices[severity] = 0
  end

  results = report["results"] != nil ? report["results"] : {}
  results.each do |rule_id, detail|
    severity = detail["metadata"] != nil ? detail["metadata"]["severity"] : nil
    severity = "INFO" unless SEVERITIES.include?(severity)
    files = detail["files"] != nil ? detail["files"] : []

    if files.empty?
      best_practices[severity] += 1
    else
      findings[severity] += files.length
    end
  end

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

def print_summary(summary, threshold)
  puts "------------------------------------------------------"
  puts "mobsfscan Summary"
  SEVERITIES.each do |severity|
    puts "#{severity} : #{summary[:findings][severity]} finding(s), " \
         "#{summary[:best_practices][severity]} missing best practice(s)"
  end
  puts "Total : #{summary[:total]} finding(s)"
  puts "Highest Severity : #{summary[:highest] != nil ? summary[:highest] : "none"}"
  puts "Severity Threshold : #{threshold}"
  puts "------------------------------------------------------"
end

def is_threshold_exceeded(summary, threshold)
  return false if threshold == "none"

  minimum = SEVERITY_RANK[threshold.upcase]
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

def get_step_outputs(summary, report_dir, formats)
  outputs = {
    "AC_MOBSFSCAN_REPORT_DIR" => report_dir,
    "AC_MOBSFSCAN_FINDING_COUNT" => summary[:total],
    "AC_MOBSFSCAN_ERROR_COUNT" => summary[:totals]["ERROR"],
    "AC_MOBSFSCAN_WARNING_COUNT" => summary[:totals]["WARNING"],
    "AC_MOBSFSCAN_INFO_COUNT" => summary[:totals]["INFO"],
    "AC_MOBSFSCAN_HIGHEST_SEVERITY" => summary[:highest] != nil ? summary[:highest] : "NONE"
  }

  formats.each do |format|
    next unless ["json", "sarif"].include?(format)

    outputs["AC_MOBSFSCAN_#{format.upcase}_REPORT_PATH"] = "#{report_dir}/#{OUTPUT_FORMATS[format][:filename]}"
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

puts "Scanning #{$source_path} (type: #{$scan_type}, formats: #{$output_formats.join(", ")})"
if $config_path != nil
  puts "Using mobsfscan config #{$config_path}"
else
  puts "No explicit config, a `.mobsf` file at the scan root is picked up automatically"
end

FileUtils.mkdir_p($step_temp)

create_virtualenv(get_python_executable(), $venv_path)
install_mobsfscan($venv_path, $mobsfscan_version)

FileUtils.mkdir_p($report_path)

### JSON is always produced, it is the report the threshold decision is made
### from. It is only published as an artifact when the user asked for it.
scan_formats = ["json"]
$output_formats.each { |format| scan_formats.push(format) unless scan_formats.include?(format) }
scan_formats.each { |format| run_scan(format) }

$report = parse_report("#{$report_path}/#{OUTPUT_FORMATS["json"][:filename]}")
check_scan_errors($report)

$summary = summarize_report($report)
print_summary($summary, $severity_threshold)

$export_path = nil
if $save_report
  filenames = $output_formats.map { |format| OUTPUT_FORMATS[format][:filename] }
  $export_path = copy_reports($report_path, filenames)
end

write_environment_variables(get_step_outputs($summary, $export_path != nil ? $export_path : $report_path, $output_formats))

if is_threshold_exceeded($summary, $severity_threshold)
  abort_script("mobsfscan found findings at or above the `#{$severity_threshold}` severity " \
               "threshold. The reports are still published as artifacts.")
end

puts "mobsfscan completed without exceeding the severity threshold."

exit 0

end # if __FILE__ == $PROGRAM_NAME
