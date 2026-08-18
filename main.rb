# frozen_string_literal: true

# Appcircle mobsfscan component.
#
# Runs mobsfscan (MobSF's source-code SAST engine) against the checked out
# repository. mobsfscan is LGPL-3.0-or-later, so it is not redistributed with
# Appcircle: it is installed at runtime with pip into an isolated virtualenv
# under AC_STEP_TEMP and discarded when the step ends.
#
# Only Ruby stdlib is used, steps run against the runner's system Ruby without
# Bundler.

require 'fileutils'
require 'json'
require 'open3'
require 'pathname'
require 'shellwords'

DEFAULT_MOBSFSCAN_VERSION = '1.0.0'
DEFAULT_OUTPUT_FORMATS = 'sarif,json'
DEFAULT_SCAN_TYPE = 'auto'
DEFAULT_SEVERITY_THRESHOLD = 'error'
DEFAULT_SCAN_TIMEOUT = 900
INSTALL_TIMEOUT = 1800
VENV_TIMEOUT = 300

# mobsfscan 1.0.0 requires Python 3.10+. Older pins accept older interpreters,
# so a lower version is a warning and pip gets the final say.
RECOMMENDED_PYTHON = [3, 10].freeze

SEVERITY_RANK = { 'INFO' => 1, 'WARNING' => 2, 'ERROR' => 3 }.freeze
SEVERITIES = %w[ERROR WARNING INFO].freeze
THRESHOLDS = %w[none info warning error].freeze
SCAN_TYPES = %w[auto android ios].freeze

# mobsfscan takes a single -o, so every format needs its own invocation.
OUTPUT_FORMATS = {
  'json' => { flag: '--json', filename: 'mobsfscan.json' },
  'sarif' => { flag: '--sarif', filename: 'mobsfscan.sarif' },
  'html' => { flag: '--html', filename: 'mobsfscan.html' },
  'sonarqube' => { flag: '--sonarqube', filename: 'mobsfscan-sonarqube.json' },
  'gitlab-sast' => { flag: '--gitlab-sast', filename: 'mobsfscan-gitlab-sast.json' }
}.freeze

NETWORK_ERROR_PATTERNS = [
  'Temporary failure in name resolution',
  'Name or service not known',
  'nodename nor servname provided',
  'Network is unreachable',
  'Connection refused',
  'Read timed out',
  'Failed to establish a new connection',
  'ProxyError',
  'SSLError',
  'CERTIFICATE_VERIFY_FAILED',
  'retries exceeded'
].freeze

# Raised for anything that should fail the step with a readable message
# instead of a Ruby backtrace.
class StepError < StandardError; end

# Raised when a command exceeds its timeout, so a hung scan never hangs a build.
class CommandTimeout < StepError; end

def env_value(key)
  value = ENV[key]
  value.nil? || value.strip.empty? ? nil : value.strip
end

def env_flag(key, default: false)
  value = env_value(key)
  return default if value.nil?

  %w[true 1 yes on].include?(value.downcase)
end

# The pip index URL may embed credentials, so it is masked in the command log.
def maskable_values
  [env_value('AC_MOBSFSCAN_PIP_INDEX_URL')].compact
end

def mask(text)
  maskable_values.reduce(text) { |acc, secret| acc.gsub(secret, '***') }
end

def log_command(argv)
  puts "@@[command] #{mask(argv.shelljoin)}"
end

def kill_process_group(pid)
  Process.kill('TERM', -pid)
  sleep 3
  Process.kill('KILL', -pid)
rescue Errno::ESRCH, Errno::EPERM
  nil
end

# Runs argv without a shell, so user supplied paths and parameters cannot be
# reinterpreted as shell syntax. Returns [stdout, stderr, exit_status].
def run_command(argv, env: {}, timeout: nil, echo: true)
  log_command(argv)
  stdout_text = +''
  stderr_text = +''
  status = nil

  Open3.popen3(env, *argv, pgroup: true) do |stdin, stdout, stderr, wait_thread|
    stdin.close
    readers = [
      Thread.new { stdout.each_line { |line| stdout_text << line; puts line if echo } },
      Thread.new { stderr.each_line { |line| stderr_text << line } }
    ]

    if timeout && wait_thread.join(timeout).nil?
      kill_process_group(wait_thread.pid)
      readers.each(&:kill)
      raise CommandTimeout, "`#{mask(argv.first)}` exceeded the #{timeout} second timeout and was terminated."
    end

    readers.each(&:join)
    status = wait_thread.value
  end

  [stdout_text, stderr_text, status.exitstatus]
rescue Errno::ENOENT
  raise StepError, "#{argv.first} was not found on this runner."
end

def resolve_source_path
  repository_dir = env_value('AC_REPOSITORY_DIR') || raise(StepError, 'AC_REPOSITORY_DIR is not set.')
  configured = env_value('AC_MOBSFSCAN_SOURCE_PATH') || repository_dir
  path = Pathname.new(configured).absolute? ? configured : File.join(repository_dir, configured)
  path = File.expand_path(path)
  raise StepError, "The source path to scan does not exist: #{path}" unless File.exist?(path)

  path
end

def resolve_scan_type
  scan_type = (env_value('AC_MOBSFSCAN_SCAN_TYPE') || DEFAULT_SCAN_TYPE).downcase
  unless SCAN_TYPES.include?(scan_type)
    raise StepError, "Invalid scan type `#{scan_type}`. Supported values: #{SCAN_TYPES.join(', ')}."
  end

  scan_type
end

def resolve_threshold
  threshold = (env_value('AC_MOBSFSCAN_SEVERITY_THRESHOLD') || DEFAULT_SEVERITY_THRESHOLD).downcase
  unless THRESHOLDS.include?(threshold)
    raise StepError, "Invalid severity threshold `#{threshold}`. Supported values: #{THRESHOLDS.join(', ')}."
  end

  threshold
end

def resolve_formats
  requested = (env_value('AC_MOBSFSCAN_OUTPUT_FORMATS') || DEFAULT_OUTPUT_FORMATS)
              .downcase.split(',').map(&:strip).reject(&:empty?).uniq
  unknown = requested - OUTPUT_FORMATS.keys
  unless unknown.empty?
    raise StepError, "Unsupported output format(s): #{unknown.join(', ')}. " \
                     "Supported values: #{OUTPUT_FORMATS.keys.join(', ')}."
  end
  raise StepError, 'At least one output format is required.' if requested.empty?

  requested
end

def resolve_timeout
  value = env_value('AC_MOBSFSCAN_TIMEOUT') || DEFAULT_SCAN_TIMEOUT.to_s
  timeout = value.to_i
  raise StepError, "Invalid timeout `#{value}`. A positive number of seconds is expected." unless timeout.positive?

  timeout
end

# When the config input is empty, mobsfscan discovers a `.mobsf` file at the
# scan root on its own, so -c is deliberately not passed.
def resolve_config_path(source_path)
  configured = env_value('AC_MOBSFSCAN_CONFIG_PATH')
  return nil if configured.nil?

  path = Pathname.new(configured).absolute? ? configured : File.join(source_path, configured)
  path = File.expand_path(path)
  raise StepError, "The mobsfscan config file does not exist: #{path}" unless File.file?(path)

  path
end

def python_executable
  stdout, _stderr, exit_status = run_command(%w[python3 -V], echo: false)
  raise StepError, 'python3 was not found on this runner. mobsfscan needs python3 and pip to be installed.' unless exit_status&.zero?

  version = stdout.strip[/(\d+)\.(\d+)(?:\.(\d+))?/]
  puts "Using python3 #{version}"
  if version && (version.split('.').first(2).map(&:to_i) <=> RECOMMENDED_PYTHON).negative?
    puts "@@[warning] Python #{version} is older than #{RECOMMENDED_PYTHON.join('.')}, " \
         'which recent mobsfscan releases require. The install may fail.'
  end
  'python3'
end

def create_virtualenv(python, step_temp)
  venv_dir = File.join(step_temp, 'mobsfscan-venv')
  FileUtils.rm_rf(venv_dir)
  _stdout, stderr, exit_status = run_command([python, '-m', 'venv', venv_dir], timeout: VENV_TIMEOUT, echo: false)
  unless exit_status&.zero?
    raise StepError, "Could not create a Python virtualenv under #{step_temp}. " \
                     "Make sure the `venv` module is available for python3.\n#{stderr}"
  end

  venv_dir
end

def pip_install_argv(venv_dir, version)
  argv = [File.join(venv_dir, 'bin', 'pip'), 'install', '--no-input', '--disable-pip-version-check',
          "mobsfscan==#{version}"]
  find_links = env_value('AC_MOBSFSCAN_PIP_FIND_LINKS')
  index_url = env_value('AC_MOBSFSCAN_PIP_INDEX_URL')
  argv.push('--no-index', '--find-links', find_links) if find_links
  argv.push('--index-url', index_url) if index_url
  argv
end

def install_failure_message(version, output)
  if NETWORK_ERROR_PATTERNS.any? { |pattern| output.include?(pattern) }
    'mobsfscan could not be installed because this runner has no usable outbound network access to the ' \
    'Python package index. Provide an internal index with the pip index URL input, or an offline wheel ' \
    'directory with the pip find-links input.'
  elsif output.include?('Requires-Python') || output.include?('requires a different Python')
    "mobsfscan #{version} is not compatible with the python3 version on this runner. " \
    'Pin an older mobsfscan version or use a newer Python.'
  elsif output.include?('No matching distribution') || output.include?('Could not find a version')
    "mobsfscan #{version} was not found on the configured package index. " \
    'Check the pinned version and the index configuration.'
  else
    "Installing mobsfscan #{version} failed."
  end
end

# The venv is isolated on purpose: a global or --user install breaks on
# PEP 668 managed interpreters and leaks into the pinned runner toolchain.
# mobsfscan shells out to `semgrep`, so the venv's bin directory has to be on
# PATH for the pattern matching rules to run at all.
def venv_env(venv_dir)
  {
    'PATH' => "#{File.join(venv_dir, 'bin')}#{File::PATH_SEPARATOR}#{ENV.fetch('PATH', '')}",
    'VIRTUAL_ENV' => venv_dir,
    'PYTHONPATH' => nil,
    'PYTHONHOME' => nil,
    'PIP_DISABLE_PIP_VERSION_CHECK' => '1'
  }
end

def install_mobsfscan(venv_dir, version)
  puts "Installing mobsfscan #{version} into an isolated virtualenv"
  stdout, stderr, exit_status = run_command(pip_install_argv(venv_dir, version),
                                            env: venv_env(venv_dir), timeout: INSTALL_TIMEOUT, echo: false)
  # pip echoes the index URL back on failure, so the message is masked too.
  raise StepError, mask("#{install_failure_message(version, stdout + stderr)}\n#{stderr}") unless exit_status&.zero?

  verify_installed_version(venv_dir, version)
end

# `mobsfscan --version` writes through its logger, so the version lands on
# stderr rather than stdout.
def verify_installed_version(venv_dir, requested)
  stdout, stderr, _exit_status = run_command([File.join(venv_dir, 'bin', 'mobsfscan'), '--version'],
                                             env: venv_env(venv_dir), timeout: 120, echo: false)
  installed = "#{stdout}\n#{stderr}"[/mobsfscan:?\s+v?(\d+\.\d+(?:\.\d+)?)/, 1]
  puts "mobsfscan #{installed || 'version unknown'} is ready"
  return if installed.nil? || installed == requested

  puts "@@[warning] Requested mobsfscan #{requested} but #{installed} is installed."
end

def scan_argv(venv_dir, format, output_file, source_path, scan_type, config_path)
  argv = [File.join(venv_dir, 'bin', 'mobsfscan'), OUTPUT_FORMATS.fetch(format)[:flag],
          '--type', scan_type, '-o', output_file]
  argv.push('-c', config_path) if config_path
  # The step decides success or failure by parsing the JSON report, so the tool
  # is told never to fail. A non zero exit code then means mobsfscan itself
  # broke, not that it found something.
  argv.push('--no-fail')
  argv.concat(extra_parameters)
  argv.push(source_path)
end

# Free form parameters are split with shell word rules and passed as separate
# argv entries, they are never re-evaluated by a shell.
def extra_parameters
  extra = env_value('AC_MOBSFSCAN_EXTRA_PARAMETERS')
  return [] if extra.nil?

  Shellwords.split(extra)
rescue ArgumentError => e
  raise StepError, "The extra parameters input could not be parsed: #{e.message}"
end

def parse_report(path)
  raise StepError, "mobsfscan did not produce a report at #{path}." unless File.file?(path)

  JSON.parse(File.read(path))
rescue JSON::ParserError => e
  raise StepError, "The mobsfscan JSON report at #{path} could not be parsed: #{e.message}"
end

# File level matches and "missing best practice" rules are counted separately:
# best practice rules carry no file location and always report on a project.
def summarize(report)
  findings = SEVERITIES.to_h { |severity| [severity, 0] }
  best_practices = SEVERITIES.to_h { |severity| [severity, 0] }

  (report['results'] || {}).each_value do |detail|
    severity = detail.dig('metadata', 'severity')
    severity = 'INFO' unless SEVERITIES.include?(severity)
    files = detail['files'] || []
    if files.empty?
      best_practices[severity] += 1
    else
      findings[severity] += files.length
    end
  end

  totals = SEVERITIES.to_h { |severity| [severity, findings[severity] + best_practices[severity]] }
  {
    findings: findings,
    best_practices: best_practices,
    totals: totals,
    total: totals.values.sum,
    highest: SEVERITIES.find { |severity| totals[severity].positive? }
  }
end

def print_summary(summary, threshold)
  puts ''
  puts 'mobsfscan summary'
  SEVERITIES.each do |severity|
    puts format('  %-8s %3d finding(s), %d missing best practice(s)',
                severity, summary[:findings][severity], summary[:best_practices][severity])
  end
  puts "  total    #{summary[:total]} finding(s), highest severity: #{summary[:highest] || 'none'}"
  puts "  threshold: #{threshold}"
  puts ''
end

def threshold_exceeded?(summary, threshold)
  return false if threshold == 'none'

  minimum = SEVERITY_RANK.fetch(threshold.upcase)
  SEVERITIES.any? { |severity| SEVERITY_RANK[severity] >= minimum && summary[:totals][severity].positive? }
end

def report_scan_errors(report)
  errors = report['errors'] || []
  return if errors.empty?

  errors.each { |error| puts "@@[warning] mobsfscan reported: #{error}" }
  return unless errors.any? { |error| error.to_s.include?('semgrep not found') }

  raise StepError, 'semgrep is missing from the mobsfscan installation, so only best practice rules ran. ' \
                   'This is an installation problem, not a clean scan result.'
end

def copy_reports(report_dir, filenames)
  output_dir = env_value('AC_OUTPUT_DIR')
  if output_dir.nil?
    puts '@@[warning] AC_OUTPUT_DIR is not set, the reports are not published as artifacts.'
    return nil
  end

  export_dir = File.join(output_dir, 'mobsfscan_output')
  FileUtils.mkdir_p(export_dir)
  filenames.each do |filename|
    source = File.join(report_dir, filename)
    next unless File.file?(source)

    puts "Copying #{filename} to #{export_dir}"
    FileUtils.cp(source, File.join(export_dir, filename))
  end
  export_dir
end

def write_outputs(values)
  env_file = env_value('AC_ENV_FILE_PATH')
  if env_file.nil?
    puts '@@[warning] AC_ENV_FILE_PATH is not set, the step outputs are not exported.'
    return
  end

  File.open(env_file, 'a') do |file|
    values.each { |key, value| file.puts("#{key}=#{value}") }
  end
end

def run_step
  step_temp = env_value('AC_STEP_TEMP') || raise(StepError, 'AC_STEP_TEMP is not set.')
  source_path = resolve_source_path
  scan_type = resolve_scan_type
  threshold = resolve_threshold
  requested_formats = resolve_formats
  timeout = resolve_timeout
  config_path = resolve_config_path(source_path)
  version = env_value('AC_MOBSFSCAN_VERSION') || DEFAULT_MOBSFSCAN_VERSION

  puts "Scanning #{source_path} (type: #{scan_type}, formats: #{requested_formats.join(', ')})"
  puts config_path ? "Using mobsfscan config #{config_path}" : 'No explicit config, a `.mobsf` file at the scan root is picked up automatically'

  venv_dir = create_virtualenv(python_executable, step_temp)
  install_mobsfscan(venv_dir, version)

  report_dir = File.join(step_temp, 'mobsfscan_reports')
  FileUtils.mkdir_p(report_dir)

  # JSON is always produced: it is the report the threshold decision is made
  # from. It is only published as an artifact when the user asked for it.
  produced = {}
  (['json'] + requested_formats).uniq.each do |format|
    filename = OUTPUT_FORMATS.fetch(format)[:filename]
    output_file = File.join(report_dir, filename)
    _stdout, stderr, exit_status = run_command(
      scan_argv(venv_dir, format, output_file, source_path, scan_type, config_path),
      env: venv_env(venv_dir), timeout: timeout, echo: false
    )
    unless exit_status&.zero?
      raise StepError, "mobsfscan failed while producing the #{format} report.\n#{stderr}"
    end

    produced[format] = output_file
  end

  report = parse_report(produced.fetch('json'))
  report_scan_errors(report)
  summary = summarize(report)
  print_summary(summary, threshold)

  export_dir = nil
  if env_flag('AC_MOBSFSCAN_SAVE_REPORT', default: true)
    export_dir = copy_reports(report_dir, requested_formats.map { |format| OUTPUT_FORMATS.fetch(format)[:filename] })
  end

  outputs = {
    'AC_MOBSFSCAN_REPORT_DIR' => export_dir || report_dir,
    'AC_MOBSFSCAN_FINDING_COUNT' => summary[:total],
    'AC_MOBSFSCAN_ERROR_COUNT' => summary[:totals]['ERROR'],
    'AC_MOBSFSCAN_WARNING_COUNT' => summary[:totals]['WARNING'],
    'AC_MOBSFSCAN_INFO_COUNT' => summary[:totals]['INFO'],
    'AC_MOBSFSCAN_HIGHEST_SEVERITY' => summary[:highest] || 'NONE'
  }
  requested_formats.each do |format|
    next unless %w[json sarif].include?(format)

    path = File.join(export_dir || report_dir, OUTPUT_FORMATS.fetch(format)[:filename])
    outputs["AC_MOBSFSCAN_#{format.upcase}_REPORT_PATH"] = path
  end
  write_outputs(outputs)

  if threshold_exceeded?(summary, threshold)
    raise StepError, "mobsfscan found findings at or above the `#{threshold}` severity threshold. " \
                     'The reports are still published as artifacts.'
  end

  puts 'mobsfscan completed without exceeding the severity threshold.'
end

if __FILE__ == $PROGRAM_NAME
  begin
    run_step
  rescue StepError => e
    abort("@@[error] #{e.message}")
  end
end
