# ─── Dependencies ─────────────────────────────────────────────────────────────
require 'rspec'
require 'rspec/core/formatters/base_formatter'
require 'fileutils'
require 'json'
require 'open3'
require 'stringio'
require 'tmpdir'

MAIN_RB = File.expand_path('../main.rb', __dir__)
SAMPLE_PROJECTS = File.expand_path('sample_projects', __dir__)

# ─── Custom Formatter ─────────────────────────────────────────────────────────
class ReadableFormatter < RSpec::Core::Formatters::BaseFormatter
  RSpec::Core::Formatters.register(
    self,
    :example_group_started,
    :example_group_finished,
    :example_passed,
    :example_failed,
    :example_pending,
    :dump_summary
  )

  PASS  = "\e[32;1m[ PASS ]\e[0m"
  FAIL  = "\e[31;1m[ FAIL ]\e[0m"
  ERROR = "\e[31;1m[ERROR ]\e[0m"
  SKIP  = "\e[33;1m[ SKIP ]\e[0m"

  DIVIDER     = "\e[90m#{'─' * 72}\e[0m"
  DIVIDER_FAT = "\e[90m#{'═' * 72}\e[0m"

  GROUP_COLORS = [
    "\e[34;1m",
    "\e[35;1m",
    "\e[36;1m",
    "\e[33;1m",
  ].freeze

  def initialize(output)
    super
    @depth    = 0
    @top_idx  = -1
    @failures = []
    @counts   = { passed: 0, failed: 0, pending: 0 }
  end

  def example_group_started(notification)
    group = notification.group
    if group.parent_groups.size <= 1
      output.puts if @depth.zero?
      @top_idx = (@top_idx + 1) % GROUP_COLORS.size
      output.puts "  #{GROUP_COLORS[@top_idx]}#{group.description}\e[0m"
    else
      output.puts "    #{'  ' * (@depth - 1)}\e[90m▸ \e[0m\e[37m#{group.description}\e[0m"
    end
    @depth += 1
  end

  def example_group_finished(_notification)
    @depth -= 1 if @depth > 0
  end

  def example_passed(notification)
    @counts[:passed] += 1
    print_example(PASS, notification.example)
  end

  def example_failed(notification)
    @counts[:failed] += 1
    ex    = notification.example
    exc   = ex.execution_result.exception
    badge = exc.is_a?(RSpec::Expectations::ExpectationNotMetError) ? FAIL : ERROR
    print_example(badge, ex)
    @failures << notification
  end

  def example_pending(notification)
    @counts[:pending] += 1
    ex = notification.example
    output.puts "    #{'  ' * [0, @depth - 1].max}#{SKIP}  #{ex.description}"
  end

  def dump_summary(notification)
    output.puts
    output.puts DIVIDER_FAT

    unless @failures.empty?
      output.puts "\n  \e[1;31mFailures:\e[0m\n"
      @failures.each_with_index do |n, i|
        ex  = n.example
        exc = ex.execution_result.exception
        output.puts "  \e[1m#{i + 1}) #{ex.full_description}\e[0m"
        exc.message.lines.first(6).each { |line| output.puts "     \e[31m#{line.rstrip}\e[0m" }
        output.puts "     \e[90m# #{ex.location}\e[0m"
        output.puts
      end
      output.puts DIVIDER
    end

    t   = notification.examples.size
    p   = @counts[:passed]
    f   = @counts[:failed]
    s   = @counts[:pending]
    sec = format('%.3fs', notification.duration)

    parts = ["\e[32m#{p} passed\e[0m"]
    parts << "\e[31m#{f} failed\e[0m"  if f > 0
    parts << "\e[33m#{s} pending\e[0m" if s > 0

    overall = f.zero? ? "\e[32;1m✔  All #{t} tests passed\e[0m" : "\e[31;1m✖  #{f} of #{t} tests failed\e[0m"
    output.puts "\n  #{overall}"
    output.puts "  #{parts.join('  |  ')}  \e[90m(#{sec})\e[0m"
    output.puts DIVIDER_FAT
  end

  private

  def print_example(badge, example)
    indent = '  ' * [0, @depth - 1].max
    time   = format('%.3fs', example.execution_result.run_time)
    output.puts "    #{indent}#{badge}  #{example.description}  \e[90m(#{time})\e[0m"
  end
end

# ─── Load main.rb (top-level execution is guarded by __FILE__ == $PROGRAM_NAME)
require_relative '../main.rb'

# ─── Global State Helpers ─────────────────────────────────────────────────────
# main.rb keeps its configuration in globals that are assigned only when it runs
# as the main script, so the unit tests set them directly.
INPUT_KEYS = %w[
  AC_REPOSITORY_DIR AC_STEP_TEMP AC_TEMP_DIR AC_OUTPUT_DIR AC_ENV_FILE_PATH
  AC_MOBSFSCAN_SOURCE_PATH AC_MOBSFSCAN_SCAN_TYPE AC_MOBSFSCAN_VERSION
  AC_MOBSFSCAN_OUTPUT_FORMATS AC_MOBSFSCAN_SEVERITY_THRESHOLD
  AC_MOBSFSCAN_CONFIG_PATH AC_MOBSFSCAN_SAVE_REPORT AC_MOBSFSCAN_TIMEOUT
  AC_MOBSFSCAN_EXTRA_PARAMETERS AC_MOBSFSCAN_PIP_INDEX_URL
  AC_MOBSFSCAN_PIP_FIND_LINKS
].freeze

def reset_inputs
  INPUT_KEYS.each { |key| ENV.delete(key) }
  $repository_path = nil
  $output_path = nil
  $env_file_path = nil
  $venv_path = nil
  $report_path = nil
  $source_path = nil
  $scan_type = nil
  $config_path = nil
  $extra_parameters = []
  $pip_index_url = nil
  $pip_find_links = nil
end

# abort_script writes to $stderr and raises SystemExit. Returns the message, or
# nil when the block did not abort.
def capture_abort
  buffer = StringIO.new
  original = $stderr
  $stderr = buffer
  aborted = false
  begin
    yield
  rescue SystemExit
    aborted = true
  ensure
    $stderr = original
  end
  return aborted ? buffer.string : nil
end

def capture_stdout
  buffer = StringIO.new
  original = $stdout
  $stdout = buffer
  begin
    yield
  ensure
    $stdout = original
  end
  return buffer.string
end

# ─── Report Helpers ───────────────────────────────────────────────────────────
def build_report(results, errors = [])
  return { 'errors' => errors, 'mobsfscan_version' => '1.0.0', 'results' => results }
end

def build_rule(severity, file_count)
  files = []
  file_count.times do |index|
    files.push({ 'file_path' => "/src/File#{index}.java", 'match_lines' => [index + 1, index + 1] })
  end
  return { 'files' => files, 'metadata' => { 'severity' => severity } }
end

# ─── Subprocess Helper ────────────────────────────────────────────────────────
# Runs main.rb in a child process with a controlled ENV, the way the runner does.
# Nil values explicitly unset keys inherited from the parent process.
#
# Report content assertions must not depend on the severity gate, so the helper
# scans in report only mode. The threshold examples set their own value, and
# passing nil for a key exercises the step's own default.
def run_main(source, env = {})
  Dir.mktmpdir do |workspace|
    step_temp = File.join(workspace, 'step_temp')
    output_dir = File.join(workspace, 'output')
    env_file = File.join(workspace, 'env_file')
    FileUtils.mkdir_p([step_temp, output_dir])
    FileUtils.touch(env_file)

    clean_env = INPUT_KEYS.each_with_object({}) { |key, acc| acc[key] = nil }
                          .merge(
                            'AC_REPOSITORY_DIR' => SAMPLE_PROJECTS,
                            'AC_STEP_TEMP' => step_temp,
                            'AC_TEMP_DIR' => step_temp,
                            'AC_OUTPUT_DIR' => output_dir,
                            'AC_ENV_FILE_PATH' => env_file,
                            'AC_MOBSFSCAN_SOURCE_PATH' => source,
                            'AC_MOBSFSCAN_SEVERITY_THRESHOLD' => 'none',
                            'AC_MOBSFSCAN_OUTPUT_FORMATS' => 'sarif,json'
                          )
                          .merge(wheelhouse_input(env))
                          .merge(env)
                          .reject { |_, value| value.nil? }

    stdout_str, stderr_str, status = Open3.capture3(clean_env, "ruby #{MAIN_RB}")
    outputs = {}
    File.readlines(env_file, chomp: true).reject(&:empty?).each do |line|
      key, value = line.split('=', 2)
      outputs[key] = value
    end

    yield({
      stdout: stdout_str,
      stderr: stderr_str,
      success: status.success?,
      outputs: outputs,
      output_dir: File.join(output_dir, 'mobsfscan_output')
    })
  end
end

# Installing mobsfscan from pypi.org costs minutes per example.
# MOBSFSCAN_WHEELHOUSE points the install at a local wheel directory instead,
# which also exercises the air gapped path. Examples that cover the install
# itself opt out.
def wheelhouse_input(env)
  wheelhouse = ENV['MOBSFSCAN_WHEELHOUSE']
  return {} if wheelhouse.nil? || wheelhouse.empty?
  return {} if %w[AC_MOBSFSCAN_VERSION AC_MOBSFSCAN_PIP_INDEX_URL
                  AC_MOBSFSCAN_PIP_FIND_LINKS].any? { |key| env.key?(key) }

  return { 'AC_MOBSFSCAN_PIP_FIND_LINKS' => wheelhouse }
end

def read_json_report(result, filename)
  return JSON.parse(File.read(File.join(result[:output_dir], filename)))
end

def e2e_enabled?
  return ENV['MOBSFSCAN_E2E'] == '1'
end

# ─── Tests ────────────────────────────────────────────────────────────────────

# ─── 1. env_has_key & env_default ─────────────────────────────────────────────
RSpec.describe '#env_has_key' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path – key present and non-empty' do
    it 'returns the value' do
      ENV['AC_MOBSFSCAN_VERSION'] = '1.0.0'
      expect(env_has_key('AC_MOBSFSCAN_VERSION')).to eq('1.0.0')
    end
  end

  context 'negative path – missing key' do
    it 'raises SystemExit naming the key' do
      message = capture_abort { env_has_key('AC_MOBSFSCAN_VERSION') }
      expect(message).to include('AC_MOBSFSCAN_VERSION')
    end
  end

  context 'negative path – empty string value' do
    it 'raises SystemExit' do
      ENV['AC_MOBSFSCAN_VERSION'] = ''
      expect { env_has_key('AC_MOBSFSCAN_VERSION') }.to raise_error(SystemExit)
    end
  end
end

RSpec.describe '#env_default' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'returns the value when the key is set' do
      ENV['AC_MOBSFSCAN_SCAN_TYPE'] = 'android'
      expect(env_default('AC_MOBSFSCAN_SCAN_TYPE', 'auto')).to eq('android')
    end

    it 'strips surrounding whitespace' do
      ENV['AC_MOBSFSCAN_SCAN_TYPE'] = '  ios  '
      expect(env_default('AC_MOBSFSCAN_SCAN_TYPE', 'auto')).to eq('ios')
    end
  end

  context 'negative path – unset or empty' do
    it 'returns the default when the key is unset' do
      expect(env_default('AC_MOBSFSCAN_SCAN_TYPE', 'auto')).to eq('auto')
    end

    it 'returns the default when the value is an empty string' do
      ENV['AC_MOBSFSCAN_SCAN_TYPE'] = ''
      expect(env_default('AC_MOBSFSCAN_SCAN_TYPE', 'auto')).to eq('auto')
    end

    it 'returns a nil default for an optional input' do
      expect(env_default('AC_MOBSFSCAN_CONFIG_PATH', nil)).to be_nil
    end
  end
end

RSpec.describe '#get_step_temp' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path – running as a marketplace component' do
    it 'uses AC_STEP_TEMP as is' do
      ENV['AC_STEP_TEMP'] = '/tmp/step-temp'
      expect(get_step_temp).to eq('/tmp/step-temp')
    end
  end

  # A Custom Script does not get AC_STEP_TEMP, only the documented AC_TEMP_DIR.
  context 'positive path – running as a Custom Script' do
    it 'falls back to its own folder under AC_TEMP_DIR' do
      ENV['AC_TEMP_DIR'] = '/tmp/build-temp'
      expect(get_step_temp).to eq('/tmp/build-temp/appcircle_mobsfscan')
    end

    it 'prefers AC_STEP_TEMP when both are set' do
      ENV['AC_STEP_TEMP'] = '/tmp/step-temp'
      ENV['AC_TEMP_DIR'] = '/tmp/build-temp'
      expect(get_step_temp).to eq('/tmp/step-temp')
    end
  end

  context 'negative path – neither variable set' do
    it 'aborts naming both variables' do
      message = capture_abort { get_step_temp }
      expect(message).to include('AC_STEP_TEMP')
      expect(message).to include('AC_TEMP_DIR')
    end
  end
end

# ─── 2. abort_script ──────────────────────────────────────────────────────────
RSpec.describe '#abort_script' do
  context 'positive path' do
    it 'raises SystemExit' do
      expect { capture_abort { abort_script('fatal error') } }.not_to raise_error
      expect(capture_abort { abort_script('fatal error') }).not_to be_nil
    end

    it 'prefixes the message with the Appcircle error marker' do
      message = capture_abort { abort_script('fatal error') }
      expect(message).to include('@@[error] fatal error')
    end
  end

  context 'negative path – non-string argument' do
    it 'still raises SystemExit when given an exception object' do
      expect { abort_script(RuntimeError.new('err')) }.to raise_error(SystemExit)
    end
  end
end

# ─── 3. mask_secrets ──────────────────────────────────────────────────────────
RSpec.describe '#mask_secrets' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path – no index URL configured' do
    it 'returns the text unchanged' do
      expect(mask_secrets('pip install mobsfscan==1.0.0')).to eq('pip install mobsfscan==1.0.0')
    end
  end

  context 'positive path – index URL configured' do
    it 'replaces the credentialed URL with a placeholder' do
      $pip_index_url = 'https://user:token@pypi.internal/simple'
      masked = mask_secrets("pip install --index-url #{$pip_index_url} mobsfscan==1.0.0")
      expect(masked).not_to include('token')
      expect(masked).to include('***')
    end
  end
end

# ─── 4. run_command ───────────────────────────────────────────────────────────
RSpec.describe '#run_command' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path – command succeeds' do
    it 'returns stdout and a zero exit code' do
      stdout_str = nil
      exit_code = nil
      capture_stdout do
        stdout_str, _stderr_str, exit_code = run_command(%w[sh -c echo\ hello], true)
      end
      expect(stdout_str.strip).to eq('hello')
      expect(exit_code).to eq(0)
    end

    it 'logs the command with the Appcircle command marker' do
      log = capture_stdout { run_command(%w[sh -c true], true) }
      expect(log).to include('@@[command]')
    end
  end

  context 'negative path – command fails' do
    it 'returns the exit code and stderr when skip_abort is true' do
      stderr_str = nil
      exit_code = nil
      capture_stdout do
        _stdout_str, stderr_str, exit_code = run_command(['sh', '-c', 'echo boom >&2; exit 3'], true)
      end
      expect(exit_code).to eq(3)
      expect(stderr_str).to include('boom')
    end

    it 'raises SystemExit when skip_abort is false' do
      message = nil
      capture_stdout { message = capture_abort { run_command(%w[false], false) } }
      expect(message).not_to be_nil
    end
  end

  context 'negative path – executable missing' do
    it 'aborts with a readable message' do
      message = nil
      capture_stdout { message = capture_abort { run_command(%w[definitely-not-on-this-runner], true) } }
      expect(message).to include('was not found on this runner')
    end
  end

  context 'negative path – timeout exceeded' do
    it 'terminates the command so a stuck scan cannot hang the build' do
      message = nil
      capture_stdout { message = capture_abort { run_command(%w[sleep 30], true, 1) } }
      expect(message).to include('exceeded the 1 second timeout')
    end
  end
end

# ─── 5. get_source_path ───────────────────────────────────────────────────────
RSpec.describe '#get_source_path' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'defaults to the repository directory' do
      Dir.mktmpdir do |repo|
        $repository_path = repo
        expect(get_source_path).to eq(File.expand_path(repo))
      end
    end

    it 'resolves a relative path against the repository directory' do
      Dir.mktmpdir do |repo|
        FileUtils.mkdir_p(File.join(repo, 'android/app'))
        $repository_path = repo
        ENV['AC_MOBSFSCAN_SOURCE_PATH'] = 'android/app'
        expect(get_source_path).to eq(File.expand_path(File.join(repo, 'android/app')))
      end
    end

    it 'uses an absolute path as is' do
      Dir.mktmpdir do |repo|
        Dir.mktmpdir do |other|
          $repository_path = repo
          ENV['AC_MOBSFSCAN_SOURCE_PATH'] = other
          expect(get_source_path).to eq(File.expand_path(other))
        end
      end
    end
  end

  context 'negative path – path does not exist' do
    it 'aborts with a readable message' do
      Dir.mktmpdir do |repo|
        $repository_path = repo
        ENV['AC_MOBSFSCAN_SOURCE_PATH'] = 'does/not/exist'
        expect(capture_abort { get_source_path }).to include('does not exist')
      end
    end
  end
end

# ─── 6. get_scan_type ─────────────────────────────────────────────────────────
RSpec.describe '#get_scan_type' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'defaults to auto' do
      expect(get_scan_type).to eq('auto')
    end

    it 'downcases an explicit override' do
      ENV['AC_MOBSFSCAN_SCAN_TYPE'] = 'iOS'
      expect(get_scan_type).to eq('ios')
    end
  end

  context 'negative path – unsupported value' do
    it 'aborts and names the supported values' do
      ENV['AC_MOBSFSCAN_SCAN_TYPE'] = 'windows'
      message = capture_abort { get_scan_type }
      expect(message).to include('windows')
      expect(message).to include('android')
    end
  end
end

# ─── 7. get_severity_threshold ────────────────────────────────────────────────
RSpec.describe '#get_severity_threshold' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'defaults to error, matching the tool default' do
      expect(get_severity_threshold).to eq('error')
    end

    it 'accepts none for report only mode' do
      ENV['AC_MOBSFSCAN_SEVERITY_THRESHOLD'] = 'NONE'
      expect(get_severity_threshold).to eq('none')
    end
  end

  context 'negative path – unsupported value' do
    it 'aborts and names the supported values' do
      ENV['AC_MOBSFSCAN_SEVERITY_THRESHOLD'] = 'critical'
      expect(capture_abort { get_severity_threshold }).to include('warning')
    end
  end
end

# ─── 8. get_output_formats ────────────────────────────────────────────────────
RSpec.describe '#get_output_formats' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'defaults to sarif, matching the step form default' do
      expect(get_output_formats).to eq(%w[sarif])
    end

    # The step form offers one format, but the variable still takes a list.
    it 'still accepts a comma separated list' do
      ENV['AC_MOBSFSCAN_OUTPUT_FORMATS'] = 'sarif,json,html'
      expect(get_output_formats).to eq(%w[sarif json html])
    end

    it 'normalizes whitespace and removes duplicates' do
      ENV['AC_MOBSFSCAN_OUTPUT_FORMATS'] = ' JSON , sarif ,json'
      expect(get_output_formats).to eq(%w[json sarif])
    end
  end

  context 'negative path – unsupported format' do
    it 'aborts and names both the bad value and the supported ones' do
      ENV['AC_MOBSFSCAN_OUTPUT_FORMATS'] = 'json,pdf'
      message = capture_abort { get_output_formats }
      expect(message).to include('pdf')
      expect(message).to include('gitlab-sast')
    end
  end

  context 'negative path – nothing requested' do
    it 'aborts when the value holds only separators' do
      ENV['AC_MOBSFSCAN_OUTPUT_FORMATS'] = ' , '
      expect(capture_abort { get_output_formats }).to include('At least one output format')
    end
  end
end

# ─── 9. get_scan_timeout ──────────────────────────────────────────────────────
RSpec.describe '#get_scan_timeout' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'defaults to 900 seconds' do
      expect(get_scan_timeout).to eq(900)
    end

    it 'accepts an explicit value' do
      ENV['AC_MOBSFSCAN_TIMEOUT'] = '60'
      expect(get_scan_timeout).to eq(60)
    end
  end

  context 'negative path – not a positive number' do
    it 'aborts on zero' do
      ENV['AC_MOBSFSCAN_TIMEOUT'] = '0'
      expect { get_scan_timeout }.to raise_error(SystemExit)
    end

    it 'aborts on a non-numeric value' do
      ENV['AC_MOBSFSCAN_TIMEOUT'] = 'soon'
      expect { get_scan_timeout }.to raise_error(SystemExit)
    end
  end
end

# ─── 10. get_config_path ──────────────────────────────────────────────────────
RSpec.describe '#get_config_path' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path – no input given' do
    it 'returns nil so mobsfscan discovers .mobsf at the scan root itself' do
      expect(get_config_path('/tmp')).to be_nil
    end
  end

  context 'positive path – relative input' do
    it 'resolves against the source path' do
      Dir.mktmpdir do |source|
        config = File.join(source, '.mobsf')
        File.write(config, "ignore-rules:\n  - hardcoded_secret\n")
        ENV['AC_MOBSFSCAN_CONFIG_PATH'] = '.mobsf'
        expect(get_config_path(source)).to eq(config)
      end
    end
  end

  context 'negative path – file missing' do
    it 'aborts with a readable message' do
      Dir.mktmpdir do |source|
        ENV['AC_MOBSFSCAN_CONFIG_PATH'] = '.mobsf'
        expect(capture_abort { get_config_path(source) }).to include('does not exist')
      end
    end
  end
end

# ─── 11. get_extra_parameters ─────────────────────────────────────────────────
RSpec.describe '#get_extra_parameters' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'returns an empty array when nothing is set' do
      expect(get_extra_parameters).to eq([])
    end

    it 'splits the value with shell word rules' do
      ENV['AC_MOBSFSCAN_EXTRA_PARAMETERS'] = '-mp thread'
      expect(get_extra_parameters).to eq(%w[-mp thread])
    end

    it 'keeps a quoted argument as one token' do
      ENV['AC_MOBSFSCAN_EXTRA_PARAMETERS'] = '--config "my config"'
      expect(get_extra_parameters).to eq(['--config', 'my config'])
    end
  end

  context 'negative path – unbalanced quotes' do
    it 'aborts with a readable message' do
      ENV['AC_MOBSFSCAN_EXTRA_PARAMETERS'] = 'a "b'
      expect(capture_abort { get_extra_parameters }).to include('could not be parsed')
    end
  end
end

# ─── 12. get_scan_command ─────────────────────────────────────────────────────
RSpec.describe '#get_scan_command' do
  before do
    reset_inputs
    $venv_path = '/venv'
    $source_path = '/src/app'
    $scan_type = 'android'
    $config_path = nil
    $extra_parameters = []
  end
  after { reset_inputs }

  context 'positive path' do
    it 'uses the virtualenv entry point and the format flag' do
      command = get_scan_command('sarif', '/out/mobsfscan.sarif')
      expect(command[0]).to eq('/venv/bin/mobsfscan')
      expect(command).to include('--sarif')
    end

    it 'passes the type and the output file' do
      command = get_scan_command('json', '/out/mobsfscan.json')
      expect(command[command.index('--type'), 2]).to eq(%w[--type android])
      expect(command[command.index('-o'), 2]).to eq(['-o', '/out/mobsfscan.json'])
    end

    # The step decides the outcome from the report, so the tool must never fail.
    it 'always passes --no-fail' do
      expect(get_scan_command('json', '/out/r.json')).to include('--no-fail')
    end

    it 'keeps the scan path last' do
      expect(get_scan_command('json', '/out/r.json').last).to eq('/src/app')
    end

    it 'omits -c when no config file is resolved' do
      expect(get_scan_command('json', '/out/r.json')).not_to include('-c')
    end

    it 'passes -c when a config file is resolved' do
      $config_path = '/src/.mobsf'
      command = get_scan_command('json', '/out/r.json')
      expect(command[command.index('-c'), 2]).to eq(['-c', '/src/.mobsf'])
    end

    it 'keeps a path with spaces as a single argument' do
      $source_path = '/src/My App'
      expect(get_scan_command('json', '/out/r.json').last).to eq('/src/My App')
    end
  end

  context 'positive path – extra parameters are inert tokens' do
    it 'passes shell metacharacters through as plain arguments' do
      $extra_parameters = ['-mp', 'thread', '&&', 'rm', '-rf', '/']
      command = get_scan_command('json', '/out/r.json')
      expect(command).to include('&&')
      expect(command.shelljoin).not_to include(' && ')
    end
  end
end

# ─── 13. get_pip_install_command ──────────────────────────────────────────────
RSpec.describe '#get_pip_install_command' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path – default index' do
    it 'pins the requested version' do
      command = get_pip_install_command('/venv', '1.0.0')
      expect(command[0]).to eq('/venv/bin/pip')
      expect(command).to include('mobsfscan==1.0.0')
      expect(command).not_to include('--no-index')
    end
  end

  context 'positive path – air gapped install' do
    it 'passes --no-index with the wheel directory' do
      $pip_find_links = '/wheels'
      command = get_pip_install_command('/venv', '1.0.0')
      expect(command).to include('--no-index')
      expect(command[command.index('--find-links'), 2]).to eq(['--find-links', '/wheels'])
    end
  end

  context 'positive path – internal index' do
    it 'passes the index URL' do
      $pip_index_url = 'https://pypi.internal/simple'
      command = get_pip_install_command('/venv', '1.0.0')
      expect(command[command.index('--index-url'), 2]).to eq(['--index-url', 'https://pypi.internal/simple'])
    end
  end
end

# ─── 14. venv_environment ─────────────────────────────────────────────────────
RSpec.describe '#venv_environment' do
  # mobsfscan shells out to semgrep, so the venv bin directory has to be on PATH.
  context 'positive path' do
    it 'prepends the virtualenv bin directory to PATH' do
      expect(venv_environment('/venv')['PATH']).to start_with("/venv/bin#{File::PATH_SEPARATOR}")
    end

    it 'marks the virtualenv as active' do
      expect(venv_environment('/venv')['VIRTUAL_ENV']).to eq('/venv')
    end

    it 'clears the inherited Python paths so the system packages cannot leak in' do
      environment = venv_environment('/venv')
      expect(environment['PYTHONPATH']).to be_nil
      expect(environment['PYTHONHOME']).to be_nil
    end
  end
end

# ─── 15. get_install_failure_message ──────────────────────────────────────────
RSpec.describe '#get_install_failure_message' do
  context 'positive path – network failure' do
    it 'names the offline options instead of surfacing a pip error' do
      message = get_install_failure_message('1.0.0', 'Could not fetch URL: Temporary failure in name resolution')
      expect(message).to include('no usable outbound network access')
      expect(message).to include('find-links')
    end
  end

  context 'positive path – incompatible interpreter' do
    it 'names the Python incompatibility' do
      message = get_install_failure_message('1.0.0', 'Requires-Python >=3.10')
      expect(message).to include('not compatible with the python3 version')
    end
  end

  context 'positive path – bad pin' do
    it 'names the version that was not found' do
      message = get_install_failure_message('9.9.9', 'ERROR: No matching distribution found for mobsfscan==9.9.9')
      expect(message).to include('9.9.9 was not found')
    end
  end

  context 'negative path – unrecognized output' do
    it 'falls back to a generic install failure' do
      expect(get_install_failure_message('1.0.0', 'something odd')).to include('Installing mobsfscan 1.0.0 failed')
    end
  end
end

# ─── 16. parse_report ─────────────────────────────────────────────────────────
RSpec.describe '#parse_report' do
  context 'positive path' do
    it 'returns the parsed report' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'mobsfscan.json')
        File.write(path, JSON.dump(build_report({})))
        expect(parse_report(path)['mobsfscan_version']).to eq('1.0.0')
      end
    end
  end

  # A missing or broken report means the tool failed, it is not a clean result.
  context 'negative path – report missing' do
    it 'aborts with a distinct message' do
      expect(capture_abort { parse_report('/nope/mobsfscan.json') }).to include('did not produce a report')
    end
  end

  context 'negative path – report unparseable' do
    it 'aborts with a distinct message' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'mobsfscan.json')
        File.write(path, 'Traceback (most recent call last):')
        expect(capture_abort { parse_report(path) }).to include('could not be parsed')
      end
    end
  end
end

# ─── 17. check_scan_errors ────────────────────────────────────────────────────
RSpec.describe '#check_scan_errors' do
  context 'positive path – no errors' do
    it 'returns without printing anything' do
      expect(capture_stdout { check_scan_errors(build_report({})) }).to eq('')
    end
  end

  context 'positive path – recoverable error' do
    it 'logs a warning and continues' do
      log = capture_stdout { check_scan_errors(build_report({}, ['Failed to parse AndroidManifest.xml'])) }
      expect(log).to include('@@[warning]')
    end
  end

  # A silently semgrep-less install reports only best practice rules, which
  # would otherwise look like a clean project.
  context 'negative path – semgrep missing' do
    it 'aborts instead of reporting a clean scan' do
      message = nil
      capture_stdout do
        message = capture_abort do
          check_scan_errors(build_report({}, ['semgrep not found. Install with: pip install semgrep']))
        end
      end
      expect(message).to include('semgrep is missing')
    end
  end
end

# ─── 18. summarize_report ─────────────────────────────────────────────────────
RSpec.describe '#summarize_report' do
  context 'positive path – file level matches' do
    it 'counts every match, not just the rule' do
      summary = summarize_report(build_report('hardcoded_secret' => build_rule('WARNING', 2),
                                              'weak_cipher' => build_rule('ERROR', 1)))
      expect(summary[:findings]['WARNING']).to eq(2)
      expect(summary[:findings]['ERROR']).to eq(1)
      expect(summary[:total]).to eq(3)
      expect(summary[:highest]).to eq('ERROR')
    end
  end

  # Best practice rules carry no file location and must stay distinguishable.
  context 'positive path – rules without a file location' do
    it 'counts them as missing best practices' do
      summary = summarize_report(build_report('android_certificate_pinning' => build_rule('INFO', 0),
                                              'hardcoded_secret' => build_rule('WARNING', 1)))
      expect(summary[:best_practices]['INFO']).to eq(1)
      expect(summary[:findings]['INFO']).to eq(0)
      expect(summary[:totals]['INFO']).to eq(1)
      expect(summary[:highest]).to eq('WARNING')
    end
  end

  context 'positive path – empty report' do
    it 'reports no findings and no highest severity' do
      summary = summarize_report(build_report({}))
      expect(summary[:total]).to eq(0)
      expect(summary[:highest]).to be_nil
    end
  end

  context 'negative path – unknown severity' do
    it 'treats it as INFO rather than dropping the finding' do
      summary = summarize_report(build_report('odd_rule' => build_rule('CRITICAL', 1)))
      expect(summary[:findings]['INFO']).to eq(1)
    end
  end
end

# ─── 19. is_threshold_exceeded ────────────────────────────────────────────────
RSpec.describe '#is_threshold_exceeded' do
  let(:warnings_only) do
    summarize_report(build_report('hardcoded_secret' => build_rule('WARNING', 3),
                                  'android_certificate_pinning' => build_rule('INFO', 0)))
  end
  let(:with_error) { summarize_report(build_report('weak_cipher' => build_rule('ERROR', 1))) }
  let(:clean) { summarize_report(build_report({})) }

  context 'positive path – threshold not reached' do
    it 'passes warnings when the threshold is error' do
      expect(is_threshold_exceeded(warnings_only, 'error')).to be false
    end

    it 'passes everything when the threshold is none' do
      expect(is_threshold_exceeded(with_error, 'none')).to be false
    end

    it 'passes a clean report at every threshold' do
      SEVERITY_THRESHOLDS.each do |threshold|
        expect(is_threshold_exceeded(clean, threshold)).to be false
      end
    end
  end

  context 'negative path – threshold reached' do
    it 'fails on an error finding at the error threshold' do
      expect(is_threshold_exceeded(with_error, 'error')).to be true
    end

    it 'fails on a warning finding at the warning threshold' do
      expect(is_threshold_exceeded(warnings_only, 'warning')).to be true
    end

    it 'fails on a best practice finding at the info threshold' do
      expect(is_threshold_exceeded(warnings_only, 'info')).to be true
    end
  end
end

# ─── 20. get_step_outputs ─────────────────────────────────────────────────────
RSpec.describe '#get_step_outputs' do
  let(:summary) { summarize_report(build_report('weak_cipher' => build_rule('ERROR', 1))) }

  context 'positive path' do
    it 'exports the counts and the highest severity' do
      outputs = get_step_outputs(summary, '/reports', %w[sarif json])
      expect(outputs['AC_MOBSFSCAN_FINDING_COUNT']).to eq(1)
      expect(outputs['AC_MOBSFSCAN_ERROR_COUNT']).to eq(1)
      expect(outputs['AC_MOBSFSCAN_HIGHEST_SEVERITY']).to eq('ERROR')
    end

    it 'exports the report paths for the requested formats' do
      outputs = get_step_outputs(summary, '/reports', %w[sarif json])
      expect(outputs['AC_MOBSFSCAN_SARIF_REPORT_PATH']).to eq('/reports/mobsfscan.sarif')
      expect(outputs['AC_MOBSFSCAN_JSON_REPORT_PATH']).to eq('/reports/mobsfscan.json')
    end

    it 'omits the path of a format that was not requested' do
      outputs = get_step_outputs(summary, '/reports', %w[sarif])
      expect(outputs).not_to have_key('AC_MOBSFSCAN_JSON_REPORT_PATH')
    end

    it 'reports NONE as the highest severity for a clean scan' do
      outputs = get_step_outputs(summarize_report(build_report({})), '/reports', %w[json])
      expect(outputs['AC_MOBSFSCAN_HIGHEST_SEVERITY']).to eq('NONE')
    end
  end
end

# ─── 21. End to end ───────────────────────────────────────────────────────────
# Runs main.rb the way the runner does, against the deliberately insecure
# samples. Needs python3 and a reachable Python package index.
RSpec.describe 'main.rb end to end' do
  before { skip 'set MOBSFSCAN_E2E=1 to run the end to end tests' unless e2e_enabled? }

  context 'positive path – Android source' do
    it 'reports findings with file, line, rule id, severity and CWE/MASVS references' do
      run_main('android') do |result|
        expect(result[:success]).to be(true), "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
        expect(result[:stdout]).not_to include('semgrep not found')

        report = read_json_report(result, 'mobsfscan.json')
        expect(report['errors']).to be_empty

        matched = report['results'].reject { |_id, detail| (detail['files'] || []).empty? }
        expect(matched).not_to be_empty

        detail = matched.values.first
        finding = detail['files'].first
        expect(finding['file_path']).not_to be_nil
        expect(finding['match_lines'].first).to be > 0
        expect(detail['metadata']['severity']).not_to be_nil
        expect(detail['metadata']['cwe']).not_to be_nil
        expect(detail['metadata']['masvs']).not_to be_nil
      end
    end
  end

  context 'positive path – iOS source' do
    it 'reports findings from the Swift sample' do
      run_main('ios') do |result|
        expect(result[:success]).to be(true), "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
        matched = read_json_report(result, 'mobsfscan.json')['results']
                  .reject { |_id, detail| (detail['files'] || []).empty? }
        expect(matched).not_to be_empty
        expect(matched.keys.any? { |id| id.start_with?('ios_') }).to be true
      end
    end
  end

  context 'positive path – report publishing' do
    it 'publishes the SARIF and JSON reports as artifacts and exports their paths' do
      run_main('android') do |result|
        expect(result[:success]).to be true
        expect(File.file?(File.join(result[:output_dir], 'mobsfscan.json'))).to be true
        expect(File.file?(File.join(result[:output_dir], 'mobsfscan.sarif'))).to be true

        sarif = read_json_report(result, 'mobsfscan.sarif')
        expect(sarif['version']).to eq('2.1.0')
        expect(sarif['runs'].first['results']).not_to be_empty

        expect(result[:outputs]['AC_MOBSFSCAN_JSON_REPORT_PATH'])
          .to eq(File.join(result[:output_dir], 'mobsfscan.json'))
        expect(result[:outputs]['AC_MOBSFSCAN_SARIF_REPORT_PATH'])
          .to eq(File.join(result[:output_dir], 'mobsfscan.sarif'))
        expect(result[:outputs]['AC_MOBSFSCAN_FINDING_COUNT'].to_i).to be > 0
        expect(%w[ERROR WARNING INFO]).to include(result[:outputs]['AC_MOBSFSCAN_HIGHEST_SEVERITY'])
      end
    end

    # JSON is always generated for the gate, but it is not an artifact unless asked for.
    it 'does not publish the JSON report when only SARIF is requested' do
      run_main('android', 'AC_MOBSFSCAN_OUTPUT_FORMATS' => 'sarif') do |result|
        expect(result[:success]).to be true
        expect(File.file?(File.join(result[:output_dir], 'mobsfscan.sarif'))).to be true
        expect(File.exist?(File.join(result[:output_dir], 'mobsfscan.json'))).to be false
      end
    end

    # The step form offers a single format, and the default matches it.
    it 'publishes only SARIF by default' do
      run_main('android', 'AC_MOBSFSCAN_OUTPUT_FORMATS' => nil) do |result|
        expect(result[:success]).to be true
        expect(File.file?(File.join(result[:output_dir], 'mobsfscan.sarif'))).to be true
        expect(File.exist?(File.join(result[:output_dir], 'mobsfscan.json'))).to be false
      end
    end
  end

  # This is the path a Custom Script takes, where AC_STEP_TEMP is not provided.
  context 'positive path – AC_TEMP_DIR fallback' do
    it 'completes a scan with only AC_TEMP_DIR set' do
      run_main('android', 'AC_STEP_TEMP' => nil) do |result|
        expect(result[:success]).to be(true), "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
        expect(File.file?(File.join(result[:output_dir], 'mobsfscan.json'))).to be true
      end
    end
  end

  context 'positive path – scan type override' do
    it 'honors an explicit ios override on Android source' do
      run_main('android', 'AC_MOBSFSCAN_SCAN_TYPE' => 'ios') do |result|
        expect(result[:success]).to be true
        expect(read_json_report(result, 'mobsfscan.json')['results']).to be_empty
      end
    end
  end

  context 'positive path – clean project' do
    it 'passes and still produces a report' do
      run_main('clean') do |result|
        expect(result[:success]).to be(true), "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
        expect(File.file?(File.join(result[:output_dir], 'mobsfscan.json'))).to be true
        matched = read_json_report(result, 'mobsfscan.json')['results']
                  .reject { |_id, detail| (detail['files'] || []).empty? }
        expect(matched).to be_empty
        expect(result[:outputs]['AC_MOBSFSCAN_ERROR_COUNT']).to eq('0')
      end
    end
  end

  context 'positive path – suppression' do
    it 'drops a single finding suppressed with an inline mobsf-ignore comment' do
      run_main('android') do |result|
        expect(result[:success]).to be(true), "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
        reported = read_json_report(result, 'mobsfscan.json')['results'].values
                   .flat_map { |detail| detail['files'] || [] }
                   .map { |match| File.basename(match['file_path']) }
        expect(reported).not_to include('SuppressedCode.java')
      end
    end

    it 'drops the rules listed in a .mobsf config' do
      Dir.mktmpdir do |repo|
        FileUtils.cp_r(File.join(SAMPLE_PROJECTS, 'android'), repo)
        File.write(File.join(repo, 'android', '.mobsf'),
                   "ignore-rules:\n  - hardcoded_api_key\n  - hardcoded_password\n  - hardcoded_secret\n")
        run_main('android', 'AC_REPOSITORY_DIR' => repo) do |result|
          expect(result[:success]).to be true
          rules = read_json_report(result, 'mobsfscan.json')['results'].keys
          expect(rules).not_to include('hardcoded_api_key')
          expect(rules).not_to include('hardcoded_password')
        end
      end
    end
  end

  context 'negative path – severity threshold' do
    # The insecure Android sample carries an ERROR finding.
    it 'fails the build at the default error threshold' do
      run_main('android', 'AC_MOBSFSCAN_SEVERITY_THRESHOLD' => nil) do |result|
        expect(result[:success]).to be false
        expect(result[:stdout] + result[:stderr]).to include('at or above the `error` severity threshold')
        expect(result[:outputs]['AC_MOBSFSCAN_HIGHEST_SEVERITY']).to eq('ERROR')
      end
    end

    it 'fails at the warning threshold and still publishes the report' do
      run_main('android', 'AC_MOBSFSCAN_SEVERITY_THRESHOLD' => 'warning') do |result|
        expect(result[:success]).to be false
        expect(result[:stdout] + result[:stderr]).to include('severity threshold')
        expect(File.file?(File.join(result[:output_dir], 'mobsfscan.json'))).to be true
      end
    end

    it 'reports without failing when the threshold is none' do
      run_main('android', 'AC_MOBSFSCAN_SEVERITY_THRESHOLD' => 'none') do |result|
        expect(result[:success]).to be true
        expect(result[:outputs]['AC_MOBSFSCAN_FINDING_COUNT'].to_i).to be > 0
      end
    end
  end

  context 'positive path – pinned version' do
    it 'installs exactly the pinned version' do
      run_main('clean', 'AC_MOBSFSCAN_VERSION' => '0.4.5') do |result|
        expect(result[:success]).to be(true), "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
        expect(result[:stdout]).to match(/mobsfscan 0\.4\.5 is ready/)
        expect(result[:stdout]).not_to match(/@@\[warning\] Requested mobsfscan/)
      end
    end
  end

  context 'negative path – install failures' do
    it 'reports a bad pin with an actionable message' do
      run_main('clean', 'AC_MOBSFSCAN_VERSION' => '99.99.99') do |result|
        expect(result[:success]).to be false
        expect(result[:stdout] + result[:stderr])
          .to match(/was not found on the configured package index|no usable outbound network access/)
      end
    end

    it 'reports an unreachable index with an actionable message' do
      run_main('clean', 'AC_MOBSFSCAN_PIP_INDEX_URL' => 'https://pypi.invalid-host.example/simple') do |result|
        expect(result[:success]).to be false
        expect(result[:stdout] + result[:stderr])
          .to match(/no usable outbound network access|was not found on the configured package index/)
      end
    end
  end

  context 'negative path – bad input' do
    it 'fails on a missing source path before installing anything' do
      run_main('does-not-exist') do |result|
        expect(result[:success]).to be false
        expect(result[:stdout] + result[:stderr]).to include('does not exist')
        expect(result[:stdout]).not_to include('Installing mobsfscan')
      end
    end
  end
end

# ─── Runner ───────────────────────────────────────────────────────────────────
if __FILE__ == $PROGRAM_NAME
  RSpec.configure do |config|
    config.add_formatter ReadableFormatter
    config.color  = true
    config.order  = :defined
  end

  exit RSpec::Core::Runner.run(['--order', 'defined'])
end
