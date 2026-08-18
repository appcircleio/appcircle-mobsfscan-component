# frozen_string_literal: true

# Tests for the Appcircle mobsfscan component.
#
#   ruby tests/test_main.rb                  # unit tests only
#   MOBSFSCAN_E2E=1 ruby tests/test_main.rb  # also run the end to end tests
#
# The end to end tests run main.rb as a subprocess, so they need python3 and
# access to a Python package index.

require 'minitest/autorun'
require 'fileutils'
require 'json'
require 'open3'
require 'tmpdir'

MAIN_RB = File.expand_path('../main.rb', __dir__)
SAMPLE_PROJECTS = File.expand_path('sample_projects', __dir__)

require_relative '../main'

module EnvHelper
  # main.rb reads its inputs straight from ENV, so tests set and restore them.
  def with_env(values)
    original = values.keys.to_h { |key| [key, ENV[key]] }
    values.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
    yield
  ensure
    original.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
  end

  def cleared_inputs
    ENV.keys.grep(/\AAC_MOBSFSCAN_/).to_h { |key| [key, nil] }
       .merge('AC_REPOSITORY_DIR' => nil, 'AC_OUTPUT_DIR' => nil,
              'AC_STEP_TEMP' => nil, 'AC_ENV_FILE_PATH' => nil)
  end
end

class InputResolutionTest < Minitest::Test
  include EnvHelper

  def test_source_path_defaults_to_the_repository_dir
    Dir.mktmpdir do |repo|
      with_env(cleared_inputs.merge('AC_REPOSITORY_DIR' => repo)) do
        assert_equal File.expand_path(repo), resolve_source_path
      end
    end
  end

  def test_relative_source_path_is_resolved_against_the_repository_dir
    Dir.mktmpdir do |repo|
      FileUtils.mkdir_p(File.join(repo, 'android/app'))
      with_env(cleared_inputs.merge('AC_REPOSITORY_DIR' => repo,
                                    'AC_MOBSFSCAN_SOURCE_PATH' => 'android/app')) do
        assert_equal File.expand_path(File.join(repo, 'android/app')), resolve_source_path
      end
    end
  end

  def test_absolute_source_path_is_used_as_is
    Dir.mktmpdir do |repo|
      Dir.mktmpdir do |other|
        with_env(cleared_inputs.merge('AC_REPOSITORY_DIR' => repo,
                                      'AC_MOBSFSCAN_SOURCE_PATH' => other)) do
          assert_equal File.expand_path(other), resolve_source_path
        end
      end
    end
  end

  def test_missing_source_path_fails_with_a_readable_message
    Dir.mktmpdir do |repo|
      with_env(cleared_inputs.merge('AC_REPOSITORY_DIR' => repo,
                                    'AC_MOBSFSCAN_SOURCE_PATH' => 'does/not/exist')) do
        error = assert_raises(StepError) { resolve_source_path }
        assert_match(/does not exist/, error.message)
      end
    end
  end

  def test_missing_repository_dir_fails
    with_env(cleared_inputs) do
      assert_raises(StepError) { resolve_source_path }
    end
  end

  def test_scan_type_defaults_to_auto_and_rejects_unknown_values
    with_env(cleared_inputs) { assert_equal 'auto', resolve_scan_type }
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_SCAN_TYPE' => 'iOS')) { assert_equal 'ios', resolve_scan_type }
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_SCAN_TYPE' => 'windows')) do
      assert_raises(StepError) { resolve_scan_type }
    end
  end

  def test_threshold_defaults_to_error_and_rejects_unknown_values
    with_env(cleared_inputs) { assert_equal 'error', resolve_threshold }
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_SEVERITY_THRESHOLD' => 'NONE')) { assert_equal 'none', resolve_threshold }
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_SEVERITY_THRESHOLD' => 'critical')) do
      assert_raises(StepError) { resolve_threshold }
    end
  end

  def test_formats_default_to_sarif_and_json
    with_env(cleared_inputs) { assert_equal %w[sarif json], resolve_formats }
  end

  def test_formats_are_normalized_and_deduplicated
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_OUTPUT_FORMATS' => ' JSON , sarif ,json')) do
      assert_equal %w[json sarif], resolve_formats
    end
  end

  def test_unknown_format_is_rejected_and_names_the_supported_values
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_OUTPUT_FORMATS' => 'json,pdf')) do
      error = assert_raises(StepError) { resolve_formats }
      assert_match(/pdf/, error.message)
      assert_match(/gitlab-sast/, error.message)
    end
  end

  def test_timeout_must_be_a_positive_number
    with_env(cleared_inputs) { assert_equal 900, resolve_timeout }
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_TIMEOUT' => '60')) { assert_equal 60, resolve_timeout }
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_TIMEOUT' => '0')) { assert_raises(StepError) { resolve_timeout } }
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_TIMEOUT' => 'soon')) { assert_raises(StepError) { resolve_timeout } }
  end

  def test_no_config_path_input_leaves_discovery_to_mobsfscan
    with_env(cleared_inputs) { assert_nil resolve_config_path('/tmp') }
  end

  def test_relative_config_path_is_resolved_against_the_source_path
    Dir.mktmpdir do |source|
      config = File.join(source, '.mobsf')
      File.write(config, "ignore-rules:\n  - hardcoded_secret\n")
      with_env(cleared_inputs.merge('AC_MOBSFSCAN_CONFIG_PATH' => '.mobsf')) do
        assert_equal config, resolve_config_path(source)
      end
    end
  end

  def test_missing_config_file_fails
    Dir.mktmpdir do |source|
      with_env(cleared_inputs.merge('AC_MOBSFSCAN_CONFIG_PATH' => '.mobsf')) do
        assert_raises(StepError) { resolve_config_path(source) }
      end
    end
  end

  def test_save_report_defaults_to_true
    with_env(cleared_inputs) { assert env_flag('AC_MOBSFSCAN_SAVE_REPORT', default: true) }
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_SAVE_REPORT' => 'false')) do
      refute env_flag('AC_MOBSFSCAN_SAVE_REPORT', default: true)
    end
  end
end

class CommandBuildingTest < Minitest::Test
  include EnvHelper

  def test_scan_argv_passes_no_fail_and_keeps_the_path_last
    with_env(cleared_inputs) do
      argv = scan_argv('/venv', 'sarif', '/out/mobsfscan.sarif', '/src/app', 'android', nil)
      assert_equal '/venv/bin/mobsfscan', argv.first
      assert_includes argv, '--sarif'
      assert_includes argv, '--no-fail'
      assert_equal %w[--type android], argv[argv.index('--type'), 2]
      assert_equal %w[-o /out/mobsfscan.sarif], argv[argv.index('-o'), 2]
      assert_equal '/src/app', argv.last
      refute_includes argv, '-c'
    end
  end

  def test_scan_argv_passes_the_config_file_when_one_is_resolved
    with_env(cleared_inputs) do
      argv = scan_argv('/venv', 'json', '/out/mobsfscan.json', '/src', 'auto', '/src/.mobsf')
      assert_equal %w[-c /src/.mobsf], argv[argv.index('-c'), 2]
    end
  end

  def test_paths_with_spaces_stay_a_single_argument
    with_env(cleared_inputs) do
      argv = scan_argv('/venv', 'json', '/out/r.json', '/src/My App', 'auto', nil)
      assert_equal '/src/My App', argv.last
    end
  end

  def test_extra_parameters_are_split_with_shell_word_rules
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_EXTRA_PARAMETERS' => '-mp thread')) do
      assert_equal %w[-mp thread], extra_parameters
    end
  end

  def test_quoted_extra_parameters_stay_one_argument
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_EXTRA_PARAMETERS' => '--config "my config"')) do
      assert_equal ['--config', 'my config'], extra_parameters
    end
  end

  def test_shell_metacharacters_in_extra_parameters_are_inert_tokens
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_EXTRA_PARAMETERS' => '-mp thread && rm -rf /')) do
      argv = scan_argv('/venv', 'json', '/out/r.json', '/src', 'auto', nil)
      assert_includes argv, '&&'
      refute_includes argv.shelljoin, ' && '
    end
  end

  def test_unbalanced_quotes_in_extra_parameters_fail_with_a_readable_message
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_EXTRA_PARAMETERS' => 'a "b')) do
      assert_raises(StepError) { extra_parameters }
    end
  end

  def test_pip_install_pins_the_version
    with_env(cleared_inputs) do
      argv = pip_install_argv('/venv', '1.0.0')
      assert_equal '/venv/bin/pip', argv.first
      assert_includes argv, 'mobsfscan==1.0.0'
      refute_includes argv, '--no-index'
    end
  end

  def test_pip_install_uses_no_index_for_an_offline_directory
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_PIP_FIND_LINKS' => '/wheels')) do
      argv = pip_install_argv('/venv', '1.0.0')
      assert_includes argv, '--no-index'
      assert_equal %w[--find-links /wheels], argv[argv.index('--find-links'), 2]
    end
  end

  def test_pip_install_uses_a_custom_index_url
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_PIP_INDEX_URL' => 'https://pypi.internal/simple')) do
      argv = pip_install_argv('/venv', '1.0.0')
      assert_equal %w[--index-url https://pypi.internal/simple], argv[argv.index('--index-url'), 2]
    end
  end

  def test_the_pip_index_url_is_masked_in_logs
    url = 'https://user:token@pypi.internal/simple'
    with_env(cleared_inputs.merge('AC_MOBSFSCAN_PIP_INDEX_URL' => url)) do
      masked = mask("pip install --index-url #{url} mobsfscan==1.0.0")
      refute_includes masked, 'token'
      assert_includes masked, '***'
    end
  end

  # mobsfscan shells out to semgrep, so the venv bin directory has to be on PATH.
  def test_the_venv_bin_directory_is_prepended_to_path
    env = venv_env('/venv')
    assert env['PATH'].start_with?("/venv/bin#{File::PATH_SEPARATOR}")
    assert_equal '/venv', env['VIRTUAL_ENV']
    assert_nil env['PYTHONPATH']
    assert_nil env['PYTHONHOME']
  end
end

class SummaryTest < Minitest::Test
  def report(results)
    { 'errors' => [], 'mobsfscan_version' => '1.0.0', 'results' => results }
  end

  def rule(severity, file_count)
    files = Array.new(file_count) do |index|
      { 'file_path' => "/src/File#{index}.java", 'match_lines' => [index + 1, index + 1] }
    end
    { 'files' => files, 'metadata' => { 'severity' => severity } }
  end

  def test_file_matches_are_counted_per_match
    summary = summarize(report('hardcoded_secret' => rule('WARNING', 2),
                               'weak_cipher' => rule('ERROR', 1)))
    assert_equal 2, summary[:findings]['WARNING']
    assert_equal 1, summary[:findings]['ERROR']
    assert_equal 3, summary[:total]
    assert_equal 'ERROR', summary[:highest]
  end

  # Best practice rules carry no file location and must stay distinguishable.
  def test_rules_without_files_are_counted_as_missing_best_practices
    summary = summarize(report('android_certificate_pinning' => rule('INFO', 0),
                               'hardcoded_secret' => rule('WARNING', 1)))
    assert_equal 1, summary[:best_practices]['INFO']
    assert_equal 0, summary[:findings]['INFO']
    assert_equal 1, summary[:totals]['INFO']
    assert_equal 'WARNING', summary[:highest]
  end

  def test_an_empty_report_has_no_findings_and_no_highest_severity
    summary = summarize(report({}))
    assert_equal 0, summary[:total]
    assert_nil summary[:highest]
  end

  def test_an_unknown_severity_is_treated_as_info
    summary = summarize(report('odd_rule' => rule('CRITICAL', 1)))
    assert_equal 1, summary[:findings]['INFO']
  end

  def test_the_error_threshold_ignores_warnings_and_info
    summary = summarize(report('hardcoded_secret' => rule('WARNING', 3),
                               'android_certificate_pinning' => rule('INFO', 0)))
    refute threshold_exceeded?(summary, 'error')
    assert threshold_exceeded?(summary, 'warning')
    assert threshold_exceeded?(summary, 'info')
  end

  def test_the_error_threshold_fails_on_an_error_finding
    summary = summarize(report('weak_cipher' => rule('ERROR', 1)))
    assert threshold_exceeded?(summary, 'error')
  end

  def test_the_none_threshold_never_fails
    summary = summarize(report('weak_cipher' => rule('ERROR', 5)))
    refute threshold_exceeded?(summary, 'none')
  end

  def test_a_clean_report_passes_every_threshold
    summary = summarize(report({}))
    THRESHOLDS.each { |threshold| refute threshold_exceeded?(summary, threshold) }
  end
end

class ReportParsingTest < Minitest::Test
  def test_a_missing_report_is_a_tool_failure_not_a_clean_result
    error = assert_raises(StepError) { parse_report('/nope/mobsfscan.json') }
    assert_match(/did not produce a report/, error.message)
  end

  def test_an_unparseable_report_is_a_tool_failure
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'mobsfscan.json')
      File.write(path, 'Traceback (most recent call last):')
      error = assert_raises(StepError) { parse_report(path) }
      assert_match(/could not be parsed/, error.message)
    end
  end

  # A silently semgrep-less install reports only best practice rules, which
  # would otherwise look like a clean project.
  def test_a_missing_semgrep_install_is_reported_as_a_failure
    error = assert_raises(StepError) do
      report_scan_errors('errors' => ['semgrep not found. Install with: pip install semgrep'])
    end
    assert_match(/semgrep is missing/, error.message)
  end

  def test_other_scan_errors_are_warnings_only
    report_scan_errors('errors' => ['Failed to parse AndroidManifest.xml'])
  end
end

class InstallFailureMessageTest < Minitest::Test
  def test_a_network_failure_is_actionable
    message = install_failure_message('1.0.0', 'Could not fetch URL: Temporary failure in name resolution')
    assert_match(/no usable outbound network access/, message)
    assert_match(/find-links/, message)
  end

  def test_an_incompatible_python_is_named
    message = install_failure_message('1.0.0', 'Requires-Python >=3.10')
    assert_match(/not compatible with the python3 version/, message)
  end

  def test_a_bad_pin_is_named
    message = install_failure_message('9.9.9', 'ERROR: No matching distribution found for mobsfscan==9.9.9')
    assert_match(/9\.9\.9 was not found/, message)
  end
end

class CommandRunnerTest < Minitest::Test
  def test_output_and_exit_status_are_returned
    stdout, _stderr, exit_status = run_command(['sh', '-c', 'echo hello'], echo: false)
    assert_equal 'hello', stdout.strip
    assert_equal 0, exit_status
  end

  def test_a_non_zero_exit_status_is_reported_not_raised
    _stdout, stderr, exit_status = run_command(['sh', '-c', 'echo boom >&2; exit 3'], echo: false)
    assert_equal 3, exit_status
    assert_match(/boom/, stderr)
  end

  def test_a_missing_executable_fails_with_a_readable_message
    error = assert_raises(StepError) { run_command(['definitely-not-on-this-runner'], echo: false) }
    assert_match(/was not found on this runner/, error.message)
  end

  # A stuck scan must never hang the build.
  def test_a_command_over_the_timeout_is_terminated
    error = assert_raises(CommandTimeout) { run_command(['sleep', '30'], timeout: 1, echo: false) }
    assert_match(/exceeded the 1 second timeout/, error.message)
  end
end

# End to end coverage: runs main.rb the way the runner does. Needs python3 and
# a reachable Python package index.
class EndToEndTest < Minitest::Test
  include EnvHelper

  def setup
    skip 'set MOBSFSCAN_E2E=1 to run the end to end tests' unless ENV['MOBSFSCAN_E2E'] == '1'
  end

  # Installing mobsfscan from pypi.org costs minutes per test. MOBSFSCAN_WHEELHOUSE
  # points the install at a local wheel directory instead, which also exercises
  # the air gapped path. Tests that cover the install itself opt out.
  def wheelhouse_input(extra)
    wheelhouse = ENV['MOBSFSCAN_WHEELHOUSE']
    return {} if wheelhouse.nil? || wheelhouse.empty?
    return {} if %w[AC_MOBSFSCAN_VERSION AC_MOBSFSCAN_PIP_INDEX_URL
                    AC_MOBSFSCAN_PIP_FIND_LINKS].any? { |key| extra.key?(key) }

    { 'AC_MOBSFSCAN_PIP_FIND_LINKS' => wheelhouse }
  end

  # Report content assertions must not depend on the severity gate, so the
  # helper scans in report only mode. The threshold tests set their own value,
  # and passing nil for a key exercises the step's own default.
  def run_step_for(source, extra = {})
    Dir.mktmpdir do |workspace|
      step_temp = File.join(workspace, 'step_temp')
      output_dir = File.join(workspace, 'output')
      env_file = File.join(workspace, 'env_file')
      FileUtils.mkdir_p([step_temp, output_dir])
      FileUtils.touch(env_file)

      env = {
        'AC_REPOSITORY_DIR' => SAMPLE_PROJECTS,
        'AC_STEP_TEMP' => step_temp,
        'AC_OUTPUT_DIR' => output_dir,
        'AC_ENV_FILE_PATH' => env_file,
        'AC_MOBSFSCAN_SOURCE_PATH' => source,
        'AC_MOBSFSCAN_SEVERITY_THRESHOLD' => 'none'
      }.merge(wheelhouse_input(extra)).merge(extra)

      stdout, stderr, status = Open3.capture3(env, 'ruby', MAIN_RB)
      outputs = File.readlines(env_file, chomp: true).reject(&:empty?)
                    .to_h { |line| line.split('=', 2) }
      yield({ stdout: stdout, stderr: stderr, success: status.success?, outputs: outputs,
              output_dir: File.join(output_dir, 'mobsfscan_output') })
    end
  end

  def read_report(result, filename)
    JSON.parse(File.read(File.join(result[:output_dir], filename)))
  end

  def test_an_android_project_is_scanned_and_reported
    run_step_for('android') do |result|
      assert result[:success], "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
      refute_match(/semgrep not found/, result[:stdout])

      report = read_report(result, 'mobsfscan.json')
      assert_empty report['errors']
      matched = report['results'].reject { |_id, detail| (detail['files'] || []).empty? }
      refute_empty matched, 'expected findings in the insecure Android sample'

      detail = matched.values.first
      finding = detail['files'].first
      assert finding['file_path']
      assert finding['match_lines'].first.positive?
      assert detail['metadata']['severity']
      assert detail['metadata']['cwe']
      assert detail['metadata']['masvs']
    end
  end

  def test_an_ios_project_is_scanned_and_reported
    run_step_for('ios') do |result|
      assert result[:success], "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
      report = read_report(result, 'mobsfscan.json')
      matched = report['results'].reject { |_id, detail| (detail['files'] || []).empty? }
      refute_empty matched, 'expected findings in the insecure iOS sample'
      assert matched.keys.any? { |id| id.start_with?('ios_') }
    end
  end

  def test_sarif_and_json_reports_are_published_as_artifacts
    run_step_for('android') do |result|
      assert result[:success]
      assert File.file?(File.join(result[:output_dir], 'mobsfscan.json'))
      assert File.file?(File.join(result[:output_dir], 'mobsfscan.sarif'))

      sarif = read_report(result, 'mobsfscan.sarif')
      assert_equal '2.1.0', sarif['version']
      refute_empty sarif['runs'].first['results']

      assert_equal File.join(result[:output_dir], 'mobsfscan.json'),
                   result[:outputs]['AC_MOBSFSCAN_JSON_REPORT_PATH']
      assert_equal File.join(result[:output_dir], 'mobsfscan.sarif'),
                   result[:outputs]['AC_MOBSFSCAN_SARIF_REPORT_PATH']
      assert result[:outputs]['AC_MOBSFSCAN_FINDING_COUNT'].to_i.positive?
      assert_includes %w[ERROR WARNING INFO], result[:outputs]['AC_MOBSFSCAN_HIGHEST_SEVERITY']
    end
  end

  def test_the_json_report_is_not_published_when_only_sarif_is_requested
    run_step_for('android', 'AC_MOBSFSCAN_OUTPUT_FORMATS' => 'sarif') do |result|
      assert result[:success]
      assert File.file?(File.join(result[:output_dir], 'mobsfscan.sarif'))
      refute File.exist?(File.join(result[:output_dir], 'mobsfscan.json'))
    end
  end

  def test_the_scan_type_override_is_honored
    run_step_for('android', 'AC_MOBSFSCAN_SCAN_TYPE' => 'ios') do |result|
      assert result[:success]
      report = read_report(result, 'mobsfscan.json')
      assert_empty report['results'], 'iOS rules must not match the Android sample'
    end
  end

  def test_a_clean_project_passes_and_still_produces_a_report
    run_step_for('clean') do |result|
      assert result[:success], "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
      assert File.file?(File.join(result[:output_dir], 'mobsfscan.json'))
      matched = read_report(result, 'mobsfscan.json')['results']
                .reject { |_id, detail| (detail['files'] || []).empty? }
      assert_empty matched
      assert_equal '0', result[:outputs]['AC_MOBSFSCAN_ERROR_COUNT']
    end
  end

  # The insecure Android sample carries an ERROR finding, so the default gate
  # has to fail on it.
  def test_the_default_error_threshold_fails_on_an_error_finding
    run_step_for('android', 'AC_MOBSFSCAN_SEVERITY_THRESHOLD' => nil) do |result|
      refute result[:success], 'expected the default threshold to fail on an ERROR finding'
      assert_match(/at or above the `error` severity threshold/, result[:stdout] + result[:stderr])
      assert_equal 'ERROR', result[:outputs]['AC_MOBSFSCAN_HIGHEST_SEVERITY']
    end
  end

  def test_the_warning_threshold_fails_the_build_and_still_publishes_the_report
    run_step_for('android', 'AC_MOBSFSCAN_SEVERITY_THRESHOLD' => 'warning') do |result|
      refute result[:success], 'expected the step to fail on WARNING findings'
      assert_match(/severity threshold/, result[:stdout] + result[:stderr])
      assert File.file?(File.join(result[:output_dir], 'mobsfscan.json'))
    end
  end

  def test_the_none_threshold_reports_without_failing
    run_step_for('android', 'AC_MOBSFSCAN_SEVERITY_THRESHOLD' => 'none') do |result|
      assert result[:success]
      assert result[:outputs]['AC_MOBSFSCAN_FINDING_COUNT'].to_i.positive?
    end
  end

  def test_inline_suppression_drops_a_single_finding
    run_step_for('android') do |result|
      assert result[:success], "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
      report = read_report(result, 'mobsfscan.json')
      suppressed = report['results'].values.flat_map { |detail| detail['files'] || [] }
                                   .map { |match| File.basename(match['file_path']) }
      refute_includes suppressed, 'SuppressedCode.java'
    end
  end

  def test_a_mobsf_config_suppresses_the_matching_findings
    Dir.mktmpdir do |repo|
      FileUtils.cp_r(File.join(SAMPLE_PROJECTS, 'android'), repo)
      File.write(File.join(repo, 'android', '.mobsf'),
                 "ignore-rules:\n  - hardcoded_api_key\n  - hardcoded_password\n  - hardcoded_secret\n")
      run_step_for('android', 'AC_REPOSITORY_DIR' => repo) do |result|
        assert result[:success]
        rules = read_report(result, 'mobsfscan.json')['results'].keys
        refute_includes rules, 'hardcoded_api_key'
        refute_includes rules, 'hardcoded_password'
      end
    end
  end

  def test_a_pinned_version_installs_exactly_that_version
    run_step_for('clean', 'AC_MOBSFSCAN_VERSION' => '0.4.5') do |result|
      assert result[:success], "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
      assert_match(/mobsfscan 0\.4\.5 is ready/, result[:stdout])
      refute_match(/@@\[warning\] Requested mobsfscan/, result[:stdout])
    end
  end

  def test_a_bad_pin_fails_with_an_actionable_message
    run_step_for('clean', 'AC_MOBSFSCAN_VERSION' => '99.99.99') do |result|
      refute result[:success]
      assert_match(/was not found on the configured package index|no usable outbound network access/,
                   result[:stdout] + result[:stderr])
    end
  end

  def test_an_unreachable_index_produces_an_actionable_message
    run_step_for('clean', 'AC_MOBSFSCAN_PIP_INDEX_URL' => 'https://pypi.invalid-host.example/simple') do |result|
      refute result[:success]
      combined = result[:stdout] + result[:stderr]
      assert_match(/no usable outbound network access|was not found on the configured package index/, combined)
    end
  end

  def test_a_missing_source_path_fails_before_installing_anything
    run_step_for('does-not-exist') do |result|
      refute result[:success]
      assert_match(/does not exist/, result[:stdout] + result[:stderr])
      refute_match(/Installing mobsfscan/, result[:stdout])
    end
  end
end
