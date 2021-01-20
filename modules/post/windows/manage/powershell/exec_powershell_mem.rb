##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zlib'

class MetasploitModule < Msf::Post


  def initialize(info = {})
    super(update_info(info,
                      'Name'         => "Muit Manage Powershell load and run",
                      'Description'  => %q{
        This module will Load and execute a Powershell script over a meterpreter session.
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
                    OptString.new('SCRIPT', [true, 'Path to the local powershell script', ::File.join(Msf::Config.install_root, "scripts", "ps", "msflag.ps1")]),
            ])

    register_advanced_options(
            [
                    OptInt.new('TIMEOUT', [false, 'Execution timeout', 60]),
            ])

  end

  def run

    if session.type == "shell"
      pub_json_result(false,
                      "Unsupport shell type",
                      nil,
                      self.uuid)
      return
    end

    if File.file?(File.join(Msf::Config.loot_directory, datastore['SCRIPT']))
      script_path = File.join(Msf::Config.loot_directory, datastore['SCRIPT'])
    elsif File.file?(datastore['SCRIPT'])
      script_path = datastore['SCRIPT']
    elsif File.file?(File.join(Msf::Config.install_root, "scripts", "ps", datastore['SCRIPT']))
      script_path = File.join(Msf::Config.install_root, "scripts", "ps", datastore['SCRIPT'])
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
      ps_ext   = session.ext.aliases['powershell']
      opts     = {file: script_path}
      begin
        pyresult = ps_ext.import_file(opts, datastore['TIMEOUT'])
      rescue ::Timeout::Error, Rex::TimeoutError

        pub_json_result(false,
                        'run script timeout,please set timeout bigger',
                        nil,
                        self.uuid)
        return
      end

      if pyresult.length > 0
        pub_json_result(true,
                        nil,
                        pyresult,
                        self.uuid)
      else
        pub_json_result(false,
                        "there are no output for script",
                        nil,
                        self.uuid)

      end
    else
      pub_json_result(false,
                      'powershell extensions load failed!',
                      nil,
                      self.uuid)
    end
  end
end

