##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'zlib'
require 'base64'

# require 'rex/post/meterpreter/extensions/python/python'
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Common
  include Msf::Payload::Python

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => "Muit Manage Python Load and run",
                      'Description'  => %q{
        This module will Load and execute a Python script over a meterpreter session.
        The user may also enter text substitutions to be made in memory before execution.
        Setting VERBOSE to true will output both the script prior to execution and the results.
      },
                      'License'      => MSF_LICENSE,
                      'Platform'     => ['win', 'linux'],
                      'SessionTypes' => ['meterpreter'],
                      'Author'       => [
                              'viper',
                      ]
          ))

    register_options(
            [
                    OptString.new('SCRIPT', [true, 'Path to the local Python script', ::File.join(Msf::Config.install_root, "scripts", "python", "getcwd.py")]),

            ])

    register_advanced_options(
            [
                    OptInt.new('TIMEOUT', [false, 'Execution timeout', 60]),
            ])

  end

  # Msf::Config.loot_directory
  def run

    if session.type == "shell"
      pub_json_result(false,
                      'Unsupport shell type',
                      nil,
                      self.uuid)
      return
    end

    if File.file?(File.join(Msf::Config.loot_directory, datastore['SCRIPT']))
      script_path = File.join(Msf::Config.loot_directory, datastore['SCRIPT'])
    elsif File.file?(datastore['SCRIPT'])
      script_path = datastore['SCRIPT']
    else
      pub_json_result(false,
                      "#{datastore['SCRIPT']} not found",
                      nil,
                      self.uuid)

      return
    end

    if session.platform == "linux"
      # run with system python
      python_run, python_version = get_linux_python_version
      if python_version == nil
        pub_json_result(false,
                        'this linux system does not have python',
                        nil,
                        self.uuid)
        return
      end
      timeout    = datastore['TIMEOUT']
      python_cmd = "#{python_run} -c \"#{py_create_exec_stub(File.read(script_path))}\""

      if python_cmd.length > 1024
        filename = '/' + Time.now.to_i.to_s + '.py'
        tmprpath = session.fs.dir.pwd + filename
        upload_file(tmprpath, script_path)
        script_result = cmd_exec(cmd = "#{python_run} #{tmprpath}", args = "", time_out = timeout)
        register_file_for_cleanup(tmprpath)
      else
        script_result = cmd_exec(cmd = python_cmd, args = "", time_out = timeout)
      end
      pub_json_result(true,
                      nil,
                      script_result,
                      self.uuid)

      print("#{script_result}")
    else
      session.load_python
      if session.ext.aliases.has_key?('python')
        py_ext = session.ext.aliases['python']
        begin
          pyresult = py_ext.import(script_path, nil, nil, datastore['TIMEOUT'])
        rescue ::Timeout::Error, Rex::TimeoutError
          pub_json_result(false,
                          'run script timeout,please set timeout bigger',
                          script_result,
                          self.uuid)
          return
        end

        if pyresult[:stdout].length > 0
          pub_json_result(true,
                          pyresult[:stderr],
                          pyresult[:stdout],
                          self.uuid)
          print("#{pyresult}")

        else
          pub_json_result(false,
                          'there are no output for script!',
                          nil,
                          self.uuid)
        end
      else
        pub_json_result(false,
                        'python extensions load failed!',
                        nil,
                        self.uuid)
      end
    end
  end

  def get_linux_python_version()
    result = cmd_exec("python -V")
    if (result =~ /Python (.+)/)
      return "python", $1
    end

    result = cmd_exec("python2 -V")
    if (result =~ /Python (.+)/)
      return "python2", $1
    end

    result = cmd_exec("python3 -V")
    if (result =~ /Python (.+)/)
      return "python3", $1
    end
    return nil, nil
  end

  def rpath
    filename = '/' + Time.now.to_i.to_s
    session.fs.dir.pwd + filename
  end
end

