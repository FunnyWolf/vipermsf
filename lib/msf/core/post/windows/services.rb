# -*- coding: binary -*-

module Msf
class Post
module Windows


# @deprecated Use {Services} instead
module WindowsServices
  def self.included(base)
    include Services
  end

  def setup
    print_error("The Windows::WindowsServices mixin is deprecated, use Windows::Services instead")
    super
  end
end

#
# Post module mixin for dealing with Windows services
#
module Services

  START_TYPE = ["Boot","System","Auto","Manual","Disabled"]
  START_TYPE_BOOT       = 0
  START_TYPE_SYSTEM     = 1
  START_TYPE_AUTO       = 2
  START_TYPE_MANUAL     = 3
  START_TYPE_DISABLED   = 4

  SERVICE_STOPPED           = 1
  SERVICE_START_PENDING     = 2
  SERVICE_STOP_PENDING      = 3
  SERVICE_RUNNING           = 4
  SERVICE_CONTINUE_PENDING  = 5
  SERVICE_PAUSE_PENDING     = 6
  SERVICE_PAUSED            = 7

  include ::Msf::Post::Windows::Error
  include ::Msf::Post::Windows::ExtAPI
  include ::Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              extapi_service_enum
              extapi_service_query
              stdapi_railgun_api
            ]
          }
        }
      )
    )
  end

  def advapi32
    session.railgun.advapi32
  end

  #
  # Open the service manager with advapi32.dll!OpenSCManagerA on the
  # given host or the local machine if :host option is nil. If called
  # with a block, yields the manager and closes it when the block
  # returns.
  #
  # @param opts [Hash]
  # @option opts [String] :host (nil) The host on which to open the
  #   service manager. May be a hostname or IP address.
  # @option opts [Integer] :access (0xF003F) Bitwise-or of the
  #   SC_MANAGER_* constants (see
  #   {http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx})
  #
  # @return [Integer] Opaque Windows handle SC_HANDLE as returned by
  #   OpenSCManagerA()
  # @yield [manager] Gives the block a manager handle as returned by
  #   advapi32.dll!OpenSCManagerA. When the block returns, the handle
  #   will be closed with {#close_service_handle}.
  # @raise [RuntimeError] if OpenSCManagerA returns a NULL handle
  #
  def open_sc_manager(opts={})
    host = opts[:host] || nil
    access = opts[:access] || "SC_MANAGER_ALL_ACCESS"
    machine_str = host ? "\\\\#{host}" : nil

    # SC_HANDLE WINAPI OpenSCManager(
    #   _In_opt_  LPCTSTR lpMachineName,
    #   _In_opt_  LPCTSTR lpDatabaseName,
    #   _In_      DWORD dwDesiredAccess
    # );
    manag = advapi32.OpenSCManagerA(machine_str,nil,access)
    if (manag["return"] == 0)
      raise "Unable to open service manager: #{manag["ErrorMessage"]}"
    end

    if (block_given?)
      begin
        yield manag["return"]
      ensure
        close_service_handle(manag["return"])
      end
    else
      return manag["return"]
    end
  end

  #
  # Call advapi32.dll!CloseServiceHandle on the given handle
  #
  def close_service_handle(handle)
    if handle
      advapi32.CloseServiceHandle(handle)
    end
  end

  #
  # Open the service with advapi32.dll!OpenServiceA on the
  # target manager
  #
  # @return [Integer] Opaque Windows handle SC_HANDLE as returned by
  #   OpenServiceA()
  # @yield [manager] Gives the block a service handle as returned by
  #   advapi32.dll!OpenServiceA. When the block returns, the handle
  #   will be closed with {#close_service_handle}.
  # @raise [RuntimeError] if OpenServiceA failed
  #
  def open_service_handle(manager, name, access)
    handle = advapi32.OpenServiceA(manager, name, access)
    if (handle["return"] == 0)
      raise "Could not open service. OpenServiceA error: #{handle["ErrorMessage"]}"
    end

    if (block_given?)
      begin
        yield handle["return"]
      ensure
        close_service_handle(handle["return"])
      end
    else
      return handle["return"]
    end
  end

  # Yield each service name on the remote host
  #
  # @todo Allow operating on a remote host
  # @yield [String] Case-sensitive name of a service
  def each_service(&block)
    if load_extapi
      session.extapi.service.enumerate.each(&block)
    else
      serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"

      keys = registry_enumkeys(serviceskey)
      keys.each do |sk|
        srvtype = registry_getvaldata("#{serviceskey}\\#{sk}","Type")
        # From http://support.microsoft.com/kb/103000
        #
        # 0x1            A Kernel device driver.
        #
        # 0x2            File system driver, which is also
        #                a Kernel device driver.
        #
        # 0x4            A set of arguments for an adapter.
        #
        # 0x10           A Win32 program that can be started
        #                by the Service Controller and that
        #                obeys the service control protocol.
        #                This type of Win32 service runs in
        #                a process by itself.
        #
        # 0x20           A Win32 service that can share a process
        #                with other Win32 services.
        if srvtype == 32 || srvtype == 16
          yield sk
        end
      end

      keys
    end
  end

  #
  # List all Windows Services present
  #
  # @return [Array<Hash>] Array of Hashes containing Service details. May contain the following keys:
  #   * :name
  #   * :display
  #   * :pid
  #   * :status
  #   * :interactive
  #
  # @todo Rewrite to allow operating on a remote host
  #
  def service_list
    if load_extapi
      return session.extapi.service.enumerate
    else
      serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
      a =[]
      services = []
      keys = registry_enumkeys(serviceskey)
      keys.each do |s|
        if a.length >= 10
          a.first.join
          a.delete_if {|x| not x.alive?}
        end
        t = framework.threads.spawn(self.refname+"-ServiceRegistryList",false,s) { |sk|
          begin
            srvtype = registry_getvaldata("#{serviceskey}\\#{sk}","Type").to_s
            if srvtype == "32" or srvtype == "16"
              services << {:name => sk }
            end
          rescue
          end
        }
        a.push(t)
      end
    end

    return services
  end

  #
  # Get Windows Service information.
  #
  # Information returned in a hash with display name, startup mode and
  # command executed by the service. Service name is case sensitive.  Hash
  # keys are Name, Start, Command and Credentials.
  #
  # If ExtAPI is available we return the DACL, LOGroup, and Interactive
  # values otherwise these values are nil
  #
  # @param name [String] The target service's name (not to be confused
  #   with Display Name). Case sensitive.
  #
  # @return [Hash]
  #
  # @todo Rewrite to allow operating on a remote host
  #
  def service_info(name)
    service = {}

    if load_extapi
      begin
        return session.extapi.service.query(name)
      rescue Rex::Post::Meterpreter::RequestError => e
        vprint_error("Request Error #{e} falling back to registry technique")
      end
    end

    servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
    service[:display]     = registry_getvaldata(servicekey,"DisplayName").to_s
    service[:starttype]   = registry_getvaldata(servicekey,"Start").to_i
    service[:path]        = registry_getvaldata(servicekey,"ImagePath").to_s
    service[:startname]   = registry_getvaldata(servicekey,"ObjectName").to_s
    service[:dacl]        = nil
    service[:logroup]     = nil
    service[:interactive] = nil

    return service
  end

  #
  # Check if the specified Windows service exists.
  #
  # @param name [String] The target service's name (not to be confused
  #   with Display Name). Case sensitive.
  #
  # @return [Boolean]
  #
  def service_exists?(service)
    srv_info = service_info(service)

    if srv_info.nil?
      vprint_error('Unable to enumerate Windows services')
      return false
    end

    if srv_info && srv_info[:display].empty?
      return false
    end

    true
  end

  #
  # Changes a given service startup mode, name must be provided and the mode.
  #
  # Mode is a string with either auto, manual or disable for the
  # corresponding setting. The name of the service is case sensitive.
  #
  #
  def service_change_startup(name, mode, server=nil)
    if mode.is_a? Integer
      startup_number = mode
    else
      case mode.downcase
        when "boot" then startup_number     = START_TYPE_BOOT
        when "system" then startup_number   = START_TYPE_SYSTEM
        when "auto" then startup_number     = START_TYPE_AUTO
        when "manual" then startup_number   = START_TYPE_MANUAL
        when "disable" then startup_number  = START_TYPE_DISABLED
        else
          raise "Invalid Startup Mode: #{mode}"
      end
    end

    if session.railgun
      begin
        ret = service_change_config(name, {:starttype => startup_number}, server)
        return (ret == Error::SUCCESS)
      rescue Rex::Post::Meterpreter::RequestError => e
        if server
          # Cant do remote registry changes at present
          return false
        else
          vprint_error("Request Error #{e} falling back to registry technique")
        end
      end
    end

    servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
    registry_setvaldata(servicekey,"Start",startup_number,"REG_DWORD")
  end

  #
  # Modify a service on the session host
  #
  # @param name [String] Name of the service to be used as the key
  # @param opts [Hash] Settings to be modified
  # @param server [String,nil] A hostname or IP address. Default is the
  #   remote localhost
  #
  # @return [GetLastError] 0 if the function succeeds
  #
  def service_change_config(name, opts, server=nil)
    open_sc_manager(:host=>server, :access=>"SC_MANAGER_CONNECT") do |manager|
      open_service_handle(manager, name, "SERVICE_CHANGE_CONFIG") do |service_handle|
        ret = advapi32.ChangeServiceConfigA(service_handle,
                                 opts[:service_type]        || "SERVICE_NO_CHANGE",
                                 opts[:starttype]           || "SERVICE_NO_CHANGE",
                                 opts[:error_control]       || "SERVICE_NO_CHANGE",
                                 opts[:path]                || nil,
                                 opts[:logroup]             || nil,
                                 opts[:tag_id]              || nil,
                                 opts[:dependencies]        || nil,
                                 opts[:startname]           || nil,
                                 opts[:password]            || nil,
                                 opts[:display]             || nil
        )

        return ret['GetLastError']
      end
    end
  end

  #
  # Create a service that runs +executable_on_host+ on the session host
  #
  # @param name [String] Name of the service to be used as the key
  # @param opts [Hash] Settings to be modified
  # @param server [String,nil] A hostname or IP address. Default is the
  #   remote localhost
  #
  # @return [GetLastError] 0 if the function succeeds
  #
  def service_create(name, opts, server=nil)
    access = "SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS"
    open_sc_manager(:host=>server, :access=>access) do |manager|

      opts[:display]             ||= Rex::Text.rand_text_alpha(8)
      opts[:desired_access]      ||= "SERVICE_START"
      opts[:service_type]        ||= "SERVICE_WIN32_OWN_PROCESS"
      opts[:starttype]           ||= START_TYPE_AUTO
      opts[:error_control]       ||= "SERVICE_ERROR_IGNORE"
      opts[:path]                ||= nil
      opts[:logroup]             ||= nil
      opts[:tag_id]              ||= nil
      opts[:dependencies]        ||= nil
      opts[:startname]           ||= nil
      opts[:password]            ||= nil

      newservice = advapi32.CreateServiceA(manager,
                                      name,
                                      opts[:display],
                                      opts[:desired_access],
                                      opts[:service_type],
                                      opts[:starttype],
                                      opts[:error_control],
                                      opts[:path],
                                      opts[:logroup],
                                      opts[:tag_id], # out
                                      opts[:dependencies],
                                      opts[:startname],
                                      opts[:password]
      )

      if newservice
        close_service_handle(newservice["return"])
      end

      return newservice["GetLastError"]
    end
  end

  #
  # Start a service.
  #
  # @param name [String] Service name (not display name)
  # @param server [String,nil] A hostname or IP address. Default is the
  #   remote localhost
  #
  # @return [Integer] 0 if service started successfully, 1 if it failed
  #   because the service is already running, 2 if it is disabled
  #
  # @raise [RuntimeError] if OpenServiceA failed
  #
  def service_start(name, server=nil)
    open_sc_manager(:host=>server, :access=>"SC_MANAGER_CONNECT") do |manager|
      open_service_handle(manager, name, "SERVICE_START") do |service_handle|
        retval = advapi32.StartServiceA(service_handle,0,nil)

        return retval["GetLastError"]
      end
    end
  end

  #
  # Stop a service.
  #
  # @param (see #service_start)
  # @return [Integer] 0 if service stopped successfully, 1 if it failed
  #   because the service is already stopped or disabled, 2 if it
  #   cannot be stopped for some other reason.
  #
  # @raise (see #service_start)
  #
  def service_stop(name, server=nil)
    open_sc_manager(:host=>server, :access=>"SC_MANAGER_CONNECT") do |manager|
      open_service_handle(manager, name, "SERVICE_STOP") do |service_handle|

        retval = advapi32.ControlService(service_handle,1,28)
        case retval["GetLastError"]
        when Error::SUCCESS,
            Error::INVALID_SERVICE_CONTROL,
            Error::SERVICE_CANNOT_ACCEPT_CTRL,
            Error::SERVICE_NOT_ACTIVE
          status = parse_service_status_struct(retval['lpServiceStatus'])
        else
          status = nil
        end

        return retval["GetLastError"]
      end
    end
  end

  #
  # Delete a service.
  #
  # @param (see #service_start)
  #
  def service_delete(name, server=nil)
    open_sc_manager(:host=>server) do |manager|
      open_service_handle(manager, name, "DELETE") do |service_handle|
        ret = advapi32.DeleteService(service_handle)
        return ret["GetLastError"]
      end
    end
  end

  #
  # Query Service Status
  #
  # @param (see #service_start)
  #
  # @return {} representing lpServiceStatus
  #
  # @raise (see #service_start)
  #
  #
  def service_status(name, server=nil)
    ret = nil

    open_sc_manager(:host => server, :access => "GENERIC_READ") do |manager|
      open_service_handle(manager, name, "GENERIC_READ") do |service_handle|
        status = advapi32.QueryServiceStatus(service_handle,28)

        if (status["return"] == 0)
          raise "Could not query service. QueryServiceStatus error: #{status["ErrorMessage"]}"
        else
          ret = parse_service_status_struct(status['lpServiceStatus'])
        end
      end
    end

    return ret
  end

  #
  # Performs an aggressive service (re)start
  # If service is disabled it will re-enable
  # If service is running it will stop and restart
  #
  # @param name [String] The service name
  # @param start_type [Integer] The start type to configure if disabled
  # @param server [String] The server to target
  #
  # @return [Boolean] indicating success
  #
  #
  def service_restart(name, start_type=START_TYPE_AUTO, server=nil)
    tried = false

    begin
      status = service_start(name, server)

      if status == Error::SUCCESS
        vprint_good("[#{name}] Service started")
        return true
      else
        raise status
      end
    rescue RuntimeError => s
      if tried
        vprint_error("[#{name}] Unhandled error: #{s}")
        return false
      else
        tried = true
      end

      case s.message.to_i
      when Error::ACCESS_DENIED
        vprint_error("[#{name}] Access denied")
      when Error::INVALID_HANDLE
        vprint_error("[#{name}] Invalid handle")
      when Error::PATH_NOT_FOUND
        vprint_error("[#{name}] Service binary could not be found")
      when Error::SERVICE_ALREADY_RUNNING
        vprint_status("[#{name}] Service already running attempting to stop and restart")
        stopped = service_stop(name, server)
        if ((stopped == Error::SUCCESS) || (stopped == Error::SERVICE_NOT_ACTIVE))
          retry
        else
          vprint_error("[#{name}] Service disabled, unable to change start type Error: #{stopped}")
        end
      when Error::SERVICE_DISABLED
        vprint_status("[#{name}] Service disabled attempting to set to manual")
        if (service_change_config(name, {:starttype => start_type}, server) == Error::SUCCESS)
          retry
        else
          vprint_error("[#{name}] Service disabled, unable to change start type")
        end
      else
        vprint_error("[#{name}] Unhandled error: #{s}")
        return false
      end
    end
  end

  #
  # Parses out a SERVICE_STATUS struct from the
  # lpServiceStatus out parameter
  #
  # @param lpServiceStatus [String] the latest status of calling service
  #
  # @return [Hash] Containing SERVICE_STATUS values
  #
  def parse_service_status_struct(lpServiceStatus)
    if lpServiceStatus
      vals = lpServiceStatus.unpack('V*')
      return {
          :type              => vals[0],
          :state             => vals[1],
          :controls_accepted => vals[2],
          :win32_exit_code   => vals[3],
          :service_exit_code => vals[4],
          :check_point       => vals[5],
          :wait_hint         => vals[6]
      }
    else
     return nil
    end
  end

end

end
end
end
