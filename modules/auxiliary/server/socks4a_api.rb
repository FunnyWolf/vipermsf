##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::SocketServer
  def initialize
    super(
            'Name'           => 'Socks4a Proxy Server',
            'Description'    => 'This module provides a socks4a proxy server that uses the builtin Metasploit routing to relay connections.',
            'Author'         => 'sf',
            'License'        => MSF_LICENSE,
            'Actions'        =>
                    [
                            ['Proxy']
                    ],
            'PassiveActions' =>
                    [
                            'Proxy'
                    ],
            'DefaultAction'  => 'Proxy'
    )

    register_options(
            [

                    OptString.new('SRVHOST', [true, "The address to listen on", '0.0.0.0']),
                    OptPort.new('SRVPORT', [true, "The port to listen on.", 1080])
            ])
  end

  def setup
    super
    @mutex   = ::Mutex.new
    @socks4a = nil
  end

  def cleanup
    @mutex.synchronize do
      if (@socks4a)
        print_status("Stopping the socks4a proxy server")
        @socks4a.stop
        @socks4a = nil
      end
    end
    super
  end

  def run
    opts = {
            'ServerHost' => bindhost,
            'ServerPort' => bindport,
            'Comm' => _determine_server_comm(bindhost),
            'Context' => { 'Msf' => framework, 'MsfExploit' => self }
    }

    @socks4a = Rex::Proto::Proxy::Socks4a.new(opts)

    print_status("Starting the socks4a proxy server")

    @socks4a.start

    @socks4a.join
  end
end
