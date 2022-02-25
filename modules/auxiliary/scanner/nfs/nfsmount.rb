##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SunRPC
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'          => 'NFS Mount Scanner',
      'Description'   => %q{
        This module scans NFS mounts and their permissions.
      },
      'Author'	       => ['<tebo[at]attackresearch.com>'],
      'References'     =>
        [
          ['CVE', '1999-0170'],
          ['URL',	'https://www.ietf.org/rfc/rfc1094.txt']
        ],
      'License'	=> MSF_LICENSE
    )

    register_options([
      OptEnum.new('PROTOCOL', [ true, 'The protocol to use', 'udp', ['udp', 'tcp']])
    ])

  end

  def run_host(ip)

    begin
      program		= 100005
      progver		= 1
      procedure	= 5

      sunrpc_create(datastore['PROTOCOL'], program, progver)
      sunrpc_authnull()
      resp = sunrpc_call(procedure, "")

      # XXX: Assume that transport is udp and port is 2049
      # Technically we are talking to mountd not nfsd

      report_service(
        :host  => ip,
        :proto => datastore['PROTOCOL'],
        :port  => 2049,
        :name  => 'nfsd',
        :info  => "NFS Daemon #{program} v#{progver}"
      )

      exports = resp[3,1].unpack('C')[0]
      if (exports == 0x01)
        shares = []
        while Rex::Encoder::XDR.decode_int!(resp) == 1 do
          dir = Rex::Encoder::XDR.decode_string!(resp)
          grp = []
          while Rex::Encoder::XDR.decode_int!(resp) == 1 do
            grp << Rex::Encoder::XDR.decode_string!(resp)
          end
          print_good("#{ip} NFS Export: #{dir} [#{grp.join(", ")}]")
          shares << [dir, grp]
        end
        report_note(
          :host => ip,
          :proto => datastore['PROTOCOL'],
          :port => 2049,
          :type => 'nfs.exports',
          :data => { :exports => shares },
          :update => :unique_data
        )
      elsif(exports == 0x00)
        vprint_status("#{ip} - No exported directories")
      end

      sunrpc_destroy
    rescue ::Rex::Proto::SunRPC::RPCTimeout, ::Rex::Proto::SunRPC::RPCError => e
      vprint_error(e.to_s)
    end
  end
end
