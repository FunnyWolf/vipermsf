##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report

  OUI_LIST = Rex::Oui

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather ARP Scanner',
        'Description'   => %q{ This Module will perform an ARP scan for a given IP range through a
          Meterpreter Session.},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter']
      ))
    register_options(
      [
        OptString.new('RHOSTS', [true, 'The target address range or CIDR identifier', nil]),
        OptInt.new('THREADS', [false, 'The number of concurrent threads', 10])

      ])
  end

  # Run Method for when run command is issued
  def run
    arp_scan(datastore['RHOSTS'], datastore['THREADS'])
  end


  def arp_scan(cidr, threads)

    ws           = client.railgun.ws2_32
    iphlp        = client.railgun.iphlpapi
    a            = []
    iplst, found = [], ""
    ipadd        = Rex::Socket::RangeWalker.new(cidr)
    numip        = ipadd.num_ips
    while (iplst.length < numip)
      ipa = ipadd.next_ip
      if (not ipa)
        break
      end
      iplst << ipa
    end
    data = []
    while (not iplst.nil? and not iplst.empty?)
      a = []
      1.upto(threads) do
        a << framework.threads.spawn("Module(#{self.refname})", false, iplst.shift) do |ip_text|
          next if ip_text.nil?
          h  = ws.inet_addr(ip_text)
          ip = h["return"]
          h  = iphlp.SendARP(ip, 0, 6, 6)
          if h["return"] == client.railgun.const("NO_ERROR")
            mac_text = h["pMacAddr"].unpack('C*').map { |e| "%02x" % e }.join(':')
            company  = OUI_LIST::lookup_oui_company_name(mac_text)
            data.push({:host => ip_text, :mac => mac_text, :company => company})
            report_host(:host => ip_text, :mac => mac_text)
            next if company.nil?
            nil
          end
        end
      end
      a.map { |x| x.join }
    end
    pub_json_result(true,
                    nil,
                    data,
                    self.uuid)

  end
end
