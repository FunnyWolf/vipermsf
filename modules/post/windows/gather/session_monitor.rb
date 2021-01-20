##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report

  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Accounts
  OUI_LIST = Rex::Oui

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Windows Session Monitor',
                      'Description'  => %q{ This Module is use to monitor session.},
                      'License'      => MSF_LICENSE,
                      'Author'       => ['viper'],
                      'Platform'     => ['win'],
                      'SessionTypes' => ['meterpreter']
          ))
    register_options(
            [
                    OptString.new('DarkGuardian_path', [false, 'DarkGuardian exe path', nil]),
            ])
  end

  # Run Method for when run command is issued
  def run
    @logged_on_users = []
    while true
      return false if !session.alive?
      logged_on_users_monitor()
      darkguardian_monitor()
      Rex::sleep(10)
    end


  end

  def darkguardian_monitor()
    darkguardian_path = datastore['DarkGuardian_path']
    if darkguardian_path == nil
      return
    end
    filename = darkguardian_path + '\\data\\notice.json'
    if exist?(filename)
      psresult = read_file(filename)
      session.fs.file.delete(filename)
      # rm_f([filename])
      pub_json_data(true,
                    "RDP_NOTICES",
                    psresult,
                    self.uuid)
    end
  end

  def logged_on_users_monitor()
    tbl = []
    registry_enumkeys("HKU").each do |maybe_sid|
      # There is junk like .DEFAULT we want to avoid
      if maybe_sid =~ /^S(?:-\d+){2,}$/
        info = resolve_sid(maybe_sid)
        if !info.nil? && info[:type] == :user
          username = info[:domain] << '\\' << info[:name]
          oneuser  = {maybe_sid => username}
          tbl << oneuser
        end
      end
    end
    tbl.each do |tempuser|
      if !@logged_on_users.include?(tempuser)
        pub_json_data(true,
                      "LOGGED_ON_USERS",
                      tbl,
                      self.uuid)
      end
    end
    @logged_on_users = tbl
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
