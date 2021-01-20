##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'yajl'
class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Multi Manage Network Route via Meterpreter Session',
                      'Description'  => %q{This module manages session routing via an existing
          Meterpreter session. It enables other modules to 'pivot' through a
          compromised host when connecting to the named NETWORK and SUBMASK.
          Autoadd will search a session for valid subnets from the routing table
          and interface list then add routes to them. Default will add a default
          route so that all TCP/IP traffic not specified in the MSF routing table
          will be routed through the session when pivoting. See documentation for more
          'info -d' and click 'Knowledge Base'},
                      'License'      => MSF_LICENSE,
                      'Author'       =>
                              [
                                      'viper.',

                              ],
                      'Arch'         => [ARCH_X86, ARCH_X64],
                      'Platform'     => ['win', 'linux'],
                      'SessionTypes' => ['meterpreter']
          ))

    register_options(
            [
                    OptEnum.new('CMD', [true, 'Specify the portfwd command', 'list', ['add', 'delete', 'list', 'flush']]),
                    OptEnum.new('TYPE', [false, 'Forward: Indicates a port forward. Reverse: Indicates a reverse port forward.', 'Forward', ['Forward', 'Reverse']]),
                    OptString.new('LHOST', [false, 'Forward: local host to listen on (optional). Reverse: local host to connect to.', nil]),
                    OptInt.new('LPORT', [false, 'Forward: local port to listen on. Reverse: local port to connect to.', nil]),
                    OptString.new('RHOST', [false, 'Forward: remote host to connect to.', nil]),
                    OptInt.new('RPORT', [false, 'Forward: remote port to connect to. Reverse: remote port to listen on.', nil]),
                    OptInt.new('INDEX', [false, 'Index of the port forward entry to interact with.', nil]),
            ])
  end

  module PortForwardTracker
    def cleanup
      super

      if pfservice
        pfservice.deref
      end
    end

    attr_accessor :pfservice
  end

  def portfwd_cmd
    if datastore['ACTION'].to_s.empty?
      datastore['CMD'].to_s.downcase.to_sym
    else
      wlog("Warning, deprecated use of 'ACTION' datastore option for #{self.fullname}'. Use 'CMD' instead.")
      datastore['ACTION'].to_s.downcase.to_sym
    end
  end

  # Run Method for when run command is issued
  #
  # @return [void] A useful return value is not expected here
  def run
    @result = {:status => false, :message => nil, :data => nil}
    unless session_good?
      @result[:message] = "Session is not already"
      json              = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
      print(json)
      return
    end

    # If we haven't extended the session, then do it now since we'll
    # need to track port forwards
    if client.kind_of?(PortForwardTracker) == false
      client.extend(PortForwardTracker)
      client.pfservice = Rex::ServiceManager.start(Rex::Services::LocalRelay)
    end

    # Build a local port forward in association with the channel
    service = client.pfservice

    # get args
    if datastore['TYPE'].downcase == 'reverse'
      reverse = true
    else
      reverse = false
    end

    rhost     = datastore['RHOST']
    rport     = datastore['RPORT']
    lhost     = datastore['LHOST']
    lport     = datastore['LPORT']
    index     = datastore['INDEX']
    sessionid = datastore['SESSION']
    case portfwd_cmd
    when :list
      cnt = 0
      # Enumerate each TCP relay
      list_route = []
      service.each_tcp_relay { |lhost, lport, rhost, rport, opts|
        next if (opts['MeterpreterRelay'] == nil)
        # direction  = 'Forward'
        # direction  = 'Reverse' if opts['Reverse'] == true
        if opts['Reverse'] == true
          # LocalHost,LocalPort,PeerHost,PeerPort
          list_route << {:index     => cnt + 1,
                         :type      => 'Reverse',
                         :rhost     => lhost,
                         :rport     => lport,
                         :lhost     => rhost,
                         :lport     => rport,
                         :sessionid => opts['SessionID'],
          }
        else
          list_route << {:index     => cnt + 1,
                         :type      => 'Forward',
                         :rhost     => rhost,
                         :rport     => rport,
                         :lhost     => lhost,
                         :lport     => lport,
                         :sessionid => opts['SessionID'], }
        end
        cnt += 1
      }
      @result[:status] = true
      @result[:data]   = list_route
      json             = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
      print(json)
    when :add

      if reverse
        # Validate parameters
        unless lport && lhost && rport
          @result[:message] = "You must supply a local port, local host, and remote port."
          json              = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
          print(json)
          return
        end
        begin
          channel = client.net.socket.create(
                  Rex::Socket::Parameters.new(
                          'LocalPort' => rport,
                          'Proto'     => 'tcp',
                          'Server'    => true
                  )
          )

          # Start the local TCP reverse relay in association with this stream
          service.start_reverse_tcp_relay(channel,
                                          'LocalPort'        => rport,
                                          'PeerHost'         => lhost,
                                          'PeerPort'         => lport,
                                          'MeterpreterRelay' => true,
                                          'SessionID'        => sessionid)
        rescue Exception, Rex::AddressInUse => e
          @result[:message] = "Failed to create relay: #{e.to_s}"
          json              = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
          print(json)
          return
        end
      else
        # Validate parameters
        unless lport && rhost && rport
          @result[:message] = "You must supply a local port, remote host, and remote port."
          json              = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
          print(json)
          return
        end
        begin
          # Start the local TCP relay in association with this stream
          service.start_tcp_relay(lport,
                                  'LocalHost'         => lhost,
                                  'PeerHost'          => rhost,
                                  'PeerPort'          => rport,
                                  'MeterpreterRelay'  => true,
                                  'SessionID'         => sessionid,
                                  'OnLocalConnection' => Proc.new { |relay, lfd| create_tcp_channel(relay) }
          )
        rescue Exception, Rex::AddressInUse, Rex::BindFailed => e
          @result[:message] = "Failed to create relay: #{e.to_s}"
          json              = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
          print(json)
          return
        end
      end
      @result[:status] = true
      @result[:data]   = {:rhost     => rhost,
                          :rport     => rport,
                          :lhost     => lhost,
                          :lport     => lport,
                          :sessionid => sessionid,
      }
      json             = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
      print(json)
    when :flush

      list_route = []
      counter    = 0
      service.each_tcp_relay do |lhost, lport, rhost, rport, opts|
        next if (opts['MeterpreterRelay'] == nil)
        if opts['Reverse'] == true
          if service.stop_reverse_tcp_relay(lport, opts['SessionID'])
            list_route << {:lport => lport, }
          else
            vprint_error("Failed to stop TCP relay on #{lport}")
            next
          end
        else
          if service.stop_tcp_relay(lport, lhost)
            list_route << {:lport => lport, :lhost => lhost || '0.0.0.0'}
          else
            vprint_error("Failed to stop TCP relay on #{lhost || '0.0.0.0'}:#{lport}")
            next
          end
        end
        counter += 1
      end
      @result[:status] = true
      @result[:data]   = list_route
      json             = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
      print(json)
    when :delete

      found     = false
      unless index.nil?
        counter = 1
        service.each_tcp_relay do |lh, lp, rh, rp, opts|
          if counter == index
            lhost, lport, rhost, rport = lh, lp, rh, rp
            reverse                    = opts['Reverse'] == true
            found                      = true
            sessionid                  = opts['SessionID']
            break
          end
          counter += 1
        end

        unless found
          vprint_error("Invalid index:  #{index}")

          # @result[:message] = "Invalid index: #{index}"
          # json              = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
          # print(json)
          # return
        end
      end

      if reverse
        # No remote port, no love.
        unless rport
          @result[:message] = 'You must supply a remote port.'
          json              = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
          print(json)
          return
        end
        sessionid = datastore['SESSION']
        if service.stop_reverse_tcp_relay(rport, sessionid)
          @result[:status] = true
          @result[:data]   = {:rport => rport, }
          json             = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
          print(json)
        else
          @result[:message] = "Failed to stop reverse TCP relay on #{rport}"
          @result[:data]    = {:rport => rport, }
          json              = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
          print(json)
        end
      else
        # No local port, no love.
        unless lport
          @result[:message] = 'You must supply a local port.'
          json              = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
          print(json)
          return
        end
        # Stop the service
        if service.stop_tcp_relay(lport, lhost)
          @result[:status] = true
          @result[:data]   = {:lhost => lhost || '0.0.0.0', :lport => lport, }
          json             = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
          print(json)
        else
          @result[:message] = "Failed to stop TCP relay on #{lhost || '0.0.0.0'}:#{lport}"
          @result[:data]    = {:lhost => lhost || '0.0.0.0', :lport => lport, }
          json              = Yajl::Encoder.encode(@result).encode('UTF-8', :invalid => :replace, :replace => "?")
          print(json)
        end
      end
    end
  end

  # Checks to see if the session is ready.
  #
  # Some Meterpreter types, like python, can take a few seconds to
  # become fully established. This gracefully exits if the session
  # is not ready yet.
  #
  # @return [true class] Session is good
  # @return [false class] Session is not
  def session_good?
    if !session.info
      return false
    end
    return true
  end

  def create_tcp_channel(relay)
    client.net.socket.create(
            Rex::Socket::Parameters.new(
                    'PeerHost' => relay.opts['PeerHost'],
                    'PeerPort' => relay.opts['PeerPort'],
                    'Proto'    => 'tcp'
            )
    )
  end
end
