# -*- coding: binary -*-

module Msf
  module Handler
    ###
    #
    # This handler implements the SSH tunneling interface.
    #
    ###
    module ReverseSsh
      include Msf::Handler
      include Msf::Handler::Reverse

      #
      # Returns the string representation of the handler type
      #
      def self.handler_type
        return 'reverse_ssh'
      end

      #
      # Returns the connection-described general handler type, in this case
      # 'tunnel'.
      #
      def self.general_handler_type
        'tunnel'
      end

      # Initializes the reverse SSH handler and ads the options that are required
      # for all reverse SSH payloads, like version string and auth params.
      #
      def initialize(info = {})
        super
        register_options([Opt::LPORT(22)])
        register_advanced_options(
          [
            OptString.new('Ssh::Version', [
              true,
              'The SSH version string to provide',
              default_version_string
            ])
          ], Msf::Handler::ReverseSsh
        )
      end

      # A URI describing where we are listening
      #
      # @param addr [String] the address that
      # @return [String] A URI of the form +ssh://host:port/+
      def listener_uri(addr = datastore['ReverseListenerBindAddress'])
        addr = datastore['LHOST'] if addr.nil? || addr.empty?
        uri_host = Rex::Socket.is_ipv6?(addr) ? "[#{addr}]" : addr
        "ssh://#{uri_host}:#{bind_port}"
      end

      # Create an Ssh listener
      #
      # @return [void]
      def setup_handler
        local_addr = nil
        local_port = bind_port
        ex = false

        ssh_opts = Rex::Proto::Ssh::Connection.default_options
        ssh_opts['local_version'] = datastore['Ssh::Version']

        # Start the SSH server service on this host/port
        bind_addresses.each do |ip|
          self.service = Rex::ServiceManager.start(Rex::Proto::Ssh::Server,
                                                   local_port, ip,
                                                   {
                                                     'Msf' => framework,
                                                     'MsfExploit' => self
                                                   },
                                                   comm,
                                                   ssh_opts)
          local_addr = ip
        rescue StandardError
          ex = $!
          print_error("Handler failed to bind to #{ip}:#{local_port}")
        else
          ex = false
          break
        end

        service.on_client_connect_proc = proc { |cli| init_fd_client(cli) }
        raise ex if ex

        print_status("Started SSH reverse handler on #{listener_uri(local_addr)}")

        if datastore['IgnoreUnknownPayloads']
          print_status('Handler is ignoring unknown payloads')
        end
      end

      # Stops the handler & service
      #
      # @return [void]
      def stop_handler
        if service && (sessions == 0)
          Rex::ServiceManager.stop_service(service)
        end
      end

      def init_fd_client(cli)
        Timeout.timeout(5) do
          sleep 0.02 while cli.connection.open_channel_keys.empty?
          fdc = Rex::Proto::Ssh::ChannelFD.new(cli)
          service.clients.push(fdc)
          create_session(fdc)
        end
      rescue Timeout::Error
        elog("Unable to find channel FDs for client #{cli}")
      end

      def create_session(ssh, opts = {})
        # If there is a parent payload, then use that in preference.
        s = Sessions::SshCommandShellReverse.new(ssh, opts)
        # Pass along the framework context
        s.framework = framework

        # Associate this system with the original exploit
        # and any relevant information
        s.set_from_exploit(assoc_exploit)

        # If the session is valid, register it with the framework and
        # notify any waiters we may have.
        if s
          register_session(s)
        end

        return s
      end

      #
      # Always wait at least 5 seconds for this payload (due to channel delays)
      #
      def wfs_delay
        datastore['WfsDelay'] > 4 ? datastore['WfsDelay'] : 5
      end
      attr_accessor :service # :nodoc:

      private

      def default_version_string
        require 'rex/proto/ssh/connection'
        Rex::Proto::Ssh::Connection.default_options['local_version']
      rescue LoadError => e
        print_error("This handler requires PTY access not available on all platforms.")
        elog(e)
        'SSH-2.0-OpenSSH_5.3p1'
      end
    end
  end
end
