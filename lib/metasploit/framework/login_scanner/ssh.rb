require 'net/ssh'
require 'metasploit/framework/login_scanner/base'
require 'rex/socket/ssh_factory'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with the Secure Shell protocol.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      #
      class SSH
        include Metasploit::Framework::LoginScanner::Base

        #
        # CONSTANTS
        #

        CAN_GET_SESSION      = true
        DEFAULT_PORT         = 22
        LIKELY_PORTS         = [ DEFAULT_PORT ]
        LIKELY_SERVICE_NAMES = [ 'ssh' ]
        PRIVATE_TYPES        = [ :password, :ssh_key ]
        REALM_KEY            = nil

        VERBOSITIES = [
            :debug,
            :info,
            :warn,
            :error,
            :fatal
        ]
        # @!attribute ssh_socket
        #   @return [Net::SSH::Connection::Session] The current SSH connection
        attr_accessor :ssh_socket
        # @!attribute verbosity
        #   The verbosity level for the SSH client.
        #
        #   @return [Symbol] An element of {VERBOSITIES}.
        attr_accessor :verbosity
        # @!attribute skip_gather_proof
        #   @return [Boolean] Whether to skip calling gather_proof
        attr_accessor :skip_gather_proof

        validates :verbosity,
          presence: true,
          inclusion: { in: VERBOSITIES }

        # (see {Base#attempt_login})
        # @note The caller *must* close {#ssh_socket}
        def attempt_login(credential)
          self.ssh_socket = nil
          factory = Rex::Socket::SSHFactory.new(framework,framework_module, proxies)
          opt_hash = {
            :port            => port,
            :use_agent       => false,
            :config          => false,
            :verbose         => verbosity,
            :proxy           => factory,
            :non_interactive => true,
            :verify_host_key => :never
          }
          case credential.private_type
          when :password, nil
            opt_hash.update(
              :auth_methods  => ['password','keyboard-interactive'],
              :password      => credential.private,
            )
          when :ssh_key
            opt_hash.update(
              :auth_methods  => ['publickey'],
              :key_data      => credential.private,
            )
          end

          result_options = {
            credential: credential
          }
          begin
            ::Timeout.timeout(connection_timeout) do
              self.ssh_socket = Net::SSH.start(
                host,
                credential.public,
                opt_hash
              )
            end
          rescue OpenSSL::Cipher::CipherError, ::EOFError, Net::SSH::Disconnect, Rex::ConnectionError, ::Timeout::Error, Errno::ECONNRESET => e
            result_options.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          rescue Net::SSH::Exception
            result_options.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: e)
          end

          unless result_options.has_key? :status
            if ssh_socket
              proof = gather_proof unless skip_gather_proof
              result_options.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: proof)
            else
              result_options.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: nil)
            end
          end

          result = ::Metasploit::Framework::LoginScanner::Result.new(result_options)
          result.host         = host
          result.port         = port
          result.protocol     = 'tcp'
          result.service_name = 'ssh'
          result
        end

        private

        # This method attempts to gather proof that we successfuly logged in.
        # @return [String] The proof of a connection, May be empty.
        def gather_proof
          proof = ''
          begin
            Timeout.timeout(10) do
              proof = ssh_socket.exec!("id\n").to_s
              if (proof =~ /id=/)
                proof << ssh_socket.exec!("uname -a\n").to_s
                if (proof =~ /JUNOS /)
                  # We're in the SSH shell for a Juniper JunOS, we can pull the version from the cli
                  # line 2 is hostname, 3 is model, 4 is the Base OS version
                  proof = ssh_socket.exec!("cli show version\n").split("\n")[2..4].join(", ").to_s
                elsif (proof =~ /Linux USG /)
                  # Ubiquiti Unifi USG
                  proof << ssh_socket.exec!("cat /etc/version\n").to_s.rstrip
                end
                temp_proof = ssh_socket.exec!("grep unifi.version /tmp/system.cfg\n").to_s.rstrip
                if (temp_proof =~ /unifi\.version/)
                  proof << temp_proof
                  # Ubiquiti Unifi device (non-USG), possibly a switch.  Tested on US-24, UAP-nanoHD
                  # The /tmp/*.cfg files don't give us device info, however the info command does
                  # we dont call it originally since it doesnt say unifi/ubiquiti in it and info
                  # is a linux command as well
                  proof << ssh_socket.exec!("grep board.name /etc/board.info\n").to_s.rstrip
                end
              else
                # Cisco IOS
                if proof =~ /Unknown command or computer name/
                  proof = ssh_socket.exec!("ver\n").to_s
                # Juniper ScreenOS
                elsif proof =~ /unknown keyword/
                  proof = ssh_socket.exec!("get chassis\n").to_s
                # Juniper JunOS CLI
                elsif proof =~ /unknown command: id/
                  proof = ssh_socket.exec!("show version\n").split("\n")[2..4].join(", ").to_s
                # Brocade CLI
                elsif proof =~ /Invalid input -> id/ || proof =~ /Protocol error, doesn't start with scp\!/
                  proof = ssh_socket.exec!("show version\n").to_s
                  if proof =~ /Version:(?<os_version>.+).+HW: (?<hardware>)/mi
                    proof = "Model: #{hardware}, OS: #{os_version}"
                  end
                # Arista
                elsif proof =~ /% Invalid input at line 1/
                  proof = ssh_socket.exec!("show version\n").split("\n")[0..1]
                  proof = proof.map {|item| item.strip}
                  proof = proof.join(", ").to_s
                # Windows
                elsif proof =~ /command not found|is not recognized as an internal or external command/
                  proof = ssh_socket.exec!("systeminfo\n").to_s
                  /OS Name:\s+(?<os_name>.+)$/ =~ proof
                  /OS Version:\s+(?<os_num>.+)$/ =~ proof
                  if os_num.present? && os_name.present?
                    proof = "#{os_name.strip} #{os_num.strip}"
                  else
                    proof = ssh_socket.exec!("ver\n").to_s.strip
                  end
                # mikrotik
                elsif proof =~ /bad command name id \(line 1 column 1\)/
                  proof = ssh_socket.exec!("/ system resource print\n").to_s
                  /platform:\s+(?<platform>.+)$/ =~ proof
                  /board-name:\s+(?<board>.+)$/ =~ proof
                  /version:\s+(?<version>.+)$/ =~ proof
                  if version && platform && board
                    proof = "#{platform.strip} #{board.strip} #{version.strip}"
                  end
                else
                  proof << ssh_socket.exec!("help\n?\n\n\n").to_s
                end
              end
            end
          rescue ::Exception
          end
          proof
        end

        def set_sane_defaults
          self.connection_timeout = 30 if self.connection_timeout.nil?
          self.port = DEFAULT_PORT if self.port.nil?
          self.verbosity = :fatal if self.verbosity.nil?
        end

        public

        def get_platform(proof)
          case proof
          when /unifi\.version|UniFiSecurityGateway/ #Ubiquiti Unifi.  uname -a is left in, so we got to pull before Linux
            'unifi'
          when /Linux/
            'linux'
          when /Darwin/
            'osx'
          when /SunOS/
            'solaris'
          when /BSD/
            'bsd'
          when /HP-UX/
            'hpux'
          when /AIX/
            'aix'
          when /cygwin|Win32|Windows|Microsoft/
            'windows'
          when /Unknown command or computer name|Line has invalid autocommand/
            'cisco-ios'
          when /unknown keyword/ # ScreenOS
            'juniper'
          when /JUNOS Base OS/ # JunOS
            'juniper'
          when /MikroTik/
            'mikrotik'
          when /Arista/
            'arista'
          else
            'unknown'
          end
        end

      end

    end
  end
end
