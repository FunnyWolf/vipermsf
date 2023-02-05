# toybox
require 'sinatra/base'
require 'uri'

require 'metasploit/framework/data_service/remote/http/core'

module Msf::WebServices
  # Extension provides a Metasploit Framework instance to a Sinatra application.
  # The framework instance is stored with the setting name framework and is
  # also accessible via the framework helper method. If the data service URL
  # environment variable is set, then the framework instance will be configured
  # to use the data service rather than the local database.
  #
  # Environment Variables:
  # MSF_WS_DATA_SERVICE_URL - The data service URL.
  # MSF_WS_DATA_SERVICE_API_TOKEN - API token used to authenticate to the remote data service.
  # MSF_WS_DATA_SERVICE_CERT - Certificate file matching the remote data server's certificate.
  #                            Needed when using self-signed SSL certificates.
  # MSF_WS_DATA_SERVICE_SKIP_VERIFY - (Boolean) Skip validating authenticity of server's certificate.
  # MSF_WS_DATA_SERVICE_LOGGER - (String) The logger that framework will use. By default logs will be
  #                             placed in `~/.msf4/logs`
  module FrameworkExtension
    FALSE_VALUES = [nil, false, 0, '0', 'f', 'false', 'off', 'no'].to_set

    module Helpers
      # Get framework instance from settings.
      def framework
        settings.framework
      end

      def get_db
        framework.db
      end
    end

    def self.registered(app)
      app.helpers FrameworkExtension::Helpers

      app.set :data_service_url, ENV.fetch('MSF_WS_DATA_SERVICE_URL', nil)
      app.set :data_service_api_token, ENV.fetch('MSF_WS_DATA_SERVICE_API_TOKEN', nil)
      app.set :data_service_cert, ENV.fetch('MSF_WS_DATA_SERVICE_CERT', nil)
      app.set :data_service_skip_verify, to_bool(ENV.fetch('MSF_WS_DATA_SERVICE_SKIP_VERIFY', false))

      @@framework = nil
      # Create simplified instance of the framework
      app.set :framework, (proc {
        @@framework ||= begin
          init_framework_opts = {
            'Logger' => ENV.fetch('MSF_WS_DATA_SERVICE_LOGGER', nil),
            # SkipDatabaseInit false is the default behavior, however for explicitness - note that framework first
            # connects to a local database as a pre-requisite to connecting to a remote service to correctly
            # configure active record
            'SkipDatabaseInit' => true
          }
          framework = Msf::Simple::Framework.create(init_framework_opts)
          Msf::WebServices::FrameworkExtension.db_connect(framework, app)
          framework.threads.spawn("viper_monitor", false) {
            loop do
              res_jobs = {}
              framework.jobs.each do |k, j|
                # toybox
                res_jobs[k] = { 'name' => j.name,
                                'start_time' => j.start_time.to_i
                }
                res_jobs[k][:uuid] = j.ctx[0].uuid
                if j.ctx && j.ctx[0]
                  modint = j.ctx[0]
                  if modint.respond_to?(:get_resource)
                    res_jobs[k][:uripath] = modint.get_resource
                  end
                  if modint.respond_to?(:datastore)
                    tmpdatastore = modint.datastore
                    tmpdatastore.delete('LocalInput')
                    tmpdatastore.delete('LocalOutput')
                    res_jobs[k]["datastore"] = tmpdatastore.user_defined
                  end
                end
              end

              res_sessions = {}
              # toybox
              framework.sessions.each do |sess|
                i, s = sess

                res_sessions[s.sid] = {
                  'type' => s.type.to_s,
                  'tunnel_local' => s.tunnel_local.to_s,
                  'tunnel_peer' => s.tunnel_peer.to_s,
                  'comm_channel_session' => s.comm_channel_session,
                  'via_exploit' => s.via_exploit.to_s,
                  'via_payload' => s.via_payload.to_s,
                  'desc' => s.desc.to_s,
                  'info' => s.info.to_s,
                  'workspace' => s.workspace.to_s,
                  'session_host' => s.session_host.to_s,
                  'session_port' => s.session_port.to_i,
                  'target_host' => s.target_host.to_s,
                  'username' => s.username.to_s,
                  'uuid' => s.uuid.to_s,
                  'exploit_uuid' => s.exploit_uuid.to_s,
                  'routes' => s.routes,
                  'arch' => s.arch.to_s,
                  'name' => s.name,
                }

                if s.type.to_s == "meterpreter"
                  res_sessions[s.sid]['platform'] = s.platform.to_s
                  res_sessions[s.sid]['advanced_info'] = s.advanced_info
                  res_sessions[s.sid]['load_powershell'] = s.ext.aliases.has_key?('powershell')
                  res_sessions[s.sid]['load_python'] = s.ext.aliases.has_key?('python')
                else
                  res_sessions[s.sid]['platform'] = nil
                  res_sessions[s.sid]['advanced_info'] = {}
                end
                if s.respond_to?(:last_checkin) && s.last_checkin
                  res_sessions[s.sid]['last_checkin'] = s.last_checkin.to_i
                else
                  res_sessions[s.sid]['last_checkin'] = 0
                end
              end

              # Accept a client connection
              pub_heartbeat_data(true,
                                 "HEARTBEAT",
                                 {
                                   "jobs" => res_jobs,
                                   "sessions" => res_sessions
                                 })
              Rex.sleep(0.5)
            end
          }
          framework
        end
      })
    end

    def self.db_connect(framework, app)
      if !app.settings.data_service_url.nil? && !app.settings.data_service_url.empty?
        options = {
          url: app.settings.data_service_url,
          api_token: app.settings.data_service_api_token,
          cert: app.settings.data_service_cert,
          skip_verify: app.settings.data_service_skip_verify
        }
        db_result = Msf::DbConnector.db_connect(framework, options)
      else
        db_result = Msf::DbConnector.db_connect_from_config(framework)
      end

      if db_result[:error]
        raise db_result[:error]
      end
    end

    private

    def self.to_bool(value)
      if value.is_a?(String)
        value = value.downcase
      end

      !FALSE_VALUES.include?(value)
    end
  end
end
