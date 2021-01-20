# toybox
module Msf::WebServices::Authentication
  module Strategies
    class ApiToken < Warden::Strategies::Base
      AUTHORIZATION = 'HTTP_AUTHORIZATION'
      AUTHORIZATION_SCHEME = 'Bearer'
      TOKEN_QUERY_PARAM = 'token'

      # Check if request contains valid data and should be authenticated.
      # @return [Boolean] true if strategy should be run for the request; otherwise, false.
      def valid?
        auth_initialized = request.env['msf.auth_initialized']
        authorization = request.env[AUTHORIZATION]
        !auth_initialized || (authorization.is_a?(String) && authorization.start_with?(AUTHORIZATION_SCHEME)) || !params[TOKEN_QUERY_PARAM].nil?
      end

      # Authenticate the request.
      def authenticate!
        auth_initialized = request.env['msf.auth_initialized']
        authorization = request.env[AUTHORIZATION]
        if !auth_initialized
          success!({message: "Initialize authentication by creating an initial user account."})
        else
          if authorization.is_a?(String) && authorization.start_with?(AUTHORIZATION_SCHEME)
            token = authorization.sub(/^#{AUTHORIZATION_SCHEME}\s+/, '')
          else
            token = params[TOKEN_QUERY_PARAM]
          end
	  # toybox
          if env['msf.user_token'] == nil
            throw(:warden, message: "Invalid API token.", code: 401)
          else

            user_token = env['msf.user_token']
            if user_token['token'] == token
              success!("json_rpc")
            else
              throw(:warden, message: "Invalid API token.", code: 401)
            end
          end
        end
      end

      # Validates the user associated with the API token.
      #
      # @return [Hash] User validation data
      # @option :valid [Boolean] True if the user is valid; otherwise, false.
      # @option :code [Integer] 0 if the user is valid; otherwise, a non-zero strategy failure code.
      # @option :message [String] strategy failure message
      def validate_user(user)
        !user.nil? ? {valid: true, code: 0, message: nil} : {valid: false, code: 401, message: "Invalid API token."}
      end

      # Authenticates the API token from an environment variable
      def auth_from_env(token)
        if token == request.env['msf.api_token']
          success!(message: "Successful auth from token")
        else
          throw(:warden, message: 'Invalid API token.', code: 401)
        end
      end
    end
  end
end
