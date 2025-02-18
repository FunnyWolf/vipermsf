# -*- coding: binary -*-
require 'redis'
require 'net/http'
require 'uri'
require 'oj'
module Msf::Module::Rpcredis
  attr_accessor :redis_client

  def self.init
    @@redis_client = self.init_redis_client
    @@message_queue = "rpcviper"
  end

  def self.init_redis_client
    file = "/root/.msf4/redis.yml"

    begin
      if ::File.exist? file
        redis_conf = YAML.load(::File.read(file))
        redis_client = Redis.new(path: redis_conf['redis_sock'], password: redis_conf['redis_password'], db: 5)
      else
        redis_client = Redis.new(path: "/var/run/redis/redis-server.sock", password: 'foobared', db: 5)
      end
      return redis_client
    rescue => e
      print_error("There was an error init redis: #{e.message}.", e)
    end
  end

  def self.json_dump(data)
    json = Oj.dump(data, mode: :custom, allow_invalid_unicode: true)
    json = json.encode("UTF-8", invalid: :replace, undef: :replace)
    json = Oj.load(json, symbol_keys: false)
    json = Oj.dump(json, mode: :custom, allow_invalid_unicode: true)
    json
  end

  def json_dump(data)
    json = Oj.dump(data, mode: :custom, allow_invalid_unicode: true)
    json = json.encode("UTF-8", invalid: :replace, undef: :replace)
    json = Oj.load(json, symbol_keys: false)
    json = Oj.dump(json, mode: :custom, allow_invalid_unicode: true)
    json
  end

  def pub_json_result(status = nil, message = nil, data = nil, uuid = nil)
    result = {}
    result[:uuid] = uuid
    result[:status] = status
    result[:message] = message
    result[:data] = data
    json = Msf::Module::Rpcredis.json_dump(result)

    flag = @@redis_client.publish "MSF_RPC_RESULT_CHANNEL", json
  end

  def pub_json_data(status = nil, message = nil, data = nil, uuid = nil)
    result = {}
    result[:uuid] = uuid
    result[:status] = status
    result[:message] = message
    result[:data] = data
    json = Msf::Module::Rpcredis.json_dump(result)
    flag = @@redis_client.publish "MSF_RPC_DATA_CHANNEL", json
  end

  def self.pub_heartbeat_data(status = nil, type = nil, data = nil)
    result = {}
    result[:status] = status
    result[:type] = type
    result[:data] = data
    json = Msf::Module::Rpcredis.json_dump(result)
    flag = @@redis_client.publish "MSF_RPC_HEARTBEAT_CHANNEL", json
    if flag != 1
      dlog("pub_heartbeat_data num: #{flag}")
    end
    flag
  end

  def pub_console_print(prompt = nil, message = nil)
    result = {}
    result[:prompt] = prompt
    result[:message] = message
    json = Msf::Module::Rpcredis.json_dump(result)
    flag = @@redis_client.publish "MSF_RPC_CONSOLE_PRINT", json
  end

  def print_good_redis(content)
    result = {}
    result[:level] = 0
    result[:content] = content
    json = Msf::Module::Rpcredis.json_dump(result)
    flag = @@redis_client.publish "MSF_RPC_LOG_CHANNEL", json

  end

  def print_status_redis(content)
    result = {}
    result[:level] = 1
    result[:content] = content
    json = Msf::Module::Rpcredis.json_dump(result)
    flag = @@redis_client.publish "MSF_RPC_LOG_CHANNEL", json
  end

  def print_warning_redis(content)
    result = {}
    result[:level] = 2
    result[:content] = content
    json = Msf::Module::Rpcredis.json_dump(result)
    flag = @@redis_client.publish "MSF_RPC_LOG_CHANNEL", json
  end

  def print_error_redis(content)
    result = {}
    result[:level] = 3
    result[:content] = content
    json = Msf::Module::Rpcredis.json_dump(result)
    flag = @@redis_client.publish "MSF_RPC_LOG_CHANNEL", json
  end

  def redis_rpc_call(method_name, timeout = 0.5, **kwargs)
    dlog("redis_rpc_call #{method_name}")
    # request setup
    function_call = { 'function' => method_name.to_s, 'kwargs' => kwargs }
    response_queue = @@message_queue + ':rpc:' + Rex::Text.rand_text_alpha(32)
    rpc_request = { 'function_call' => function_call, 'response_queue' => response_queue }
    rpc_raw_request = Msf::Module::Rpcredis.json_dump(rpc_request)
    # transport
    @@redis_client.rpush @@message_queue, rpc_raw_request
    message_queue, rpc_raw_response = @@redis_client.blpop response_queue, timeout
    if rpc_raw_response.nil?
      @@redis_client.lrem @@message_queue, 0, rpc_raw_request
      return
    end
    # response handling
    rpc_raw_response = rpc_raw_response.encode("UTF-8", invalid: :replace, undef: :replace)
    rpc_response = Oj.load(rpc_raw_response, allow_invalid_unicode: true)
    return rpc_response
  end

  # Raises an Msf::RPC Exception.
  #
  # @param [Integer] code The error code to raise.
  # @param [String] message The error message.
  # @raise [Msf::RPC::Exception]
  # @return [void]
  def error(code, message)
    raise Msf::RPC::Exception.new(code, message)
  end
end


