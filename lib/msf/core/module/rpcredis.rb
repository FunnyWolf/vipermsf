# -*- coding: binary -*-
require "redis"
require 'yajl'
module Msf::Module::Rpcredis
  attr_accessor :redis_client

  # Initializes framework, service, tokens, and users
  #
  # return [void]
  # def initialize()
  #   @@client = Redis.new(host: "127.0.0.1", password: 'foobared', port: 6379, db: 5)
  # end
  def redis_client
    file = ::File.join(Msf::Config.get_config_root, "redis.yml")
    if ::File.exist? file
      redis_conf     = YAML.load(::File.read(file))
      @@redis_client = Redis.new(path: redis_conf['redis_sock'], password: redis_conf['redis_password'], db: 5)
    else
      @@redis_client = Redis.new(host: "127.0.0.1", password: 'foobared', port: 60004, db: 5)
    end
    return @@redis_client
  end

  def pub_json_result(status = nil, message = nil, data = nil, uuid = nil)
    result           = {}
    result[:uuid]    = uuid
    result[:status]  = status
    result[:message] = message
    result[:data]    = data
    json             = Yajl::Encoder.encode(result)
    json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    @@redis_client   = self.redis_client
    flag             = @@redis_client.publish "MSF_RPC_RESULT_CHANNEL", json
    print("#{json}")
  end

  def pub_json_data(status = nil, message = nil, data = nil, uuid = nil)
    result           = {}
    result[:uuid]    = uuid
    result[:status]  = status
    result[:message] = message
    result[:data]    = data
    json             = Yajl::Encoder.encode(result)
    json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    @@redis_client   = self.redis_client
    flag             = @@redis_client.publish "MSF_RPC_DATA_CHANNEL", json
    print("#{json}")
  end

  def print_good_redis(content)
    log            = {}
    log[:level]    = 0
    log[:content]  = content
    json           = Yajl::Encoder.encode(log)
    json           = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    @@redis_client = self.redis_client
    flag           = @@redis_client.publish "MSF_RPC_LOG_CHANNEL", json
  end

  def print_status_redis(content)
    log            = {}
    log[:level]    = 1
    log[:content]  = content
    json           = Yajl::Encoder.encode(log)
    json           = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    @@redis_client = self.redis_client
    flag           = @@redis_client.publish "MSF_RPC_LOG_CHANNEL", json

  end

  def print_warning_redis(content)
    log            = {}
    log[:level]    = 2
    log[:content]  = content
    json           = Yajl::Encoder.encode(log)
    json           = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    @@redis_client = self.redis_client
    flag           = @@redis_client.publish "MSF_RPC_LOG_CHANNEL", json
  end

  def print_error_redis(content)
    log            = {}
    log[:level]    = 3
    log[:content]  = content
    json           = Yajl::Encoder.encode(log)
    json           = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    @@redis_client = self.redis_client
    flag           = @@redis_client.publish "MSF_RPC_LOG_CHANNEL", json
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


