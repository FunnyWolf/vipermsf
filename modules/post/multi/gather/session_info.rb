# -*- coding: UTF-8 -*-
require 'json'
require 'yajl'
require 'msf/core/post/windows/accounts'


class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Accounts
  include Msf::Post::Linux::Priv


  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Base session information Gather',
                      'Description'  => %q{ This module will get base session information using a Meterpreter session.},
                      'License'      => MSF_LICENSE,
                      'Author'       => ['viper'],
                      'Arch'         => [ARCH_X86, ARCH_X64],
                      'Platform'     => ['win', 'linux'],
                      'SessionTypes' => ['meterpreter']
          ))
    register_options(
            [

                    OptBool.new('RIGHTINFO', [false, 'get session UAC info', false]),
                    OptBool.new('UACINFO', [false, 'get session UAC info', false]),
                    OptBool.new('PINFO', [false, 'get session process info', false]),
                    OptInt.new('TIMEOUT', [true, 'Timeout in seconds for get info depand reg.', 10]),
            ])

  end

  # Run Method for when run command is issued
  def run
    @result = {:job_id => self.job_id, :uuid => self.uuid, :status => true, :message => nil, :data => nil, }
    if session.type == "shell"
      @result[:status]  = false
      @result[:message] = 'Unsupport shell type'
      json              = Yajl::Encoder.encode(result)
      json              = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
      return
    end
    info = {}
    if session.platform == "windows"
      # info about right
      if datastore['RIGHTINFO']
        begin
          Timeout.timeout(datastore['TIMEOUT']) do
            info["IS_UAC_ENABLE"] = is_uac_enabled?
            info["UAC_LEVEL"]     = get_uac_level
            info["IS_ADMIN"]      = nil
            info["TEMP"]          = get_env('TEMP').gsub(/\\/, '/')
          end
        rescue => e
          print_error_redis("Get RIGHTINFO : " + e.to_s)
          info["IS_UAC_ENABLE"] = nil
          info["UAC_LEVEL"]     = -1
          info["IS_ADMIN"]      = nil
          info["TEMP"]          = nil
        end
      else
        info["IS_UAC_ENABLE"] = nil
        info["UAC_LEVEL"]     = -1
        info["IS_ADMIN"]      = nil
        info["TEMP"]          = nil
      end
      # info about uac
      if datastore['UACINFO']
        begin
          Timeout.timeout(datastore['TIMEOUT']) do
            info["INTEGRITY"] = nil
            whoami            = get_whoami
            if whoami.nil?
              info["IS_IN_ADMIN_GROUP"] = nil
              info["INTEGRITY"]         = nil
            end
            if whoami.include? ADMINISTRATORS_SID
              info["IS_IN_ADMIN_GROUP"] = true
            end
            INTEGRITY_LEVEL_SID.each_pair do |k, sid|
              if whoami.include? sid
                info["INTEGRITY"] = sid
              end
            end
          end
        rescue => e
          print_error_redis("Get UACINFO : " + e.to_s)
          info["IS_IN_ADMIN_GROUP"] = nil
          info["INTEGRITY"]         = nil
        end
      else
        info["IS_IN_ADMIN_GROUP"] = nil
        info["INTEGRITY"]         = nil
      end
    else
      info["IS_IN_ADMIN_GROUP"] = false
      info["IS_ADMIN"]          = false
      info["IS_UAC_ENABLE"]     = false
      info["UAC_LEVEL"]         = 0
      info["INTEGRITY"]         = 'S-1-16-4096'
      info["TEMP"]              = '/tmp'
    end
    if datastore['PINFO']
      begin
        Timeout.timeout(datastore['TIMEOUT'] * 2) do
          pid       = session.sys.process.getpid
          processes = session.sys.process.processes
          processes.each do |process|
            if pid == process['pid']
              info["PID"]   = pid
              info["PNAME"] = process['name']
              info["PPATH"] = process['path']
              info["PUSER"] = process['user']
              info["PARCH"] = process['arch']
            end
          end
          info["PROCESSES"] = processes
        end
      rescue => e

        print_error_redis("Get PINFO : " + e.to_s)
        info["PID"]       = nil
        info["PNAME"]     = nil
        info["PPATH"]     = nil
        info["PUSER"]     = nil
        info["PARCH"]     = nil
        info["PROCESSES"] = []
      end
    else
      info["PID"]       = nil
      info["PNAME"]     = nil
      info["PPATH"]     = nil
      info["PUSER"]     = nil
      info["PARCH"]     = nil
      info["PROCESSES"] = []
    end
    @result[:data] = info
    json           = Yajl::Encoder.encode(@result)
    json           = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    print("#{json}")
  end
end
