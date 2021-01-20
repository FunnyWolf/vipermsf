##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'base64'
require 'json'
require 'open-uri'
require 'yajl'
class MetasploitModule < Msf::Post
  include Post::Windows::Priv

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'registry operation atomic',
                      'Description'  => %q{ This module is an alias of meterpreter registry.
sometimes we need to use this func outside msf,so run it as module is comfortable},
                      'License'      => MSF_LICENSE,
                      'Author'       => ['viper'],
                      'Platform'     => ['win'],
                      'SessionTypes' => ['meterpreter']
          ))

    register_options(
            [
                    OptEnum.new('OPERATION', [true, 'type of opertaion', 'registry_createkey',
                                              ['registry_createkey',
                                               'registry_deletekey',
                                               'registry_enumkeys',
                                               'registry_key_exist',
                                               'registry_enumvals',
                                               'registry_deleteval',
                                               'registry_getvaldata',
                                               'registry_getvalinfo',
                                               'registry_setvaldata'
                                              ]]),
                    OptString.new('KEY', [false, 'sessions dir path (list,upload,destory_dir)',]),
                    OptString.new('VALNAME', [false, 'sessions dir path (list,upload,destory_dir)',]),
                    OptString.new('DATA', [false, 'sessions dir path (list,upload,destory_dir)',]),
                    OptString.new('TYPE', [false, 'sessions dir path (list,upload,destory_dir)',]),
                    OptInt.new('VIEW', [false, 'sessions dir path (list,upload,destory_dir)', 0]),

            ])
  end

  # Run Method for when run command is issued
  def run
    result = {:status => true, :message => nil, :data => nil}
    unless session.platform == "windows"
      result[:status]  = false
      result[:message] = 'linux did not have registry'
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
      return
    end
    operation = datastore['OPERATION']
    key       = datastore['KEY']
    valname   = datastore['VALNAME']
    data      = datastore['DATA']
    type      = datastore['TYPE']
    view      = datastore['VIEW']

    if operation == 'registry_createkey'
      opeartion_result = registry_createkey(key, view)
      result[:data]    = opeartion_result
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    elsif operation == 'registry_deletekey'
      opeartion_result = registry_deletekey(key, view)
      result[:data]    = opeartion_result
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    elsif operation == 'registry_enumkeys'
      opeartion_result = registry_enumkeys(key, view)
      result[:data]    = opeartion_result
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    elsif operation == 'registry_key_exist'
      opeartion_result = registry_key_exist?(key)
      result[:data]    = opeartion_result
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    elsif operation == 'registry_enumvals'
      opeartion_result = registry_enumvals(key, view)
      result[:data]    = opeartion_result
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    elsif operation == 'registry_deleteval'
      opeartion_result = registry_deleteval(key, valname, view)
      result[:data]    = opeartion_result
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    elsif operation == 'registry_getvaldata'
      opeartion_result = registry_getvaldata(key, valname, view)
      result[:data]    = opeartion_result
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    elsif operation == 'registry_getvalinfo'
      opeartion_result = registry_getvalinfo(key, valname, view)
      result[:data]    = opeartion_result
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    elsif operation == 'registry_setvaldata'
      opeartion_result = registry_setvaldata(key, valname, data, type, view)
      result[:data]    = opeartion_result
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    else
      result[:status]  = false
      result[:message] = 'unknown operation'
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    end
  end
end
