#encoding=UTF-8
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Multi Generic Operating System Session Command Execution',
                      'Description'  => %q{ This module executes an arbitrary command line},
                      'License'      => MSF_LICENSE,
                      'Author'       => ['viper'],
                      'Platform'     => %w{ linux osx unix win },
                      'SessionTypes' => ['shell', 'meterpreter']
          ))
    register_options(
            [
                    OptString.new('COMMAND', [false, 'The command to execute on the session']),
                    OptString.new('ARGS', [false, 'The args of command '])

            ])
  end

  def run
    # print_status("Executing #{datastore['COMMAND']} on #{session.inspect}...")
    begin
      res = cmd_exec(datastore['COMMAND'], args = datastore['ARGS'])
      print("#{res}")
    rescue => e
      print_error("Error: Command -- #{datastore['COMMAND']} is nonsupport")
      print_error("#{e}")
    end
  end
end
