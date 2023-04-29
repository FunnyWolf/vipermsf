##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Gather Run Console Resource File',
        'Description' => %q{
          This module will read console commands from a resource file and
          execute the commands in the specified Meterpreter session.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ]
      )
    )
    register_options(
      [

        OptString.new('RESOURCE', [true, 'Full path to resource file to read commands from.', nil]),

      ]
    )
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")
    if !::File.exist?(datastore['RESOURCE'])
      raise 'Resource File does not exist!'
    else
      ::File.open(datastore['RESOURCE'], 'rb').each_line do |cmd|
        next if cmd.strip.empty?
        next if cmd[0, 1] == '#'

        begin
          print_status "Running command #{cmd.chomp}"
          session.console.run_single(cmd.chomp)
        rescue ::Exception => e
          print_status("Error Running Command #{cmd.chomp}: #{e.class} #{e}")
        end
      end
    end
  end
end
