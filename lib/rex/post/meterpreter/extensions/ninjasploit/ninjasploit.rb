# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/ninjasploit/tlv'
require 'rex/post/meterpreter/extensions/ninjasploit/command_ids'

module Rex
module Post
module Meterpreter
module Extensions
module Ninjasploit

class Ninjasploit < Extension

  def self.extension_id
    EXTENSION_ID_NINJASPLOIT
  end

  def initialize(client)
    super(client, 'Ninjasploit')

    client.register_extension_aliases(
      [
        {
          'name' => 'Ninjasploit',
          'ext'  => self
        },
      ])
  end

  def install_hooks
    request = Packet.create_request(COMMAND_ID_NINJASPLOIT_INSTALL_HOOK)

    response = client.send_request(request)

    response.get_tlv_value(TLV_TYPE_NINJASPLOIT_INSTALL_HOOKS)
  end

  def restore_hooks
    request = Packet.create_request(COMMAND_ID_NINJASPLOIT_RESTORE_HOOK)

    response = client.send_request(request)

    response.get_tlv_value(TLV_TYPE_NINJASPLOIT_RESTORE_HOOKS)
  end

end

end
end
end
end
end
