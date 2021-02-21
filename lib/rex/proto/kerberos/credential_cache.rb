# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module CredentialCache
        VERSION = 0x0504
        HEADER = "\x00\x08\xff\xff\xff\xff\x00\x00\x00\x00"
      end
    end
  end
end

require 'rex/proto/kerberos/credential_cache/cache'
