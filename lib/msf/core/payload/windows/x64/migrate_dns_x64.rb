
# -*- coding: binary -*-

module Msf

  ###
  #
  # Payload that supports migration over DNS transports on x64.
  #
  ###

  module Payload::Windows::MigrateDns_x64

    include Msf::Payload::Windows::MigrateCommon_x64

    def initialize(info={})
      super(update_info(info,
                        'Name'        => 'DNS Transport Migration (x64)',
                        'Description' => 'Migration stub to use over DNS transports via x64',
                        'Author'      => ['Alexey Sintsov', 'Maksym Andriyanov'],
                        'License'     => MSF_LICENSE,
                        'Platform'    => 'win',
                        'Arch'        => ARCH_X64
            ))
    end

    #
    # Constructs the migrate stub on the fly
    #
    def generate_migrate(opts={})
      # This payload only requires the common features, so return
      # an empty string indicating no code requires.
      ''
    end

  end

end
