
# -*- coding: binary -*-



module Msf

  ###
  #
  # Payload that supports migration over DNS transports on x86.
  #
  ###

  module Payload::Windows::MigrateDns

    include Msf::Payload::Windows::MigrateCommon

    def initialize(info={})
      super(update_info(info,
                        'Name'        => 'DNS Transport Migration (x86)',
                        'Description' => 'Migration stub to use over DNS transports via x86',
                        'Author'      => ['Alexey Sintsov', 'Maksym Andriyanov'],
                        'License'     => MSF_LICENSE,
                        'Platform'    => 'win',
                        'Arch'        => ARCH_X86
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
