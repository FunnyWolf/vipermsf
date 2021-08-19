##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Windows Gather Installed Application Enumeration',
                      'Description'  => %q{ This module will enumerate all installed applications on a Windows system },
                      'License'      => MSF_LICENSE,
                      'Author'       => ['Carlos Perez <carlos_perez[at]darkoperator.com>'],
                      'Platform'     => ['win'],
                      'SessionTypes' => ['meterpreter']
          ))

  end

  def app_list
    tbl     = Rex::Text::Table.new(
            'Header'  => "Installed Applications",
            'Indent'  => 1,
            'Columns' =>
                    [
                            "Name",
                            "Version"
                    ])
    appkeys = [
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
            'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
            'HKLM\\SOFTWARE\\WOW6432NODE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
            'HKCU\\SOFTWARE\\WOW6432NODE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
    ]
    apps    = []
    appkeys.each do |keyx86|
      found_keys = registry_enumkeys(keyx86)
      if found_keys
        found_keys.each do |ak|
          apps << keyx86 + "\\" + ak
        end
      end
    end

    t = []
    while (not apps.empty?)

      1.upto(16) do
        t << framework.threads.spawn("Module(#{self.refname})", false, apps.shift) do |k|
          begin
            dispnm      = registry_getvaldata("#{k}", "DisplayName")
            dispversion = registry_getvaldata("#{k}", "DisplayVersion")
            tbl << [dispnm, dispversion] if dispnm and dispversion
          rescue
          end
        end

      end
      t.map { |x| x.join }
    end

    results = tbl.to_s
    pub_json_result(true,
                    nil,
                    results,
                    self.uuid)

  end

  def run
    app_list
  end
end
