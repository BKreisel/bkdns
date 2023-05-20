
mod packet;

// Use Quad9 if no nameserver specified
const DEFAULT_NAMESERVER: &str = "9.9.9.9";

fn main() {
   if !(2..=3).contains(&std::env::args().len()) {
        println!("usage: {} domain_name [nameserver_ip]", std::env::args().nth(0).unwrap());
        return;
   }
   
   let sock = std::net::UdpSocket::bind("0.0.0.0:0")
     .expect("Failed to bind UDP source socket");

    let domain = std::env::args().nth(1).unwrap();

    let nameserver = format!(
        "{}:53",
        match std::env::args().len() {
            3 => std::env::args().nth(2).unwrap(),
            _ => String::from(DEFAULT_NAMESERVER),
        }
    );

   println!("Asking {} to resolve {}", nameserver, domain);
   sock.connect(nameserver)
     .expect("Upstream UDP connection failed to nameserver");

   let mut packet = packet::DNSPacket::new();
   packet.add_question(packet::DNSQuestion::new(domain, packet::RecordType::A));
   packet.header.flags.recurse_desired = true;

   sock.send(&packet.serialize())
        .expect("Failed to send DNS Packet");

   let mut buf =  [0; 1024];
   sock.recv(&mut buf)
     .expect("No response from DNS Server");

   let response = packet::DNSPacket::deserialize(&buf)
     .expect("Failed to parse response");

    println!("{:?}", response.header);
}