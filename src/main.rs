use std::net::UdpSocket;

const UPSTREAM: &str = "9.9.9.9:53";

enum RecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
}

impl RecordType {
    pub fn value(&self) -> u16 {
       match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
       } 
    }
}

enum RecordClass {
    IN,
}

impl RecordClass {
    pub fn value(&self) -> u16 {
       match self {
            RecordClass::IN => 1,
       } 
    }
}

struct DNSHeader {
    id: u16,
    flags: u16,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl DNSHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.question_count.to_be_bytes());
        bytes.extend_from_slice(&self.answer_count.to_be_bytes());
        bytes.extend_from_slice(&self.authority_count.to_be_bytes());
        bytes.extend_from_slice(&self.additional_count.to_be_bytes());
        return bytes;
    }
}

struct DNSQuestion {
    name: Vec<u8>,
    qtype: RecordType,
    class: RecordClass,
}

impl DNSQuestion {
    pub fn new(name: &str, qtype: RecordType) -> Self {
        let mut name_bytes: Vec<u8> = Vec::new();
        let parts: Vec<String> = name.split(".").map(|x| x.to_owned()).collect();

        for part in parts.iter() {
            name_bytes.push(part.len() as u8);
            for chr in part.chars() {
                name_bytes.push(chr.to_ascii_lowercase() as u8);
            }
        }
        name_bytes.push(0);

        DNSQuestion {
            name: name_bytes,
            qtype,
            class: RecordClass::IN,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(self.name.as_slice());
        bytes.extend_from_slice(&self.qtype.value().to_be_bytes());
        bytes.extend_from_slice(&self.class.value().to_be_bytes());
        return bytes;
    }
}

struct DNSPacket {
    questions: Vec<DNSQuestion>,
}

impl DNSPacket {
    pub fn serialize(&self) -> Vec<u8> {
        let header = DNSHeader {
            id: rand::random::<u16>(),
            flags: 256,
            question_count: self.questions.len() as u16,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        };
        let mut bytes: Vec<u8> = Vec::from(header.to_bytes());
        for question in self.questions.iter() {
            bytes.extend_from_slice(question.to_bytes().as_slice());
        }
       return bytes; 
    }
}

fn main() {
   let args: Vec<String> = std::env::args().collect();
   if args.len() != 2 {
        println!("usage: {} domain_name", args.first().unwrap());
        return;
   }
   
   let sock = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind UDP Socket");
   sock.connect(UPSTREAM).expect("Upstream UDP connection failed");

   let packet = DNSPacket {
        questions:  Vec::from([DNSQuestion::new(args.get(1).unwrap(), RecordType::A)]),
   };

   sock.send(&packet.serialize()).expect("Failed to send DNS Packet");

   let mut buf =  [0; 1024];
   sock.recv(&mut buf).expect("No response from DNS Server");


   println!("{:?}", buf);

}

#[cfg(test)]
mod tests {
    use crate::{DNSHeader, DNSQuestion, RecordType};
    use hex_literal::hex;

    #[test]
    fn header_serialization() {
        let header = DNSHeader {
            id: 0x1314,
            flags: 0,
            question_count: 1, 
            answer_count: 0, 
            authority_count: 0, 
            additional_count: 0, 
        };
        assert_eq!(header.to_bytes(), hex!("13 14 00 00 00 01 00 00 00 00 00 00"));
    }

    #[test]
    fn question_serialization() {
        let question = DNSQuestion::new("example.com", RecordType::A);
        assert_eq!(question.to_bytes(), hex!("07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01"));
    }
}