// Record Class will always be Internet/IN/1
const RECORD_CLASS: u16 = 1;

const HEADER_SIZE: usize = std::mem::size_of::<u16>() * 6; // bytes

#[derive(Debug, PartialEq)]
pub struct DNSFlags {
    pub is_response: bool,
    pub opcode: u8,
    pub is_authoritative: bool,
    pub is_truncated: bool,
     pub recurse_desired: bool,
     pub recurse_available: bool,
     pub answer_authed: bool,
     pub unauth_ok: bool,
     pub reply_code: u8,
}

impl DNSFlags {
    pub fn default() -> Self {
        DNSFlags {
            is_response: false,
            opcode: 0,
            is_authoritative: false,
            is_truncated: false,
            recurse_desired: false,
            recurse_available: false,
            answer_authed: false,
            unauth_ok: false,
            reply_code: 0,
        }
    }
}

/*  Example 
Flags: 0x8580 Standard query response, No error
        1... .... .... .... = Response: Message is a response
        .000 0... .... .... = Opcode: Standard query (0)
        .... .1.. .... .... = Authoritative: Server is an authority for domain
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... 1... .... = Recursion available: Server can do recursive queries
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
        .... .... ...0 .... = Non-authenticated data: Unacceptable
        .... .... .... 0000 = Reply code: No error (0)
    */

impl DNSFlags {
    pub fn serialize(&self) -> u16 {
        let mut flags: u16 = 0;
        flags |= (self.is_response as u16) << 15;  
        flags |= ((self.opcode & 0xF) as u16) << 11; // shift over lower 4 bits
        flags |= (self.is_authoritative as u16) << 10;  
        flags |= (self.is_truncated as u16) << 9;  
        flags |= (self.recurse_desired as u16) << 8;  
        flags |= (self.recurse_available as u16) << 7;  
        //reserved at 6
        flags |= (self.answer_authed as u16) << 5;  
        flags |= (self.unauth_ok as u16) << 4;  
        flags |= (self.reply_code & 0xF) as u16; // keep lower 4 bits
        flags
    }

    pub fn from(uint16: u16) -> Self {
        DNSFlags {
            is_response: (uint16 & 0x8000) > 0, 
            opcode: ((uint16 & 0x7800) >> 11) as u8,
            is_authoritative: (uint16 & 0x400 ) > 0,
            is_truncated: (uint16 & 0x200 ) > 0,
            recurse_desired: (uint16 & 0x100 ) > 0,
            recurse_available: (uint16 & 0x80 ) > 0,
            answer_authed: (uint16 & 0x20 ) > 0,
            unauth_ok: (uint16 & 0x10 ) > 0,
            reply_code: (uint16 & 0xF) as u8,
        }
    }
}

pub enum RecordType {
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

#[derive(Debug)]
pub struct DNSHeader {
    id: u16,
    pub flags: DNSFlags,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl DNSHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(HEADER_SIZE);
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.serialize().to_be_bytes());
        bytes.extend_from_slice(&self.question_count.to_be_bytes());
        bytes.extend_from_slice(&self.answer_count.to_be_bytes());
        bytes.extend_from_slice(&self.authority_count.to_be_bytes());
        bytes.extend_from_slice(&self.additional_count.to_be_bytes());
        bytes
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_SIZE {
            return Err(format!(
                "Failed to parse header. Expected {} bytes, got: {}", HEADER_SIZE, bytes.len()
            ));
        }

        Ok(DNSHeader {
            id: u16::from_be_bytes(bytes[0..2].try_into().unwrap()),
            flags: DNSFlags::from(u16::from_be_bytes(bytes[2..4].try_into().unwrap())),
            question_count: u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
            answer_count: u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
            authority_count: u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
            additional_count: u16::from_be_bytes(bytes[10..12].try_into().unwrap()),
        })
    }
}

pub struct DNSQuestion {
    name: String,
    qtype: RecordType,
}

impl DNSQuestion {
    pub fn new(name: String, qtype: RecordType) -> Self {
        DNSQuestion { name, qtype }
    }

    pub fn serialize(&self) -> Vec<u8> {
        // 6 u16 fields (2 bytes)
        let name_bytes = serialize_dns_str(self.name.as_str());
        let mut bytes: Vec<u8> = Vec::with_capacity(2 * 2 + name_bytes.len());
        bytes.extend_from_slice(name_bytes.as_slice());
        bytes.extend_from_slice(&self.qtype.value().to_be_bytes());
        bytes.extend_from_slice(&RECORD_CLASS.to_be_bytes());
        bytes
    }
}

pub fn serialize_dns_str(dns_str: &str) -> Vec<u8> {
    let parts: Vec<String> = dns_str.split(".")
                                .map(|x| x.to_owned())
                                .collect();
    let parts_len: usize = parts.iter()
                        .map(|x| x.len())
                        .sum();
    /* Size is:
        * 1 byte per "part" (anything period separated)
        * 1 byte for the null terminator
        * The number of characters in each part (ASCII encodes to 1 byte each)
     */ 
    let mut bytes: Vec<u8> = Vec::with_capacity(parts.len() + 1 + parts_len);
    for part in parts.iter() {
        bytes.push(part.len() as u8);
        for chr in part.chars() {
            bytes.push(chr.to_ascii_lowercase() as u8);
        }
    }
    bytes.push(0); // null terminator
    bytes
}

pub struct DNSPacket {
    pub header: DNSHeader,
    questions: Vec<DNSQuestion>,
}

impl DNSPacket {

    pub fn new() -> Self {
        DNSPacket {
            header: DNSHeader {
                id: rand::random::<u16>(),
                flags: DNSFlags::default(),
                question_count: 0,
                answer_count: 0,
                authority_count: 0,
                additional_count: 0,
            },
            questions: Vec::new(),
        }
    }

    pub fn add_question(&mut self, question: DNSQuestion) {
        self.questions.push(question);
        self.header.question_count += 1;
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::from(self.header.serialize());
        for question in self.questions.iter() {
            bytes.extend_from_slice(&question.serialize().as_slice());
        }
       bytes
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        let mut read_count: usize = 0;
        if read_count + bytes.len() < HEADER_SIZE {
            return Err(String::from("Packet size is too small. Expected: Header"));
        }

        let header = DNSHeader::deserialize(&bytes[read_count..HEADER_SIZE])?;
        read_count += HEADER_SIZE;

        let mut questions: Vec<DNSQuestion> = Vec::new();
        
        Ok(DNSPacket { header, questions})
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn serialize_dns_str() {
        assert_eq!(
            crate::packet::serialize_dns_str(String::from("test.domain.com").as_str()),
            hex_literal::hex!("04 74 65 73 74 06 64 6f 6d 61 69 6e 03 63 6f 6d 00")
        );
    }
    #[test]
    fn serialize_header() {
        assert_eq!(
            crate::packet::DNSHeader {
                id: 0x1314,
                flags: DNSFlags::default(),
                question_count: 1, 
                answer_count: 2, 
                authority_count: 3, 
                additional_count: 4, 
            }.serialize(),
            hex_literal::hex!("13 14 00 00 00 01 00 02 00 03 00 04")
        );
    }

    #[test]
    fn serialize_question() {
        assert_eq!(
            crate::packet::DNSQuestion {
                name: String::from("example.com"),
                qtype: crate::packet::RecordType::A,
            }.serialize(),
            hex_literal::hex!("07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01")
        );
    }

    #[test]
    fn serialize_packet() {
        let mut packet = crate::packet::DNSPacket::new();
        
        // set static packet ID for test
        packet.header.id = 0xFFFF;
        packet.add_question(crate::packet::DNSQuestion {
            name: String::from("example.com"),
            qtype: crate::packet::RecordType::A,
        });

        assert_eq!(
            packet.serialize(),
            hex_literal::hex!(
                """ 
                FF FF 00 00 00 01 00 00 00 00 00 00
                07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01
                """
            )
        );
    }

    #[test]
    fn serialize_flags() {
        let mut flags = crate::packet::DNSFlags::default();
        flags.is_response = true;
        flags.is_authoritative = true;
        flags.recurse_available = true;
        assert_eq!(flags.serialize(), 0x8480);
    }

    #[test]
    fn deserialize_flags() {
        let mut flags = crate::packet::DNSFlags::default();
        flags.is_response = true;
        flags.is_authoritative = true;
        flags.recurse_available = true;
        assert_eq!(crate::packet::DNSFlags::from(0x8480), flags);

    }
}