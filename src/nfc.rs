pub mod pasori_rcs300 {
    // NFC-Port 400 API (specific to Sony manufactured card readers)

    pub fn get_data_card_identification_id(card: &pcsc::Card) -> Result<u8, ()> {
        let apdu = [0xFF, 0xCA, 0xF0, 0x00, 0x00];
        let mut rapdu_buf = [0; pcsc::MAX_BUFFER_SIZE];
        let rapdu = card.transmit(&apdu, &mut rapdu_buf).map_err(|_| ())?;
        if rapdu.len() != 3 || !matches!(&rapdu[1..], b"\x90\x00" | b"\x62\x82") {
            eprintln!(
                "error on get_data_card_identification_id: got {:02X?}",
                rapdu
            );
            return Err(());
        }
        Ok(rapdu[0])
    }

    pub mod mifare_ultralight {

        /// addr is a page number.
        pub fn read_binary(card: &pcsc::Card, addr: u16) -> Result<[u8; 16], ()> {
            let addr_be = addr.to_be_bytes();

            let apdu = [0xFF, 0xB0, addr_be[0], addr_be[1], 16];
            let mut rapdu_buf = [0; pcsc::MAX_BUFFER_SIZE];
            let rapdu = card.transmit(&apdu, &mut rapdu_buf).map_err(|_| ())?;
            if rapdu.len() != 18 || !matches!(&rapdu[16..], b"\x90\x00" | b"\x62\x82") {
                eprintln!("error on read_binary: got {:02X?}", rapdu);
                return Err(());
            }

            Ok(rapdu[..16].try_into().expect("rapdu is too small"))
        }

        /// addr is a page number.
        /// data is a page content that will be written at the address.
        #[allow(dead_code)]
        pub fn update_binary(card: &pcsc::Card, addr: u16, data: [u8; 4]) -> Result<(), ()> {
            let addr_be = addr.to_be_bytes();

            let apdu = [
                0xFF, 0xD6, addr_be[0], addr_be[1], 0x04, data[0], data[1], data[2], data[3],
            ];
            let mut rapdu_buf = [0; pcsc::MAX_BUFFER_SIZE];
            let rapdu = card.transmit(&apdu, &mut rapdu_buf).map_err(|_| ())?;
            if rapdu.len() != 2 || !matches!(&rapdu[..], b"\x90\x00" | b"\x62\x82") {
                eprintln!("error on update_binary: got {:02X?}", rapdu);
                return Err(());
            }

            Ok(())
        }
    }
}

pub mod ndef {
    use super::pasori_rcs300::mifare_ultralight::read_binary;

    fn read_page(card: &pcsc::Card, addr: u16) -> Result<[u8; 4], ()> {
        let data = read_binary(card, addr)?;
        Ok(data[..4].try_into().unwrap())
    }

    pub struct Record<'msg> {
        pub type_: &'msg [u8],
        pub payload: &'msg [u8],
    }

    pub fn read_message(card: &pcsc::Card) -> Result<Vec<u8>, ()> {
        let mut addr = 4_u16;

        let page = read_page(card, addr)?;
        if page[0] != 0x03 {
            eprintln!("not NDEF message");
            return Err(());
        }

        let total_size = page[1] as usize + 1;

        let mut buf = Vec::new();
        buf.extend_from_slice(&page[2..]);

        while buf.len() < total_size {
            addr += 1;
            let page = read_page(card, addr)?;
            buf.extend_from_slice(&page[..]);
        }
        buf.truncate(total_size);

        if buf.len() < 1 || *buf.last().unwrap() != 0xFE {
            eprintln!("invalid NDEF message");
            Err(())
        } else {
            buf.pop();
            Ok(buf)
        }
    }

    pub fn parse_records<'msg>(message: &'msg [u8]) -> Result<Vec<Record<'msg>>, ()> {
        let mut records = Vec::new();

        let mut i = 0;
        while i < message.len() {
            if message[i] & 0b11000000 != 0b11000000 {
                eprintln!("support more than 1 record");
                return Err(());
            }
            if message[i] & 0b00100000 == 0b00100000 {
                eprintln!("support chunked record");
                return Err(());
            }
            if message[i] & 0b00010000 == 0b00000000 {
                eprintln!("support non-short record");
                return Err(());
            }
            if message[i] & 0b00001000 != 0b00000000 {
                eprintln!("support record with ID-length field");
                return Err(());
            }
            if message[i] & 0b00000111 != 0b00000001 {
                eprintln!("support record with non-NFC well-known type");
                return Err(());
            }

            i += 1;
            let type_length = message[i] as usize;

            i += 1;
            let payload_length = message[i] as usize;

            i += 1;
            if message.len() < i + type_length {
                eprintln!("message is too short");
                return Err(());
            }
            let type_ = &message[i..i + type_length];

            if type_ != b"U" {
                eprintln!("support more well-known types");
                return Err(());
            }

            if i + payload_length > message.len() {
                eprintln!("invalid message");
                return Err(());
            }

            i += type_length;
            let payload = &message[i..i + payload_length];

            records.push(Record { type_, payload });

            i += payload_length;
        }

        Ok(records)
    }

    #[allow(dead_code)]
    pub fn construct_message<'src>(records: &[Record<'src>]) -> Vec<u8> {
        let mut records_length = 0;
        for r in records {
            if r.payload.len() < 256 {
                // short record
                records_length += 3 + r.payload.len() + r.type_.len();
            } else {
                // (normal) record
                unimplemented!();
            }
        }
        assert!(records_length < 256);

        if records.len() > 1 {
            todo!("support multiple records");
        }
        if records[0].payload.len() >= 256 {
            todo!("support non-short records");
        }
        assert!(records[0].type_.len() < 256);

        let mut message = vec![0x03];
        message.push(records_length as u8);

        message.push(0b11010001); // NFC Well-known type
        message.push(records[0].type_.len() as u8); // TYPE LENGTH
        message.push(records[0].payload.len() as u8); // PAYLOAD LENGTH
        message.extend_from_slice(&records[0].type_);
        message.extend_from_slice(&records[0].payload);

        message.push(0xFE); // terminator

        if message.len() % 4 != 0 {
            for _ in 0..(4 - message.len() % 4) {
                message.push(0x00);
            }
        }

        message
    }
}
