mod nfc;
mod spotify;

use pcsc::{Card, Context, Protocols, ReaderState, Scope, ShareMode, State};

struct PlayerState {
    last_played_album: String,
    start_to_play: u32,
}

#[tokio::main]
async fn main() {
    // Establish a PC/SC context.
    let ctx = Context::establish(Scope::System).expect("failed to establish context");

    let readers = ctx.list_readers_owned().unwrap();
    let mut reader_states: Vec<ReaderState> = readers
        .into_iter()
        .map(|name| ReaderState::new(name, State::UNAWARE))
        .collect();
    let mut counts: Vec<u32> = vec![u32::MAX; reader_states.len()];

    let mut player_state = PlayerState {
        last_played_album: "".to_owned(),
        start_to_play: 0,
    };

    loop {
        ctx.get_status_change(std::time::Duration::MAX, &mut reader_states)
            .unwrap();
        for state in reader_states.iter_mut() {
            state.sync_current_state();
        }

        assert_eq!(reader_states.len(), counts.len());
        for (reader, count) in reader_states.iter().zip(counts.iter_mut()) {
            if reader.event_count() == *count {
                continue;
            }
            *count = reader.event_count();

            let state = reader.current_state();
            if state.contains(State::PRESENT) {
                let card = ctx
                    .connect(reader.name(), ShareMode::Exclusive, Protocols::ANY)
                    .expect("failed to connect to card");
                on_card_deteced(&card, &mut player_state).await;
            } else if state.contains(pcsc::State::EMPTY) {
                spotify::pause_playbck().await;
            }
        }
    }
}

async fn on_card_deteced(card: &Card, player_state: &mut PlayerState) {
    let identification = nfc::pasori_rcs300::get_data_card_identification_id(card).unwrap();

    // Check if the card is MIFARE Ultralight
    if identification != 0x04 {
        println!("Error: not a MIFARE Ultralight card");
        return;
    }

    let message = nfc::ndef::read_message(&card).unwrap();
    let records = nfc::ndef::parse_records(&message).unwrap();
    for r in records {
        if r.type_ == b"U" && r.payload.len() > 1 {
            let scheme = match r.payload[0] {
                0x03 => "http",
                0x04 => "https",
                _ => unimplemented!(),
            };

            let url = format!(
                "{}://{}",
                scheme,
                std::str::from_utf8(&r.payload[1..]).unwrap()
            );

            if player_state.last_played_album == url {
                player_state.start_to_play += 1;
            } else {
                player_state.last_played_album = url.clone();
                player_state.start_to_play = 0;
            }

            println!("opening {} from track:{}", url, player_state.start_to_play);

            let mut started = false;
            let re =
                regex::Regex::new(r"^https?://open.spotify.com/album/([^?]+)(\?.*)?$").unwrap();
            if let Some(groups) = re.captures(&url) {
                if groups.len() > 1 {
                    let id = groups.get(1).unwrap().as_str();
                    spotify::play_album(&id, player_state.start_to_play).await;
                    started = true;
                }
            }

            if !started {
                println!("failed to play the album");
            }
        }
    }
}

#[allow(dead_code)]
fn write_record() {
    let record = nfc::ndef::Record {
        type_: b"U",
        payload: b"\x04open.spotify.com/album/4EFE6hdiO2XNmh5FxpTNFi",
    };
    println!("writing {:02X?}", record.payload);
    let data = nfc::ndef::construct_message(&[record]);
    assert!(data.len() % 4 == 0);
    for i in 0..(data.len() / 4) {
        let addr: u16 = 4 + i as u16;
        nfc::pasori_rcs300::mifare_ultralight::update_binary(
            card,
            addr,
            data[(i * 4)..(i + 1) * 4].try_into().unwrap(),
        )
        .unwrap();
    }
}
