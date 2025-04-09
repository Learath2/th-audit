use chrono::DateTime;
use clap::{arg, command};
use libtw2_gamenet_ddnet::msg::Game as GameDDNet;
use libtw2_gamenet_teeworlds_0_7::msg::Game as GameSeven;
use libtw2_packer::Unpacker;
use libtw2_teehistorian::{Buffer, Error, Reader};
use serde::Serialize;
use std::{borrow::Cow, path::Path};
use warn::Ignore;

#[derive(Debug, Serialize)]
struct AuditItem {
    timestamp: DateTime<chrono::FixedOffset>,
    rcon_user: String,
    player_name: String,
    command: String,
    country: String,
}

#[derive(Default)]
struct PlayerData {
    name: String,
    rcon_user: Option<String>,
}

enum ProtocolVersion {
    DDNet,
    Seven,
}

struct PlayerSlot {
    info: Option<PlayerData>,
    ver: ProtocolVersion,
}

fn process_file(p: &Path) -> Result<(), Error> {
    let mut buf = Buffer::new();
    let (h, mut r) = Reader::open(p, &mut buf)?;

    let mut tick = None;
    let start_time = h.timestamp;
    let country = h
        .config
        .get("sv_sql_servername")
        .map(|c| c.as_ref())
        .unwrap_or("")
        .to_owned();

    let mut audit: Vec<AuditItem> = vec![];
    let mut players: [Option<PlayerSlot>; 64] = [const { None }; 64];

    while let Some(item) = r.read(&mut buf)? {
        match item {
            libtw2_teehistorian::Item::TickStart(t) => {
                assert!(tick.is_none());
                tick = Some(t);
            }
            libtw2_teehistorian::Item::TickEnd(t) => {
                assert_eq!(tick, Some(t));
                tick = None;
            }
            libtw2_teehistorian::Item::Joinver6(j) => {
                assert!(players[j.cid as usize].is_none());
                players[j.cid as usize] = Some(PlayerSlot {
                    info: None,
                    ver: ProtocolVersion::DDNet,
                });
            }
            libtw2_teehistorian::Item::Joinver7(j) => {
                assert!(players[j.cid as usize].is_none());
                players[j.cid as usize] = Some(PlayerSlot {
                    info: None,
                    ver: ProtocolVersion::Seven,
                });
            }
            libtw2_teehistorian::Item::PlayerRejoin(j) => {
                assert!(players[j.cid as usize].is_some());
                let p = players[j.cid as usize].as_mut().unwrap();
                p.info = None;
            }
            libtw2_teehistorian::Item::Drop(d) => {
                assert!(players[d.cid as usize].is_some());
                players[d.cid as usize] = None;
            }
            libtw2_teehistorian::Item::Message(m) => {
                let mut up = Unpacker::new(m.msg);
                let p = players[m.cid as usize].as_mut().unwrap();
                match p.ver {
                    ProtocolVersion::DDNet => {
                        if let Ok(msg) = GameDDNet::decode(&mut Ignore, &mut up) {
                            match msg {
                                GameDDNet::ClStartInfo(si) => {
                                    // Drop for now, correct would be to track PlayerReady
                                    if p.info.is_some() {
                                        continue;
                                    }

                                    p.info = Some(Default::default());
                                    unsafe {
                                        if let Some(info) = &mut p.info {
                                            info.name =
                                                std::str::from_utf8_unchecked(si.name).into()
                                        }
                                    }
                                }
                                GameDDNet::ClChangeInfo(ci) => {
                                    assert!(p.info.is_some());
                                    unsafe {
                                        if let Some(info) = &mut p.info {
                                            info.name =
                                                std::str::from_utf8_unchecked(ci.name).into()
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    ProtocolVersion::Seven => {
                        if let Ok(msg) = GameSeven::decode(&mut Ignore, &mut up) {
                            match msg {
                                GameSeven::ClStartInfo(si) => {
                                    assert!(p.info.is_none());
                                    p.info = Some(Default::default());
                                    unsafe {
                                        if let Some(info) = &mut p.info {
                                            info.name =
                                                std::str::from_utf8_unchecked(si.name).into();
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            libtw2_teehistorian::Item::AuthInit(ai) => {
                let p = players[ai.cid as usize].as_mut().unwrap();
                assert!(p.info.is_some());

                unsafe {
                    if let Some(info) = &mut p.info {
                        info.rcon_user = Some(std::str::from_utf8_unchecked(ai.identity).into());
                    }
                }
            }
            libtw2_teehistorian::Item::AuthLogin(al) => {
                let p = players[al.cid as usize].as_mut().unwrap();
                assert!(p.info.is_some() && p.info.as_ref().unwrap().rcon_user.is_none());

                unsafe {
                    if let Some(info) = &mut p.info {
                        info.rcon_user = Some(std::str::from_utf8_unchecked(al.identity).into());
                    }
                }
            }
            libtw2_teehistorian::Item::AuthLogout(al) => {
                let p = players[al.cid as usize].as_mut().unwrap();
                assert!(p.info.is_some() && p.info.as_ref().unwrap().rcon_user.is_some());

                if let Some(info) = &mut p.info {
                    info.rcon_user = None;
                }
            }
            libtw2_teehistorian::Item::ConsoleCommand(cc) => {
                if cc.cid == -1 {
                    continue;
                }

                // Edgecase: Timeout rejoins can cause a post-drop pre-startinfo command
                //assert!(players[cc.cid as usize].is_some());
                if players[cc.cid as usize].is_none() {
                    continue;
                }

                let p = players[cc.cid as usize].as_mut().unwrap();

                // Edgecase: ditto
                //assert!(p.info.is_some());
                if p.info.is_none() {
                    continue;
                }

                let info = p.info.as_ref().unwrap();

                if info.rcon_user.is_none() {
                    continue;
                }

                let time_offset = chrono::TimeDelta::seconds(tick.unwrap() as i64 / 50);
                let timestamp = start_time + time_offset;

                unsafe {
                    audit.push(AuditItem {
                        timestamp,
                        rcon_user: info.rcon_user.clone().unwrap(),
                        player_name: info.name.clone(),
                        command: std::str::from_utf8_unchecked(cc.cmd).into(),
                        country: country.to_owned(),
                    })
                }
            }

            _ => {}
        }
    }

    let j = serde_json::to_string(&audit).unwrap();
    print!("{}", j);

    Ok(())
}

fn main() -> Result<(), Error> {
    let matches = command!()
        .arg(arg!(<file> "teehistorian file to parse"))
        .get_matches();

    let file = matches.get_one::<String>("file").unwrap();
    process_file(Path::new(file))?;

    Ok(())
}
