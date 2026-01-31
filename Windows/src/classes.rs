use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;

#[derive(Debug)]
pub struct BroadcastState {
    pub broadcast_address: Mutex<String>,
    pub port: Mutex<u16>,
}

impl BroadcastState {
    pub fn set_broadcast_address(&self, address: String) {
        *self.broadcast_address.lock().unwrap() = address;
    }
    pub fn get_broadcast_address(&self) -> String {
        self.broadcast_address.lock().unwrap().clone()
    }
    // pub fn set_port(&self, p: u16) {
    //     *self.port.lock().unwrap() = p;
    // }
    pub fn get_port(&self) -> u16 {
        *self.port.lock().unwrap()
    }
    pub fn target_v4(&self) -> SocketAddrV4 {
        let ip: Ipv4Addr = self
            .get_broadcast_address()
            .parse()
            .unwrap_or(Ipv4Addr::new(255, 255, 255, 255));
        SocketAddrV4::new(ip, self.get_port())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub version: String,
    pub selected_interface: String,
    pub last_broadcast: String,
    pub last_gateway: String,
    #[serde(default)]
    pub save_to_folder: String,
}

#[derive(Debug, Clone)]
pub struct InterfacesInfo {
    pub name: String,
    pub address_to_broadcast: String,
    pub status: String,
}

//#[derive(Clone)]
// pub struct InterfaceItem {
//     pub name: slint::SharedString,
//     pub broadcast: slint::SharedString,
// }