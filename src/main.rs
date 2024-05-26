
use std::{collections::VecDeque, sync::{Arc, Mutex}, time::Duration};
use clickhouse::insert;
use serde::Deserialize;

use websocket::{client::ClientBuilder, OwnedMessage};

const CERTSTREAM_URL: &str = "wss://certstream.calidog.io/";
const BATCH_SIZE: usize = 1000;
const MAX_BATCH_AGE: Duration = Duration::new(1, 0);
                                                                            
fn main() {
    let ws_message_queue = Arc::new(Mutex::new(VecDeque::new()));
    let batch_queue = Arc::new(Mutex::new(VecDeque::new()));


    let ws_write_queue = Arc::clone(&ws_message_queue);
    let ws_read_queue = Arc::clone(&ws_message_queue);
    let batch_write_queue = Arc::clone(&batch_queue);
    let batch_read_queue = Arc::clone(&batch_queue);

    let websocket_reader = std::thread::spawn(move || {
        read_websocket(CERTSTREAM_URL, ws_write_queue);
    });

    let batcher = std::thread::spawn(move || {
        batch_records(ws_read_queue, batch_write_queue);
    });

    let inserter = std::thread::spawn(move || {
        insert_records(batch_read_queue);
    });

    websocket_reader.join().unwrap();
    batcher.join().unwrap();
    inserter.join().unwrap();

}

fn insert_records(batch_queue : Arc<Mutex<VecDeque<Vec<TransparencyRecord>>>>) {
    loop {
        while !batch_queue.lock().unwrap().is_empty() {
            let batch = batch_queue.lock().unwrap().pop_front().unwrap();
            
            println!("[Batch Writer] Writing batch of {} records", batch.len());
        }
    }
}

fn batch_records(ws_message_queue: Arc<Mutex<VecDeque<String>>>, batch_queue: Arc<Mutex<VecDeque<Vec<TransparencyRecord>>>>) {
    let mut message_buffer: Vec<TransparencyRecord> = Vec::new();
    
    let mut last_batch_time = std::time::Instant::now();

    loop{
        while !ws_message_queue.lock().unwrap().is_empty() {
            let message = ws_message_queue.lock().unwrap().pop_front().unwrap();
            let record: TransparencyRecord  = serde_json::from_str(&message).unwrap(); 

            message_buffer.push(record);
            
            if message_buffer.len() >= BATCH_SIZE || last_batch_time.elapsed() >= MAX_BATCH_AGE{
                println!("Batching up {} records", message_buffer.len());
                batch_queue.lock().unwrap().push_back(message_buffer.clone());
                message_buffer.clear();
                last_batch_time = std::time::Instant::now();
            }

        }
    }
}

fn read_websocket(url: &str, queue: Arc<Mutex<VecDeque<String>>>) {
    let mut client = ClientBuilder::new(url)
        .unwrap()
        .connect_secure(None)
        .unwrap();

    for message in client.incoming_messages() {
        let data = match message {
            Ok(data) => data,
            Err(e) => {
                println!("Error processing websocket message: {}", e);
                continue;
            }
        };

        match data{
            OwnedMessage::Text(string) => {
                queue.lock().unwrap().push_back(string);
            }
            _ => {
                println!("Received non-text message: {:?}", data);
            }
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
struct TransparencyRecordData{
    cert_index: u64,
    cert_link: String,
    leaf_cert: LeafCert
}

#[derive(Deserialize, Debug, Clone)]
struct TransparencyRecord{
    data: Option<TransparencyRecordData>,
    message_type: String,
}

#[derive(Deserialize, Debug, Clone)]
struct LeafCert{
    all_domains: Vec<String>,

    fingerprint: String,
    not_after: u64,
    not_before: u64,
    serial_number: String,
    subject: Subject
}
#[derive(Deserialize, Debug, Clone)]
struct Subject{
    c: Option<String>,
    cn: Option<String>,
    l: Option<String>,
    o: Option<String>,
    ou: Option<String>,
    st: Option<String>,
    aggregated: Option<String>,
    email_address: Option<String>
}