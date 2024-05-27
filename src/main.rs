use clickhouse_rs::types::Block;
use clickhouse_rs::{row, Pool};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
use tungstenite::{connect, Message};

const CERTSTREAM_URL: &str = "wss://certstream.calidog.io/";
const BATCH_SIZE: usize = 1000;
const MAX_BATCH_AGE: Duration = Duration::new(10, 0);

#[tokio::main]
async fn main() {
    // This whole thing is a bit of a monstrosity, for several reasons:
    //
    // * I don't think a VecDeque is the best choice of data structure here, since we have to lock it every time we
    //   want to access it.
    // * There's a hodge-podge of thread-based and async code here... the two main Clickhouse libraries I found are
    //   both async, the websocket library /can/ be async, but I don't know enough about async in rust to know whether
    //   it's performant enough -- there can be quite a few messages coming in from the websocket.
    // * I don't really know how to write idiomatic rust (yet).

    env_logger::init();

    let ws_message_queue = Arc::new(Mutex::new(VecDeque::new()));
    let batch_queue = Arc::new(Mutex::new(VecDeque::new()));

    let ws_write_queue = Arc::clone(&ws_message_queue);
    let ws_read_queue = Arc::clone(&ws_message_queue);
    let batch_write_queue = Arc::clone(&batch_queue);
    let batch_read_queue = Arc::clone(&batch_queue);

    // This could be a coroutine instead of a thread.
    let websocket_reader = std::thread::spawn(move || {
        read_websocket(CERTSTREAM_URL, ws_write_queue);
    });

    let batcher = std::thread::spawn(move || {
        batch_records(ws_read_queue, batch_write_queue);
    });

    // Inserter is async, so we don't need a thread but do need to await it.
    insert_records(batch_read_queue).await.unwrap();

    websocket_reader.join().unwrap();
    batcher.join().unwrap();
}

async fn insert_records(
    batch_queue: Arc<Mutex<VecDeque<Vec<TransparencyRecord>>>>,
) -> Result<(), Box<dyn Error>> {
    // Process batch of records for insertion.
    // Rather than deal with nested fields in the JSON, we flatten the data into a single row per domain.
    // This is pretty inefficient, but it's a simple way to get the data into Clickhouse, and the data is probably
    // very compressible...?

    let pool = Pool::new("tcp://default:@127.0.0.1:9000/default");

    let mut client = pool.get_handle().await?;

    loop {
        // Rather than having to take the lock every time we check the queue, can we do something more efficient?
        // Is there something signal based, or maybe a channel or something? It'd be nice if we could block here
        // rather than this approach of taking the lock and sleeping a bit...
        while !batch_queue.lock().unwrap().is_empty() {
            let batch = batch_queue.lock().unwrap().pop_front().unwrap();

            let mut block = Block::new();
            let mut inserted: u64 = 0;

            for record in batch.iter() {
                match &record.data {
                    Some(data) => {
                        // TODO: Can we avoid cloning here, and take ownership of the data?
                        // Note: this is a bit of a mess, but none of the two Clickhouse libraries I found seem to support
                        //       nested fields. We might be able to do some stuff with serdes to have it flatten the data
                        //       for us, but I'm not sure how to do that yet...
                        for domain in data.leaf_cert.all_domains.iter() {
                            block.push(row!{
                                "cert_index" => data.cert_index,
                                "cert_link" => data.cert_link.clone(),
                                "fingerprint" => data.leaf_cert.fingerprint.clone(),
                                "not_after" => data.leaf_cert.not_after,
                                "not_before" => data.leaf_cert.not_before,
                                "serial_number" => data.leaf_cert.serial_number.clone(),
                                "c" => data.leaf_cert.subject.c.clone().unwrap_or_default(),
                                "cn" => data.leaf_cert.subject.cn.clone().unwrap_or_default(),
                                "l" => data.leaf_cert.subject.l.clone().unwrap_or_default(),
                                "o" => data.leaf_cert.subject.o.clone().unwrap_or_default(),
                                "ou" => data.leaf_cert.subject.ou.clone().unwrap_or_default(),
                                "st" => data.leaf_cert.subject.st.clone().unwrap_or_default(),
                                "aggregated" => data.leaf_cert.subject.aggregated.clone().unwrap_or_default(),
                                "email_address" => data.leaf_cert.subject.email_address.clone().unwrap_or_default(),
                                "domain" => domain.clone()
                            })?;
                            inserted += 1;
                        }
                    }
                    None => {
                        warn!("Record missing data field: {:?}", record);
                    }
                }
            }
            client.insert("certs", block).await.unwrap();

            info!(
                "Written batch of {} records, expanded to {} rows",
                batch.len(),
                inserted
            );
        }
        // sleep a bit... not nice.
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn batch_records(
    ws_message_queue: Arc<Mutex<VecDeque<String>>>,
    batch_queue: Arc<Mutex<VecDeque<Vec<TransparencyRecord>>>>,
) {
    // Pull from the websocket queue, batch up records, and shove them into the batch queue
    // for insertion into Clickhouse.

    // Would a fixed size buffer be better here? We won't always fill it but could avoid the reallocation?
    let mut message_buffer: Vec<TransparencyRecord> = Vec::new();

    let mut last_batch_time = std::time::Instant::now();

    loop {
        while !ws_message_queue.lock().unwrap().is_empty() {
            // TODO: there's a potential race condition here if we had multiple consumers, since we're acquiring the
            // lock once for the length check and then again to pop the message...
            let message = ws_message_queue.lock().unwrap().pop_front().unwrap();
            let record: TransparencyRecord = serde_json::from_str(&message).unwrap();

            message_buffer.push(record);

            if message_buffer.len() >= BATCH_SIZE || last_batch_time.elapsed() >= MAX_BATCH_AGE {
                info!("Batching up {} records", message_buffer.len());
                batch_queue
                    .lock()
                    .unwrap()
                    .push_back(message_buffer.clone());
                message_buffer.clear();
                last_batch_time = std::time::Instant::now();
            }
        }
        // sleep a bit... also not nice...
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn read_websocket(url: &str, queue: Arc<Mutex<VecDeque<String>>>) {
    loop {
        let (mut socket, _) = match connect(url) {
            Ok(result) => result,
            Err(e) => {
                warn!("Error connecting to websocket: {:?}", e);
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        let mut error_count: u16 = 0;
        let max_errors = 5;

        let ping_interval = Duration::from_secs(5);
        let mut last_ping_sent = std::time::Instant::now();

        loop {
            // This isn't entirely ideal, given socket.read() is blocking so we're not guaranteed to meet the ping
            // interval, but the WS is busy enough that this doesn't matter in practice.

            if last_ping_sent.elapsed() >= ping_interval {
                info!("Sending ping");
                socket
                    .send(Message::Ping(vec![]))
                    .expect("Error sending ping");
                last_ping_sent = std::time::Instant::now();
            }

            match socket.read() {
                Ok(msg) => match msg {
                    Message::Text(text) => {
                        queue.lock().unwrap().push_back(text);
                    }
                    Message::Close(_) => {
                        info!("Connection closed");
                        break;
                    }
                    Message::Ping(_) => {
                        info!("Received ping");
                        socket
                            .send(Message::Pong(vec![]))
                            .expect("Error sending pong");
                    }
                    Message::Pong(_) => {
                        info!("Received pong");
                    }
                    _ => {
                        info!("Ignoring message: {:?}", msg);
                    }
                },
                Err(e) => {
                    error_count += 1;
                    warn!(
                        "[{}/{}] Error reading message: {:?}",
                        error_count, max_errors, e
                    );
                    if error_count >= max_errors {
                        warn!("Too many errors, closing connection");
                        break;
                    }
                }
            }
            socket.flush().unwrap();
        }
    }
}

// TODO: expand these structs to include more data.
#[derive(Deserialize, Debug, Clone, Serialize)]
struct TransparencyRecordData {
    cert_index: u64,
    cert_link: String,
    leaf_cert: LeafCert,
}

#[derive(Deserialize, Debug, Clone, Serialize)]
struct TransparencyRecord {
    data: Option<TransparencyRecordData>,
    message_type: String,
}

#[derive(Deserialize, Debug, Clone, Serialize)]
struct LeafCert {
    all_domains: Vec<String>,

    fingerprint: String,
    not_after: u64,
    not_before: u64,
    serial_number: String,
    subject: Subject,
}
#[derive(Deserialize, Debug, Clone, Serialize)]
struct Subject {
    c: Option<String>,
    cn: Option<String>,
    l: Option<String>,
    o: Option<String>,
    ou: Option<String>,
    st: Option<String>,
    aggregated: Option<String>,
    email_address: Option<String>,
}
