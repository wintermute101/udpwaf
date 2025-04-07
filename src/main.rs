use tokio::{net::UdpSocket, sync::mpsc, sync::mpsc::Sender, time, time::Duration, task::JoinHandle};
use std::{io, net::SocketAddr, sync::Arc};
use std::collections::HashMap;
use thiserror::Error;
use log::{debug, error, warn, info, trace, LevelFilter};
use env_logger::Builder;
use pyo3::prelude::*;
use pyo3::ffi::c_str;
use pyo3::PyErr;
use pyo3::types::PyByteArray;
use std::ffi::CString;
use clap::Parser;
use std::path::PathBuf;
use landlock::{
    ABI, Access, AccessFs, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, AccessNet,
    make_bitflags, path_beneath_rules,
};

#[derive(Error, Debug)]
pub enum DataStoreError {
    #[error("IO error {0}")]
    IOError(#[from] io::Error),

    #[error("Send error {0}")]
    SendError(#[from] mpsc::error::SendError<(Vec<u8>, SocketAddr)>),

    #[error("Timeout")]
    Timeout(),

    #[error("Python error {0}")]
    PythonError(#[from] PyErr),

    #[error("Addr Parse error {0}")]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error("RulesetError {0}")]
    RulesetError(#[from] landlock::RulesetError),
}

#[derive(Debug)]
struct Client{
    sock: Arc<UdpSocket>,
    client_addr: SocketAddr,
    client_handle: Option<JoinHandle<Result<(), DataStoreError>>>,
    py: Py<PyAny>,
    forward_addr: SocketAddr,
}

impl Client {
    async fn new(forward_addr: SocketAddr, local_bind: SocketAddr, timeout: u32, script_name: &String, sender: Sender<(Vec<u8>, SocketAddr)>, client_addr: SocketAddr) -> Result<Self, DataStoreError> {
        let sock = UdpSocket::bind(local_bind).await?;
        let r = Arc::new(sock);
        let s = r.clone();

        let mut buf = [0; 1024];
        let h = tokio::spawn(async move {
            loop{
                let r = time::timeout(Duration::from_secs(timeout as u64), r.recv_from(&mut buf)).await;
                let (len, addr) = match r{
                    Ok(Ok((len, addr))) => (len, addr),
                    Ok(Err(e)) => {
                        error!("Forwarder: Error receiving data: {}", e);
                        return Err(e.into());
                    }
                    Err(_) => {
                        debug!("Forwarder: {} Timeout waiting for data", client_addr);
                        return Ok(());
                    }
                };
                trace!("Forwarder: {} bytes received from {} forwarding to {}", len, addr, client_addr);
                sender.send((buf[..len].to_vec(), client_addr)).await.unwrap();
            }
        });

        let fun: PyResult<Py<PyAny>> = Python::with_gil(|py| {
            let code = std::fs::read_to_string(script_name)?;
            let fun = PyModule::from_code(
                    py,
                    CString::new(code)?.as_c_str(),
                    CString::new(script_name.as_bytes())?.as_c_str(),
                    c_str!("filter"),
                )?.getattr("filter")?.into();

            Ok(fun)
        });

        Ok(Client { forward_addr, sock: s, client_addr, client_handle: Some(h), py: fun? })
    }

    fn is_active(&self) -> bool {
        if let Some(handle) = &self.client_handle {
            !handle.is_finished()
        }
        else{
            false
        }
    }

    async fn close(&mut self) -> Result<(), DataStoreError> {
        if let Some(handle) = self.client_handle.take() {
            handle.await.unwrap()?;
        }
        Ok(())
    }

    async fn forward(&self, bytes: Vec<u8>) -> Result<(), DataStoreError>{
        let ret: PyResult<Option<Vec<u8>>> = Python::with_gil(|py| {
            let arg1 = PyByteArray::new(py, &bytes);
            let arg2 = self.client_addr.to_string();
            let ret: Option<Vec<u8>> = self.py.call1(py, (arg1,arg2))?.extract(py)?;
            Ok(ret)
        });

        match ret{
            Ok(Some(ret)) => {
                trace!("Forwarder: Sending {} bytes from python to {}", ret.len(), self.forward_addr);
                self.sock.send_to(&ret, self.forward_addr).await?;
            }
            Ok(None) => {
                warn!("Forwarder: Got None from python dropping packet");
            }
            Err(e) => {
                error!("Forwarder: Error calling python: {}", e);
            }
        }
        Ok(())
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, help="Server bind address", default_value_t = String::from("[::]:8080"))]
    bind: String,

    #[arg(short, long, help="Where to forward messages", default_value_t = String::from("[::1]:8000"))]
    forward: String,

    #[arg(short, long, help="Where to listent to for forwarder", default_value_t = String::from("[::1]:0"))]
    local_bind: String,

    #[arg(short, long, help="After this time client connection will be dropped", default_value_t = 10)]
    timeout: u32,

    #[arg(short='s', long, help="Python script should contain filter function.", default_value_t = String::from("script.py"))]
    filter_script: String,
}

fn restrict_thread(path: &PathBuf) -> Result<(), DataStoreError> {
    let abi = ABI::V5;

    let status = Ruleset::default()
        .handle_access(AccessNet::from_all(abi))?
        .create()?
        .restrict_self()?;

    match status.ruleset {
        // The FullyEnforced case must be tested by the developer.
        RulesetStatus::FullyEnforced => info!("Network Fully sandboxed."),
        RulesetStatus::PartiallyEnforced => warn!("Network Partially sandboxed."),
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => warn!("Network Not sandboxed! Please update your kernel."),
    }

    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        //can only execute python3 might might not be true on all linux flavors
        .add_rules(path_beneath_rules(&["/usr/bin/python3"], AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(&["/usr/lib"], make_bitflags!(AccessFs::{ReadFile|ReadDir})))?
        .add_rules(path_beneath_rules(path, make_bitflags!(AccessFs::ReadFile)))?
        .restrict_self()?;
    match status.ruleset {
        // The FullyEnforced case must be tested by the developer.
        RulesetStatus::FullyEnforced => info!("FS Fully sandboxed."),
        RulesetStatus::PartiallyEnforced => warn!("FS Partially sandboxed."),
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => warn!("FS Not sandboxed! Please update your kernel."),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(),DataStoreError> {
    Builder::new().filter_level(LevelFilter::Info).parse_default_env().init();
    let args = Args::parse();
    let sock = UdpSocket::bind(args.bind.parse::<SocketAddr>()?).await?;
    let r = Arc::new(sock);
    let s = r.clone();
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1_000);

    let forward_addr: SocketAddr = args.forward.parse()?;
    let local_bind: SocketAddr = args.local_bind.parse()?;

    restrict_thread(&PathBuf::from(&args.filter_script))?;

    info!("Starting UDP WAF listening on {}", args.bind);

    tokio::spawn(async move {
        while let Some((bytes, addr)) = rx.recv().await {
            let len = s.send_to(&bytes, &addr).await.unwrap();
            trace!("Server: {:?} bytes sent to {}", len, addr);
        }
    });

    let mut clients: HashMap<SocketAddr, Client> = HashMap::new();

    let mut buf = [0; 1024];
    loop {
        let ret = time::timeout(Duration::from_secs(1),r.recv_from(&mut buf)).await;
        let (len, addr) = match ret{
            Ok(Ok(ret))=> ret,
            Ok(Err(e)) => {
                error!("Error receiving data: {}", e);
                return Err(e.into());
            }
            Err(_) => {
                let inactive_clients: Vec<SocketAddr> = clients
                    .iter()
                    .filter(|(_, c)| !c.is_active())
                    .map(|(a, _)| *a)
                    .collect();

                for a in inactive_clients {
                    warn!("Client {} is not active, removing", a);
                    if let Some(mut c) = clients.remove(&a){
                        c.close().await?;
                    }
                }
                continue;
            }
        };
        trace!("Server: {:?} bytes received from {:?}", len, addr);

        match clients.entry(addr){
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let client = entry.get_mut();
                if client.is_active() {
                    debug!("Client already exists for {}", addr);
                    client.forward(buf[..len].to_vec()).await?;
                } else {
                    debug!("Client {} is not active creating new", addr);

                    client.close().await?;

                    *client = Client::new(forward_addr, local_bind, args.timeout, &args.filter_script, tx.clone(), addr).await?;
                    client.forward(buf[..len].to_vec()).await?;
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                info!("New client: {:?}", addr);
                let client = Client::new(forward_addr, local_bind, args.timeout, &args.filter_script, tx.clone(), addr).await?;
                client.forward(buf[..len].to_vec()).await?;
                entry.insert(client);
            }
        }
    }
}