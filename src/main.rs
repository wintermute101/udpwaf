use tokio::{net::UdpSocket, sync::mpsc, sync::mpsc::Sender, time, time::Duration, task::JoinHandle, signal::unix::{signal, SignalKind}};
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
use std::sync::atomic::{AtomicBool, Ordering};
use rlimit::{getrlimit, Resource};
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
    async fn new(forward_addr: SocketAddr, local_bind: SocketAddr, timeout: u32, script: Py<PyAny>, server_addr: SocketAddr, sender: Sender<(Vec<u8>, SocketAddr)>, client_addr: SocketAddr) -> Result<Self, DataStoreError> {
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
                if addr.port() == server_addr.port() && addr.ip().is_loopback(){
                    error!("Forwarder: {} received data from {} on server port dropping {}", client_addr, addr, server_addr);
                    continue;
                }
                trace!("Forwarder: {} bytes received from {} forwarding to {}", len, addr, client_addr);
                sender.send((buf[..len].to_vec(), client_addr)).await.unwrap();
            }
        });

        Ok(Client { forward_addr, sock: s, client_addr, client_handle: Some(h), py: script })
    }

    fn is_active(&self) -> bool {
        if let Some(handle) = &self.client_handle {
            !handle.is_finished()
        }
        else{
            false
        }
    }

    fn abort(&mut self) {
        if let Some(handle) = self.client_handle.take() {
            handle.abort();
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
    Builder::new()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .format_timestamp(Some(env_logger::fmt::TimestampPrecision::Millis))
        .init();

    let args = Args::parse();
    let server_addr = args.bind.parse::<SocketAddr>()?;
    let sock = UdpSocket::bind(server_addr).await?;
    let r = Arc::new(sock);
    let s = r.clone();
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1_000);

    let forward_addr: SocketAddr = args.forward.parse()?;
    let local_bind: SocketAddr = {
        let mut bind: SocketAddr = args.local_bind.parse()?;
        bind.set_port(0);
        bind
    };

    restrict_thread(&PathBuf::from(&args.filter_script))?;

    info!("Starting UDP WAF listening on {}", args.bind);

    let limits = getrlimit(Resource::NOFILE)?;
    info!("Current file open limits: {:?}", limits);

    if limits.0 < 50000{
        let minlimit = std::cmp::min(50000, limits.1);
        warn!("Current file open limits too low trying to increase to {}", minlimit);
        rlimit::setrlimit(Resource::NOFILE, minlimit, limits.1)?;
        let limits = getrlimit(Resource::NOFILE)?;
        info!("Current file open limits: {:?}", limits);
    }

    tokio::spawn(async move {
        while let Some((bytes, addr)) = rx.recv().await {
            let len = s.send_to(&bytes, &addr).await.unwrap();
            trace!("Server: {:?} bytes sent to {}", len, addr);
        }
    });

    let mut clients: HashMap<SocketAddr, Client> = HashMap::new();

    let fun: PyResult<Py<PyAny>> = Python::with_gil(|py| {
        let code = std::fs::read_to_string(&args.filter_script)?;
        let fun = PyModule::from_code(
                py,
                CString::new(code)?.as_c_str(),
                CString::new(args.filter_script.as_bytes())?.as_c_str(),
                c_str!("filter"),
            )?.getattr("filter")?.into();

        Ok(fun)
    });

    let mut python_script = fun?;
    let mut buf = [0; 1024];
    let mut last_cleanup = time::Instant::now();

    let mut stream = signal(SignalKind::user_defined1())?;

    let need_reload = Arc::new(AtomicBool::new(false));
    let need_reload_clone = need_reload.clone();

    tokio::spawn(async move {
        loop{
            stream.recv().await;
            info!("Received SIGUSR1, reloading");
            need_reload_clone.store(true, Ordering::Release);
        }
    });

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
                    debug!("Client {} is not active, removing", a);
                    if let Some(mut c) = clients.remove(&a){
                        c.close().await?;
                    }
                }
                last_cleanup = time::Instant::now();

                if need_reload.load(Ordering::Acquire){
                    info!("Reloading python script");

                    let fun: PyResult<Py<PyAny>> = Python::with_gil(|py| {
                        let code = std::fs::read_to_string(&args.filter_script)?;
                        let fun = PyModule::from_code(
                                py,
                                CString::new(code)?.as_c_str(),
                                CString::new(args.filter_script.as_bytes())?.as_c_str(),
                                c_str!("filter"),
                            )?.getattr("filter")?.into();

                        Ok(fun)
                    });
                    match fun{
                        Ok(fun) => {
                            python_script = fun;
                        }
                        Err(e) => {
                            error!("Error reloading python script: {}. Script not changed", e);
                            need_reload.store(false, Ordering::Release);
                            continue;
                        }
                    }
                    info!("Closing all clients [{}]", clients.len());

                    for (_, client) in clients.iter_mut(){
                        client.abort();
                        client.close().await?;
                    }
                    clients.clear();

                    need_reload.store(false, Ordering::Release);
                    info!("Python script reloaded");
                }
                continue;
            }
        };
        trace!("Server: {:?} bytes received from {:?}", len, addr);

        if last_cleanup.elapsed() > Duration::from_secs(1){
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
            last_cleanup = time::Instant::now();
        }

        match clients.entry(addr){
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let client = entry.get_mut();
                if client.is_active() {
                    debug!("Client already exists for {}", addr);
                    client.forward(buf[..len].to_vec()).await?;
                } else {
                    debug!("Client {} is not active creating new", addr);

                    client.close().await?;

                    let fun: PyResult<Py<PyAny>> = Python::with_gil(|py| {
                        Ok(python_script.clone_ref(py))
                    });
                    let fun = fun?;

                    *client = Client::new(forward_addr, local_bind, args.timeout, fun, server_addr, tx.clone(), addr).await?;
                    client.forward(buf[..len].to_vec()).await?;
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                debug!("New client: {}", addr);
                let fun: PyResult<Py<PyAny>> = Python::with_gil(|py| {
                        Ok(python_script.clone_ref(py))
                });
                let fun = fun?;

                let client = Client::new(forward_addr, local_bind, args.timeout, fun, server_addr, tx.clone(), addr).await?;
                client.forward(buf[..len].to_vec()).await?;
                entry.insert(client);
            }
        }
    }
}