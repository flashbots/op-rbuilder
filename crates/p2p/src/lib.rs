mod behaviour;
mod peers;

use behaviour::Behaviour;
use libp2p_stream::Control;
use peers::Peers;

use eyre::Context;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, Transport as _,
    identity::{self, ed25519},
    noise,
    swarm::SwarmEvent,
    tcp, yamux,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// TODO: put this on NodeBuilder
const FLASHBLOCKS_STREAM_PROTOCOL: StreamProtocol = StreamProtocol::new("/flashblocks/1.0.0");
const DEFAULT_AGENT_VERSION: &str = "rollup-boost/1.0.0";

// TODO: change this to an actual message type
pub(crate) type Message = String;

pub struct Node {
    peer_id: PeerId,
    listen_addrs: Vec<libp2p::Multiaddr>,
    swarm: Swarm<Behaviour>,
    known_peers: Vec<Multiaddr>,
    payload_rx: mpsc::Receiver<Message>,
    peers: Peers,
    cancellation_token: tokio_util::sync::CancellationToken,
}

impl Node {
    /// Returns the multiaddresses that this node is listening on, with the peer ID included.
    pub fn multiaddrs(&self) -> Vec<libp2p::Multiaddr> {
        self.listen_addrs
            .iter()
            .map(|addr| {
                addr.clone()
                    .with_p2p(self.peer_id)
                    .expect("can add peer ID to multiaddr")
            })
            .collect()
    }

    pub async fn run(self) -> eyre::Result<()> {
        use libp2p::futures::StreamExt as _;

        let Node {
            peer_id: _,
            listen_addrs,
            mut swarm,
            known_peers,
            mut payload_rx,
            mut peers,
            cancellation_token,
        } = self;

        for addr in listen_addrs {
            swarm
                .listen_on(addr)
                .wrap_err("swarm failed to listen on multiaddr")?;
        }

        for mut address in known_peers {
            let peer_id = match address.pop() {
                Some(multiaddr::Protocol::P2p(peer_id)) => peer_id,
                _ => {
                    eyre::bail!("no peer ID for known peer");
                }
            };
            swarm.add_peer_address(peer_id, address.clone());
            swarm
                .dial(address)
                .wrap_err("swarm failed to dial known peer")?;
        }

        loop {
            tokio::select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    debug!("cancellation token triggered, shutting down node");
                    break Ok(());
                }
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr {
                            address,
                            ..
                        } => {
                            debug!("new listen address: {address}");
                        }
                        SwarmEvent::ExternalAddrConfirmed { address } => {
                            debug!("external address confirmed: {address}");
                        }
                        SwarmEvent::ConnectionEstablished {
                            peer_id,
                            connection_id,
                            ..
                        } => {
                            info!("connection established with peer {peer_id}");
                            if peers.has_peer(&peer_id) {
                                swarm.close_connection(connection_id);
                                debug!("already have connection with peer {peer_id}, closed connection {connection_id}");
                            } else {
                                match swarm
                                    .behaviour_mut()
                                    .new_control()
                                    .open_stream(peer_id, FLASHBLOCKS_STREAM_PROTOCOL)
                                    .await
                                {
                                    Ok(stream) => { peers.insert_peer_and_stream(peer_id, stream);
                                        info!("opened stream with peer {peer_id} on connection {connection_id}");
                                    }
                                    Err(e) => {
                                        warn!("failed to open stream with peer {peer_id} on connection {connection_id}: {e:?}");
                                    }
                                }
                            }
                        }
                        SwarmEvent::ConnectionClosed {
                            peer_id,
                            cause,
                            ..
                        } => {
                            info!("connection closed with peer {peer_id}: {cause:?}");
                            peers.remove_peer(&peer_id);
                        }
                        SwarmEvent::Behaviour(event) => event.handle().await,
                        _ => continue,
                    }
                },
                Some(payload) = payload_rx.recv() => {
                    let peer_count = swarm.network_info().num_peers();
                    info!(peer_count, "received new payload to broadcast to peers");
                    peers.broadcast_payload(payload).await;
                }
            }
        }
    }
}

pub struct NodeBuilder {
    port: Option<u16>,
    listen_addrs: Vec<libp2p::Multiaddr>,
    keypair_hex: Option<String>,
    known_peers: Vec<Multiaddr>,
    cancellation_token: Option<tokio_util::sync::CancellationToken>,
}

impl Default for NodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeBuilder {
    pub fn new() -> Self {
        Self {
            port: None,
            listen_addrs: Vec::new(),
            keypair_hex: None,
            known_peers: Vec::new(),
            cancellation_token: None,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_listen_addr(mut self, addr: libp2p::Multiaddr) -> Self {
        self.listen_addrs.push(addr);
        self
    }

    pub fn with_keypair_hex_string(mut self, keypair_hex: String) -> Self {
        self.keypair_hex = Some(keypair_hex);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_known_peers<I, T>(mut self, addresses: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<Multiaddr>,
    {
        for address in addresses {
            self.known_peers.push(address.into());
        }
        self
    }

    pub fn try_build(self) -> eyre::Result<(Node, tokio::sync::mpsc::Sender<Message>, Control)> {
        let Self {
            port,
            mut listen_addrs,
            keypair_hex,
            known_peers,
            cancellation_token,
        } = self;

        let keypair = match keypair_hex {
            Some(hex) => {
                let mut bytes = hex::decode(hex).wrap_err("failed to decode hex string")?;
                let keypair = ed25519::Keypair::try_from_bytes(&mut bytes)
                    .wrap_err("failed to create keypair from bytes: {e}")?;
                Some(keypair.into())
            }
            None => None,
        };
        let keypair = keypair.unwrap_or(identity::Keypair::generate_ed25519());
        let peer_id = keypair.public().to_peer_id();

        let transport = create_transport(&keypair)?;
        let mut behaviour = Behaviour::new(&keypair, DEFAULT_AGENT_VERSION.to_string())
            .context("failed to create behaviour")?;
        let control = behaviour.new_control();

        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_other_transport(|_| transport)?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)) // don't disconnect from idle peers
            })
            .build();
        if listen_addrs.is_empty() {
            let port = port.unwrap_or(0);
            let listen_addr = format!("/ip4/0.0.0.0/tcp/{port}")
                .parse()
                .expect("can parse valid multiaddr");
            listen_addrs.push(listen_addr);
        }

        let (tx, rx) = tokio::sync::mpsc::channel(100);

        Ok((
            Node {
                peer_id,
                swarm,
                listen_addrs,
                known_peers,
                payload_rx: rx,
                peers: Peers::new(),
                cancellation_token: cancellation_token.unwrap_or_default(),
            },
            tx,
            control,
        ))
    }
}

fn create_transport(
    keypair: &identity::Keypair,
) -> eyre::Result<libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>> {
    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(noise::Config::new(keypair)?)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .boxed();

    Ok(transport)
}

#[cfg(test)]
mod test {
    use super::*;

    use futures::StreamExt as _;
    use tokio_util::{
        codec::{FramedRead, LinesCodec},
        compat::FuturesAsyncReadCompatExt as _,
    };

    #[tokio::test]
    async fn two_nodes_can_connect() {
        let (node1, _, mut control1) = NodeBuilder::new()
            .with_listen_addr("/ip4/127.0.0.1/tcp/9000".parse().unwrap())
            .try_build()
            .unwrap();
        let (node2, tx2, _) = NodeBuilder::new()
            .with_known_peers(node1.multiaddrs())
            .with_listen_addr("/ip4/127.0.0.1/tcp/9001".parse().unwrap())
            .try_build()
            .unwrap();
        let mut incoming1 = control1.accept(FLASHBLOCKS_STREAM_PROTOCOL).unwrap();

        tokio::spawn(async move { node1.run().await });
        tokio::spawn(async move { node2.run().await });
        // sleep to allow nodes to connect
        tokio::time::sleep(Duration::from_secs(3)).await;

        tokio::spawn(async move {
            tx2.send("message".to_string()).await.unwrap();
        });

        let (_, stream) = incoming1.next().await.unwrap();
        let codec = LinesCodec::new();
        let mut reader = FramedRead::new(stream.compat(), codec);
        let str = reader.next().await.unwrap().unwrap();
        assert_eq!(str, "message".to_string());
        // let payload: Message = serde_json::from_str(&str).unwrap();
        // assert_eq!(payload, Message::default());
    }
}
