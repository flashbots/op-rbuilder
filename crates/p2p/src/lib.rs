mod behaviour;
mod peers;

use behaviour::Behaviour;
use libp2p_stream::IncomingStreams;
use peers::OutgoingStreamsHandler;

use eyre::Context;
use libp2p::{
    PeerId, Swarm, Transport as _,
    identity::{self, ed25519},
    noise,
    swarm::SwarmEvent,
    tcp, yamux,
};
use std::{collections::HashMap, time::Duration};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub use libp2p::{Multiaddr, StreamProtocol};

/// A message that can be sent between peers.
pub trait Message:
    serde::Serialize + for<'de> serde::Deserialize<'de> + Send + Sync + Clone + std::fmt::Debug
{
    fn protocol(&self) -> StreamProtocol;
}

pub struct Node<M> {
    peer_id: PeerId,
    listen_addrs: Vec<libp2p::Multiaddr>,
    swarm: Swarm<Behaviour>,
    known_peers: Vec<Multiaddr>,
    outgoing_message_rx: mpsc::Receiver<M>,
    outgoing_streams_handler: OutgoingStreamsHandler,
    cancellation_token: tokio_util::sync::CancellationToken,
    incoming_streams_handlers: Vec<IncomingStreamsHandler<M>>,
    protocols: Vec<StreamProtocol>,
}

impl<M: Message + 'static> Node<M> {
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
            mut outgoing_message_rx,
            mut outgoing_streams_handler,
            cancellation_token,
            incoming_streams_handlers,
            protocols,
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

        let handles = incoming_streams_handlers
            .into_iter()
            .map(|handler| tokio::spawn(handler.run()))
            .collect::<Vec<_>>();

        loop {
            tokio::select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    debug!("cancellation token triggered, shutting down node");
                    handles.into_iter().for_each(|h| h.abort());
                    break Ok(());
                }
                Some(message) = outgoing_message_rx.recv() => {
                    let protocol = message.protocol();
                    if let Err(e) = outgoing_streams_handler.broadcast_message(message).await {
                        warn!("failed to broadcast message on protocol {protocol}: {e:?}");
                    }
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
                            debug!("connection established with peer {peer_id}");
                            if outgoing_streams_handler.has_peer(&peer_id) {
                                swarm.close_connection(connection_id);
                                debug!("already have connection with peer {peer_id}, closed connection {connection_id}");
                            } else {
                                for protocol in &protocols {
                                    match swarm
                                    .behaviour_mut()
                                    .new_control()
                                    .open_stream(peer_id, protocol.clone())
                                    .await
                                {
                                    Ok(stream) => { outgoing_streams_handler.insert_peer_and_stream(peer_id, protocol.clone(), stream);
                                        debug!("opened outbound stream with peer {peer_id} with protocol {protocol} on connection {connection_id}");
                                    }
                                    Err(e) => {
                                        warn!("failed to open stream with peer {peer_id} on connection {connection_id}: {e:?}");
                                    }
                                }
                                }
                            }
                        }
                        SwarmEvent::ConnectionClosed {
                            peer_id,
                            cause,
                            ..
                        } => {
                            debug!("connection closed with peer {peer_id}: {cause:?}");
                            outgoing_streams_handler.remove_peer(&peer_id);
                        }
                        SwarmEvent::Behaviour(event) => event.handle().await,
                        _ => continue,
                    }
                },
            }
        }
    }
}

pub struct NodeBuildResult<M> {
    pub node: Node<M>,
    pub outgoing_message_tx: mpsc::Sender<M>,
    pub incoming_message_rxs: HashMap<StreamProtocol, mpsc::Receiver<M>>,
}

pub struct NodeBuilder {
    port: Option<u16>,
    listen_addrs: Vec<libp2p::Multiaddr>,
    keypair_hex: Option<String>,
    known_peers: Vec<Multiaddr>,
    agent_version: Option<String>,
    protocols: Vec<StreamProtocol>,
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
            agent_version: None,
            protocols: Vec::new(),
            cancellation_token: None,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_listen_addr(mut self, addr: libp2p::Multiaddr) -> Self {
        self.listen_addrs.push(addr);
        self
    }

    pub fn with_keypair_hex_string(mut self, keypair_hex: String) -> Self {
        self.keypair_hex = Some(keypair_hex);
        self
    }

    pub fn with_agent_version(mut self, agent_version: String) -> Self {
        self.agent_version = Some(agent_version);
        self
    }

    pub fn with_protocol(mut self, protocol: StreamProtocol) -> Self {
        self.protocols.push(protocol);
        self
    }

    pub fn with_cancellation_token(
        mut self,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) -> Self {
        self.cancellation_token = Some(cancellation_token);
        self
    }

    pub fn with_known_peers<I, T>(mut self, addresses: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<Multiaddr>,
    {
        for address in addresses {
            self.known_peers.push(address.into());
        }
        self
    }

    pub fn try_build<M: Message + 'static>(self) -> eyre::Result<NodeBuildResult<M>> {
        let Self {
            port,
            mut listen_addrs,
            keypair_hex,
            known_peers,
            agent_version,
            protocols,
            cancellation_token,
        } = self;

        let Some(agent_version) = agent_version else {
            eyre::bail!("agent version must be set");
        };

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
        let mut behaviour =
            Behaviour::new(&keypair, agent_version).context("failed to create behaviour")?;
        let mut control = behaviour.new_control();

        let mut incoming_streams_handlers = Vec::new();
        let mut incoming_message_rxs = HashMap::new();
        for protocol in &protocols {
            let incoming_streams = control
                .accept(protocol.clone())
                .wrap_err("failed to subscribe to incoming streams for flashblocks protocol")?;
            let (incoming_streams_handler, message_rx) =
                IncomingStreamsHandler::new(protocol.clone(), incoming_streams);
            incoming_streams_handlers.push(incoming_streams_handler);
            incoming_message_rxs.insert(protocol.clone(), message_rx);
        }

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

        let (outgoing_message_tx, outgoing_message_rx) = tokio::sync::mpsc::channel(100);

        Ok(NodeBuildResult {
            node: Node {
                peer_id,
                swarm,
                listen_addrs,
                known_peers,
                outgoing_message_rx,
                outgoing_streams_handler: OutgoingStreamsHandler::new(),
                cancellation_token: cancellation_token.unwrap_or_default(), // TODO: caller must provide this
                incoming_streams_handlers,
                protocols,
            },
            outgoing_message_tx,
            incoming_message_rxs,
        })
    }
}

struct IncomingStreamsHandler<M> {
    protocol: StreamProtocol,
    incoming: IncomingStreams,
    tx: mpsc::Sender<M>,
}

impl<M: Message + 'static> IncomingStreamsHandler<M> {
    fn new(protocol: StreamProtocol, incoming: IncomingStreams) -> (Self, mpsc::Receiver<M>) {
        // TODO: make channel size configurable
        let (tx, rx) = mpsc::channel(100);
        (
            Self {
                protocol,
                incoming,
                tx,
            },
            rx,
        )
    }

    async fn run(self) {
        use futures::StreamExt as _;

        let Self {
            protocol,
            mut incoming,
            tx,
        } = self;
        let mut handle_stream_futures = futures::stream::FuturesUnordered::new();

        tokio::select! {
            Some((from, stream)) = incoming.next() => {
                info!("new incoming stream on protocol {protocol} from peer {from}");
                handle_stream_futures.push(tokio::spawn(handle_incoming_stream(from, stream, tx.clone())));
            }
            Some(res) = handle_stream_futures.next() => {
                match res {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        warn!("error handling incoming stream: {e:?}");
                    }
                    Err(e) => {
                        warn!("task handling incoming stream panicked: {e:?}");
                    }
                }
            }
        }
    }
}

async fn handle_incoming_stream<M: Message>(
    peer_id: PeerId,
    stream: libp2p::Stream,
    payload_tx: mpsc::Sender<M>,
) -> eyre::Result<()> {
    use futures::StreamExt as _;
    use tokio_util::{
        codec::{FramedRead, LinesCodec},
        compat::FuturesAsyncReadCompatExt as _,
    };

    let codec = LinesCodec::new();
    let mut reader = FramedRead::new(stream.compat(), codec);

    loop {
        match reader.next().await {
            Some(Ok(str)) => {
                let payload: M = serde_json::from_str(&str)
                    .wrap_err("failed to decode stream message into FlashblocksPayloadV1")?;
                info!("got message from peer {peer_id}: {payload:?}");
                let _ = payload_tx.send(payload).await;
            }
            Some(Err(e)) => {
                return Err(e).wrap_err(format!("failed to read from stream of peer {peer_id}"));
            }
            None => {}
        }
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

    const TEST_AGENT_VERSION: &str = "test/1.0.0";
    const TEST_PROTOCOL: StreamProtocol = StreamProtocol::new("/test/1.0.0");

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct TestMessage {
        content: String,
    }

    impl Message for TestMessage {
        fn protocol(&self) -> StreamProtocol {
            TEST_PROTOCOL
        }
    }

    impl serde::Serialize for TestMessage {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(&self.content)
        }
    }

    impl<'de> serde::Deserialize<'de> for TestMessage {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Ok(TestMessage { content: s })
        }
    }

    #[tokio::test]
    async fn two_nodes_can_connect_and_message() {
        let NodeBuildResult {
            node: node1,
            outgoing_message_tx: _,
            incoming_message_rxs: mut rx1,
        } = NodeBuilder::new()
            .with_listen_addr("/ip4/127.0.0.1/tcp/9000".parse().unwrap())
            .with_agent_version(TEST_AGENT_VERSION.to_string())
            .with_protocol(TEST_PROTOCOL)
            .try_build::<TestMessage>()
            .unwrap();
        let NodeBuildResult {
            node: node2,
            outgoing_message_tx: tx2,
            incoming_message_rxs: _,
        } = NodeBuilder::new()
            .with_known_peers(node1.multiaddrs())
            .with_protocol(TEST_PROTOCOL)
            .with_listen_addr("/ip4/127.0.0.1/tcp/9001".parse().unwrap())
            .with_agent_version(TEST_AGENT_VERSION.to_string())
            .try_build::<TestMessage>()
            .unwrap();

        tokio::spawn(async move { node1.run().await });
        tokio::spawn(async move { node2.run().await });
        // sleep to allow nodes to connect
        tokio::time::sleep(Duration::from_secs(2)).await;

        let message = TestMessage {
            content: "message".to_string(),
        };
        tx2.send(message.clone()).await.unwrap();

        let recv_message: TestMessage = rx1.remove(&TEST_PROTOCOL).unwrap().recv().await.unwrap();
        assert_eq!(recv_message, message);
    }
}
