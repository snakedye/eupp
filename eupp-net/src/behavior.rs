use crate::protocol::{SyncRequest, SyncResponse};
use libp2p::{gossipsub, mdns, request_response, swarm::NetworkBehaviour};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "EuppBehaviourEvent")]
pub struct EuppBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub sync: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
}

#[derive(Debug)]
pub enum EuppBehaviourEvent {
    Mdns(mdns::Event),
    Gossipsub(gossipsub::Event),
    Sync(request_response::Event<SyncRequest, SyncResponse>),
}

impl From<mdns::Event> for EuppBehaviourEvent {
    fn from(event: mdns::Event) -> Self {
        EuppBehaviourEvent::Mdns(event)
    }
}

impl From<gossipsub::Event> for EuppBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        EuppBehaviourEvent::Gossipsub(event)
    }
}

impl From<request_response::Event<SyncRequest, SyncResponse>> for EuppBehaviourEvent {
    fn from(event: request_response::Event<SyncRequest, SyncResponse>) -> Self {
        EuppBehaviourEvent::Sync(event)
    }
}
