// módulo de descobertas de dispositivos através do protocolo ARP
// responsabilidades
// - identificar a interface de rede utilizada
// - calcular a rede local
// - enviar requisições ARP
// - receber e validar respostas ARP
// - retornar os dispositivos encontrados de forma estruturada
// documentação da biblioteca: https://docs.rs/pcap/latest/pcap/

// bibliotecas
use chrono::{DateTime, Utc};
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::arp::{
    ArpHardwareTypes,
    ArpOperations,
    ArpPacket,
    MutableArpPacket,
};
use pnet::packet::ethernet::{
    EtherTypes,
    EthernetPacket,
    MutableEthernetPacket,
};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};


use crate::dbconnection::insert_arp_table;
use crate::dbconnection::check_mac_prefix;


// depuração de erros durante a descoberta ARP
#[derive(Debug)]
pub enum ArpError {
    // nenhuma interface de rede adequada foi encontrada
    InterfaceNotFound,
    // a interface não possui endereço MAC (modo loop)
    MacAddressNotFound,
    // a interface não possui endereço ipv4
    Ipv4AddressNotFound,
    // não possível criar o canal Ethernet
    EthernetChannelUnavailable,
    // não foi possível construir o pacote Ethernet
    EthernetPacketCreationFailed,
    // não foi possível construir o pacote ARP
    ArpPacketCreationFailed,
    // falha durante o envio do pacote ARP
    PacketSendFailed,
    // máscara de rede inválida
    InvalidNetmask,
}

// exibição de erros
// criar depois desta versão o envio desses erros
// para uma base de logs robusta
impl std::fmt::Display for ArpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            ArpError::InterfaceNotFound =>
                "[x] interface de rede não encontrada",
            ArpError::MacAddressNotFound =>
                "[x] interface não possui endereço MAC",
            ArpError::Ipv4AddressNotFound =>
                "[x] interface não possui endereço IPv4",
            ArpError::EthernetChannelUnavailable =>
                "[x] canal Ethernet indisponível",
            ArpError::EthernetPacketCreationFailed =>
                "[x] não foi possível criar o pacote Ethernet",
            ArpError::ArpPacketCreationFailed =>
                "[x] não foi possível criar o pacote ARP",
            ArpError::PacketSendFailed =>
                "[x] falha ao enviar pacote ARP",
            ArpError::InvalidNetmask =>
                "[x] máscara de rede inválida",
        };
        write!(formatter, "{}", message)
    }
}

impl std::error::Error for ArpError {}




// resultado da descoberta ARP
// esse bloco monta o resutado de um IP descoberto na rede
#[derive(Debug, Clone)]
pub struct ArpResult {
    // endereço ipv4 descoberto
    pub ip: Ipv4Addr,
    // endereço MAC identificado
    pub mac: MacAddr,
    // timestamp do resultado
    pub timestamp: DateTime<Utc>,
}


// dados necessários para enviar o pacote ARP
#[derive(Debug, Clone)]
pub struct NetworkContext {
    // interface de rede utilizada
    pub interface: NetworkInterface,
    // endereço MAC da interface
    pub source_mac: MacAddr,
    // endereço de IP da interface
    pub source_ip: Ipv4Addr,
    // máscara de rede da interface
    pub netmask: Ipv4Addr,
    // endereço de rede local
    pub network: Ipv4Addr,
}


// função para descobrir as interfaces de rede
pub fn discovery_interface() -> Result<NetworkContext, ArpError> {
    // obtém todas as interfaces de rede disponíveis
    let interfaces = datalink::interfaces();

    // procura uma interface ativa que não esteja em loopback
    // e evidentemente possua um endereço de ipv4
    let interface = interfaces
        .into_iter()
        .find(|interface| {
            interface.is_up()
                && !interface.is_loopback()
                && interface.ips.iter().any(|ip| ip.is_ipv4())
        })
        .ok_or(ArpError::InterfaceNotFound)?;



    // obtém o endereço MAC da interface.
    let source_mac = interface.mac.ok_or(ArpError::MacAddressNotFound)?;


    // obtém o primeiro endereço IPv4 configurado na interface.
    let ipv4_network = interface.ips.iter().find(|ip| ip.is_ipv4()).ok_or(ArpError::Ipv4AddressNotFound)?;


    // extrai o endereço IPv4.
    let source_ip = match ipv4_network.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Err(ArpError::Ipv4AddressNotFound),
    };


    // extrai a máscara de rede.
    let netmask = match ipv4_network.mask() {
        std::net::IpAddr::V4(mask) => mask,
        _ => return Err(ArpError::InvalidNetmask),
    };


    // calcula o endereço de rede
    let network = Ipv4Addr::from(
        u32::from(source_ip) & u32::from(netmask)
    );

    // todos os dados foram coletados com sucesso
    // armazena em cada variável do contexto Network
    Ok(NetworkContext {
        interface,
        source_mac,
        source_ip,
        netmask,
        network,
    })


}



// cria o pacote ARP
pub fn build_arp_request(
    buffer: &mut [u8; 42],
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<(), ArpError> {

    // cria o frame ethernet
    let mut ethernet_packet =
        MutableEthernetPacket::new(buffer)
            .ok_or(ArpError::EthernetPacketCreationFailed)?;
    
    // estabelece como destino de envio do pacote
    // o broadcast (0.0.0.0) enviando para todas as máquinas
    ethernet_packet.set_destination(MacAddr::broadcast());

    // define o MAC address da interface
    ethernet_packet.set_source(source_mac);

    // define o tipo de frame do pacote (ARP)
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    // cria o pacote ARP dentro do payload Ethernet
    let mut arp_packet =
        MutableArpPacket::new(ethernet_packet.payload_mut())
            .ok_or(ArpError::ArpPacketCreationFailed)?;

    // define ethernet como hardware utilizado
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);

    // define ipv4 como protocolo a ser utilizado
    // no transporte do pacote
    arp_packet.set_protocol_type(EtherTypes::Ipv4);

    // o tamanho do endereço MAC em bytes deve
    // ser informado dentro do pacote
    arp_packet.set_hw_addr_len(6);

    // o tamanho do endereço ipv4 também
    arp_packet.set_proto_addr_len(4);

    // define a operação como uma requisição ARP
    arp_packet.set_operation(ArpOperations::Request);

    // define endereço MAC do remetente
    arp_packet.set_sender_hw_addr(source_mac);

    // define o endereço ipv4 do remetente
    arp_packet.set_sender_proto_addr(source_ip);

    // o endereço MAC do alvo é desconhecido neste momento
    // uma vez que estamos enviando um broadcast
    // por isso o valor do MAC é 0
    arp_packet.set_target_hw_addr(MacAddr::zero());

    // define o endereço ipv4 que queremos descobrir
    // who ?
    arp_packet.set_target_proto_addr(target_ip);

    Ok(())
}


// verifica a validade da resposta recebida pelo alvo
pub fn is_valid_arp_reply(
    packet: &[u8],
    target_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
) -> Option<MacAddr> {

    // verifica se oque foi recebido é um frame ethernet
    let ethernet_packet = EthernetPacket::new(packet)?;

    // ignora qualquer frame que não seja ARP
    if ethernet_packet.get_ethertype() != EtherTypes::Arp {
        return None;
    }

    // tenta interpretar o payload como pacote ARP
    let arp_packet = ArpPacket::new(ethernet_packet.payload())?;

    // aceitamos somente respostas ARP
    if arp_packet.get_operation() != ArpOperations::Reply {
        return None;
    }

    // verifica se a resposta pertence ao endereço desejado
    // se realmente o alvo é que respondeu ao pacote
    if arp_packet.get_sender_proto_addr() != target_ip {
        return None;
    }

    // verifica se a resposta foi direcionada para nossa interface
    if arp_packet.get_target_proto_addr() != source_ip {
        return None;
    }

    // retorna o endereço MAC do nosso alvo
    Some(arp_packet.get_sender_hw_addr())

}


// executa a requisição ARP
// interessante verificar o diagrama do
// pacote ARP para entender tamanho dos bytes dos blocos
// https://ipcisco.com/wp-content/uploads/2018/10/arp-packet-format-ipcisco.jpg

pub fn probe(
    // tx => refere-se aos pacotes de rede que estão sendo enviados (transmitidos) pela placa de rede.
    tx: &mut Box<dyn pnet::datalink::DataLinkSender>,
    // rx => refere-se aos pacores de rede que estãso wendo recebidos pela placa de rede
    rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<Option<MacAddr>, ArpError> {

    // cabeçalho ethernet = 14 bytes
    // pacote ARP = 28 bytes
    // cabeçalho + pacote = 42 bytes
    // especifica o buffer do pacote em bytes (42)
    let mut ethernet_buffer = [0u8; 42];

    // constrói a requisição ARP
    build_arp_request(
        &mut ethernet_buffer,
        source_mac,
        source_ip,
        target_ip,
    )?;


    // envia o frame ethernet
    // nesta etapa utiliza-se a ancora TX (envio)
    tx.send_to(&ethernet_buffer, None)
        .ok_or(ArpError::PacketSendFailed)?
        .map_err(|_| ArpError::PacketSendFailed)?;

    // define um período de espera
    let start = Instant::now();

    // aguarda uma resposta até atingir o timeout
    while start.elapsed() < timeout {
        // tenta obter o próximo frame recebido
        let packet = match rx.next() {
            Ok(packet) => packet,
            Err(_) => continue,
        };

        // verifica se o pacote recebido é uma resposta válida
        if let Some(mac) = is_valid_arp_reply(
            packet,
            target_ip,
            source_ip,
        ) {
            return Ok(Some(mac));
        }
    }

    // nenhum dispositivo respondeu dentro
    // do tempo estipulado
    Ok(None)

}


// calcula o primeiro endereço de host da rede
fn first_host(network: Ipv4Addr) -> Ipv4Addr {
    let network = u32::from(network);
    Ipv4Addr::from(network + 1)
}


// calcula o último endereço de host da rede
// esse código define o tamanho da rede
fn last_host(network: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    let network = u32::from(network);
    let mask = u32::from(netmask);
    let broadcast = network | !mask;
    Ipv4Addr::from(broadcast - 1)
}


// inicia o scan na rede local => ordem de funcionamento
// 1. identifica a interface;
// 2. obtém IP, MAC e máscara de rede;
// 3. calcula a rede local;
// 4. cria um único canal ethernet;
// 5. envia requisições ARP para os hosts;
// 6. valida as respostas;
// 7. retorna os dispositivos encontrados;
pub fn scan() -> Result<(), ArpError> {
    // descobre o contexto de rede utilizado pelo scan
    let context = discovery_interface()?;

    // abre o canal Ethernet
    let (mut tx, mut rx) = match datalink::channel(
        &context.interface,
        Default::default(),
    ) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(ArpError::EthernetChannelUnavailable),
        Err(_) => return Err(ArpError::EthernetChannelUnavailable),
    };

    // calcula o primeiro e o último endereço de IP da rede
    let first = u32::from(first_host(context.network));
    let last = u32::from(last_host(context.network, context.netmask));

    // timeout individual de cada consulta ARP
    let timeout = Duration::from_millis(500);

    // percorre os hosts válidos da rede
    for address in first..=last {
        let target_ip = Ipv4Addr::from(address);

        // ignora o próprio endereço IP
        if target_ip == context.source_ip {
            continue;
        }

        // consulta o endereço IP via ARP
        match probe(
            &mut tx,
            &mut rx,
            context.source_mac,
            context.source_ip,
            target_ip,
            timeout,
        ) {
            Ok(Some(mac)) => {
                // dispositivo encontrado
                let timestamp = Utc::now();
                let mac_addr = mac.to_string().to_uppercase();

                // exibe os dados imediatamente
                println!(
                    "IP: {}\tMAC: {}\tTimestamp: {}",
                    target_ip,
                    mac_addr,
                    timestamp
                );

                // mac slice
                let mac_prefix: &str = &mac_addr [0..8];
                match check_mac_prefix(mac_prefix) {
                    Ok(mac_factory) => {
                        let ip_addr = target_ip.to_string();
                        let _resultado = insert_arp_table(&ip_addr, &mac_addr, &mac_factory);
                    }
                    Err(error) => {
                        eprintln!("Erro ao consultar fabricante: {}", error);
                    }
                }
                


            }

            Ok(None) => {
                // Nenhuma resposta recebida
            }

            Err(error) => {
                eprintln!(
                    "[!] Erro ao consultar {}: {}",
                    target_ip,
                    error
                );
            }
        }
    }

    Ok(())
}