use crate::packet::TCPPacket;
use crate::tcpflags;
use anyhow::{Context, Result};
use pnet::packet::{ip::IpNextHeaderProtocols, Packet};
use pnet::transport::{self, TransportChannelType, TransportProtocol, TransportSender};
use pnet::util;
use std::collections::VecDeque;
use std::fmt::{self, Display};
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

const SOCKET_BUFFER_SIZE: usize = 4380;

/// 0: 送信元IPアドレス <br/>
/// 1: 宛先IPアドレス <br/>
/// 2: 送信元ポート <br/>
/// 3: 宛先ポート
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub struct SockID(pub Ipv4Addr, pub Ipv4Addr, pub u16, pub u16);

#[derive(Clone, Debug)]
pub struct SendParam {
    /// 送信後まだ ack されていない seq の先頭
    pub unacked_seq: u32,
    /// 次の送信
    pub next: u32,
    /// 送信ウィンドウサイズ
    pub window: u16,
    /// 初期送信 seq
    pub initial_seq: u32,
}

#[derive(Clone, Debug)]
pub struct RecvParam {
    /// 次に送信する seq
    pub next: u32,
    /// 受信ウィンドウ
    pub window: u16,
    /// 初期受信 seq
    pub initial_seq: u32,
    /// 受信 seq の最後尾
    pub tail: u32,
}

#[derive(Debug, Clone)]
pub struct RetransmissionQueryEntry {
    pub packet: TCPPacket,
    pub latest_transmission_time: SystemTime,
    pub transmission_count: u8,
}

impl RetransmissionQueryEntry {
    fn new(packet: TCPPacket) -> Self {
        Self {
            packet,
            latest_transmission_time: SystemTime::now(),
            transmission_count: 1,
        }
    }
}

pub struct Socket {
    pub local_addr: Ipv4Addr,
    pub remote_addr: Ipv4Addr,
    pub local_port: u16,
    pub remote_port: u16,
    pub send_param: SendParam,
    pub recv_param: RecvParam,
    pub status: TcpStatus,
    /// 組み立てた受信データを保管するバッファ
    pub recv_buffer: Vec<u8>,
    /// セグメントが消失した時のためのセグメント保管キュー
    pub retransmission_queue: VecDeque<RetransmissionQueryEntry>,
    /// 接続済みソケットを保持するキュー、リスニングソケットでのみ使用
    pub connected_connection_queue: VecDeque<SockID>,
    /// 生成元のリスニングソケット、接続済みソケットでのみ使用
    pub listening_socket: Option<SockID>,
    pub sender: TransportSender,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum TcpStatus {
    /// リモートホストからのコネクション要求待ち
    Listen,
    /// コネクション要求の送信後、応答確認と対応するコネクション要求待ち
    SynSent,
    /// 同期（SYN）セグメントを受信し、対応する同期（SYN/ACK）セグメントを送信後、コネクション応答確認待ち
    SynRcvd,
    /// コネクションが開かれ、データ転送が行える通常の状態
    Established,
    /// リモートホストからのコネクション終了要求、もしくはすでに送った終了要求の応答確認待ち
    FinWait1,
    /// リモートホストからの終了要求待ち
    FinWait2,
    /// コネクション終了要求応答確認をリモートホストが確実に受取るのに必要な時間が経過するまでの待機状態
    TimeWait,
    /// アプリケーションプロセスからのコネクション終了要求待ち
    CloseWait,
    /// リモートホストに送ったコネクション終了要求についての応答確認待ち
    LastAck,
}

impl Display for TcpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpStatus::Listen => write!(f, "LISTEN"),
            TcpStatus::SynSent => write!(f, "SYBSENT"),
            TcpStatus::SynRcvd => write!(f, "SYNRCVD"),
            TcpStatus::Established => write!(f, "ESTABLISHED"),
            TcpStatus::FinWait1 => write!(f, "FINWAIT1"),
            TcpStatus::FinWait2 => write!(f, "FINWAIT2"),
            TcpStatus::TimeWait => write!(f, "TIMEWAIT"),
            TcpStatus::CloseWait => write!(f, "CLOSEWAIT"),
            TcpStatus::LastAck => write!(f, "LASTACK"),
        }
    }
}

impl Socket {
    pub fn new(
        local_addr: Ipv4Addr,
        remote_addr: Ipv4Addr,
        local_port: u16,
        remote_port: u16,
        status: TcpStatus,
    ) -> Result<Self> {
        let (sender, _) = transport::transport_channel(
            65535,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        )?;
        Ok(Self {
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            send_param: SendParam {
                unacked_seq: 0,
                next: 0,
                window: SOCKET_BUFFER_SIZE as u16,
                initial_seq: 0,
            },
            recv_param: RecvParam {
                next: 0,
                window: SOCKET_BUFFER_SIZE as u16,
                initial_seq: 0,
                tail: 0,
            },
            status,
            recv_buffer: vec![0; SOCKET_BUFFER_SIZE],
            retransmission_queue: VecDeque::new(),
            connected_connection_queue: VecDeque::new(),
            listening_socket: None,
            sender,
        })
    }

    pub fn send_tcp_packet(
        &mut self,
        seq: u32,
        ack: u32,
        flag: u8,
        payload: &[u8],
    ) -> Result<usize> {
        let mut tcp_packet = TCPPacket::new(payload.len());
        tcp_packet.set_src(self.local_port);
        tcp_packet.set_dest(self.remote_port);
        tcp_packet.set_seq(seq);
        tcp_packet.set_ack(ack);
        tcp_packet.set_data_offset(5); // option フィールドを使用しないので固定
        tcp_packet.set_flag(flag);
        tcp_packet.set_window_size(self.recv_param.window);
        tcp_packet.set_payload(payload);
        tcp_packet.set_checksum(util::ipv4_checksum(
            &tcp_packet.packet(),
            8,
            &[],
            &self.local_addr,
            &self.remote_addr,
            IpNextHeaderProtocols::Tcp,
        ));
        let send_size = self
            .sender
            .send_to(tcp_packet.clone(), IpAddr::V4(self.remote_addr))
            .context(format!("failed to send: \n{:?}", tcp_packet))?;

        dbg!("sent", &tcp_packet);

        // 確認応答は再送対象ではない
        // 確認応答のための確認応答...のループになってしまうため
        if payload.is_empty() && tcp_packet.get_flag() == tcpflags::ACK {
            return Ok(send_size);
        }

        // 再送時用のキューにペイロードを格納
        self.retransmission_queue
            .push_back(RetransmissionQueryEntry::new(tcp_packet));
        Ok(send_size)
    }

    pub fn get_sock_id(&self) -> SockID {
        SockID(
            self.local_addr,
            self.remote_addr,
            self.local_port,
            self.remote_port,
        )
    }
}
