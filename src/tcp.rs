use crate::packet::TCPPacket;
use crate::socket::{SockID, Socket, TcpStatus};
use crate::tcpflags;
use anyhow::{Context, Result};
use pnet::packet::{ip::IpNextHeaderProtocols, tcp::TcpPacket, Packet};
use pnet::transport::{self, TransportChannelType};
use rand::{rngs::ThreadRng, Rng};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex, RwLock, RwLockWriteGuard};
use std::time::{Duration, SystemTime};
use std::{cmp, ops::Range, str, thread};

const UNDETERMINED_IP_ADDR: std::net::Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const UNDETERMINED_PORT: u16 = 0;
const MAX_TRANSMITTION: u8 = 5;
const RETRANSMITTION_TIMEOUT: u64 = 3;
const MSS: usize = 1460;
const PORT_RANGE: Range<u16> = 40000..60000;

#[derive(Debug, Clone, PartialEq)]
struct TCPEvent {
    /// イベント発生元のソケットID
    sock_id: SockID,
    kind: TCPEventKind,
}

impl TCPEvent {
    fn new(sock_id: SockID, kind: TCPEventKind) -> Self {
        Self { sock_id, kind }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TCPEventKind {
    ConnectionComplated,
    Acked,
    DataArrived,
    ConnectionClosed,
}

pub struct TCP {
    sockets: RwLock<HashMap<SockID, Socket>>,
    event_condvar: (Mutex<Option<TCPEvent>>, Condvar),
}

impl TCP {
    pub fn new() -> Arc<Self> {
        let sockets = RwLock::new(HashMap::new());
        let tcp = Arc::new(Self {
            sockets,
            event_condvar: (Mutex::new(None), Condvar::new()),
        });

        // パケットの受信スレッドを作成
        let cloned_tcp = tcp.clone();
        std::thread::spawn(move || {
            cloned_tcp.receive_handler().unwrap();
        });

        // 再送を管理するためのタイマースレッドを作成
        let cloned_tcp = tcp.clone();
        std::thread::spawn(move || {
            cloned_tcp.timer();
        });

        tcp
    }

    /// リスニングそっケットを生成してそのIDを返す
    pub fn listen(&self, local_addr: Ipv4Addr, local_port: u16) -> Result<SockID> {
        let socket = Socket::new(
            local_addr,
            UNDETERMINED_IP_ADDR, // 接続先IPアドレスは未定
            local_port,
            UNDETERMINED_PORT, // 接続先ポートは未定
            TcpStatus::Listen,
        )?;

        let mut lock = self.sockets.write().unwrap();
        let sock_id = socket.get_sock_id();
        lock.insert(sock_id, socket);
        Ok(sock_id)
    }

    /// 接続済みソケットが生成されるまで待機し、生成されたのちそのIDを返す
    pub fn accept(&self, sock_id: SockID) -> Result<SockID> {
        self.wait_event(sock_id, TCPEventKind::ConnectionComplated);

        let mut table = self.sockets.write().unwrap();
        Ok(table
            .get_mut(&sock_id)
            .context(format!("no such socket:  {:?}", sock_id))?
            .connected_connection_queue
            .pop_front()
            .context("no connected socket")?)
    }

    pub fn connect(&self, addr: Ipv4Addr, port: u16) -> Result<SockID> {
        let mut rng = rand::thread_rng();
        let mut socket = Socket::new(
            get_source_addr_to(addr)?,
            addr,
            self.select_unused_port(&mut rng)?,
            port,
            TcpStatus::SynSent,
        )?;
        socket.send_param.initial_seq = rng.gen_range(1..1 << 31);
        socket.send_tcp_packet(socket.send_param.initial_seq, 0, tcpflags::SYN, &[])?;
        socket.send_param.unacked_seq = socket.send_param.initial_seq;
        socket.send_param.next = socket.send_param.initial_seq + 1;

        let mut table = self.sockets.write().unwrap();
        let sock_id = socket.get_sock_id();
        table.insert(sock_id, socket);
        // ロックを外してイベントの待機、受信スレッドがロックを取得できるようにするため
        drop(table);
        self.wait_event(sock_id, TCPEventKind::ConnectionComplated);
        Ok(sock_id)
    }

    /// バッファのデータを送信する。必要であればパケットに分割して送信する。
    /// 全て送信されたら（ack されていなくても）リターンする。
    pub fn send(&self, sock_id: SockID, buffer: &[u8]) -> Result<()> {
        let mut cursor = 0;
        while cursor < buffer.len() {
            let mut table = self.sockets.write().unwrap();
            let mut socket = table
                .get_mut(&sock_id)
                .context(format!("no such socket: {:?}", sock_id))?;

            let mut send_size = cmp::min(
                MSS,
                cmp::min(socket.send_param.window as usize, buffer.len() - cursor),
            );
            while send_size == 0 {
                dbg!("unable to slide send window");
                // 受信スレッドがロックを取得できるようにするため、ロックを外してイベントを待機
                drop(table);
                self.wait_event(sock_id, TCPEventKind::Acked);
                table = self.sockets.write().unwrap();
                socket = table
                    .get_mut(&sock_id)
                    .context(format!("no such socket: {:?}", sock_id))?;

                // 送信サイズを再計算する
                send_size = cmp::min(
                    MSS,
                    cmp::min(socket.send_param.window as usize, buffer.len() - cursor),
                );
            }

            dbg!("current window size", socket.send_param.window);

            socket.send_tcp_packet(
                socket.send_param.next,
                socket.recv_param.next,
                tcpflags::ACK,
                &buffer[cursor..cursor + send_size],
            )?;
            cursor += send_size;
            socket.send_param.next += send_size as u32;
            socket.send_param.window -= send_size as u16;

            // 少しの間ロックを外して待機し、受信スレッドが ACK を受信できるようにしている
            // send_window が 0 になるまで送り続け、送信がブロックされる確率を下げるため
            drop(table);
            thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    /// データをバッファに読み込んで、読み込んだサイズを返す
    /// FIN を読み込んだ場合は 0 を返す
    /// パケットが届くまでブロックする
    pub fn recv(&self, sock_id: SockID, buffer: &mut [u8]) -> Result<usize> {
        let mut table = self.sockets.write().unwrap();
        let mut socket = table
            .get_mut(&sock_id)
            .context(format!("no such socket: {:?}", sock_id))?;
        let mut received_size = socket.recv_buffer.len() - socket.recv_param.window as usize;
        while received_size == 0 {
            // ペイロードを受信 or FIN を受信でスキップ
            match socket.status {
                TcpStatus::CloseWait | TcpStatus::LastAck | TcpStatus::TimeWait => break,
                _ => {}
            }

            // ロックを外してイベントを待機、受信スレッドがロックを取得できるようにするため
            drop(table);
            dbg!("waiting incoming data");
            self.wait_event(sock_id, TCPEventKind::DataArrived);
            table = self.sockets.write().unwrap();
            socket = table
                .get_mut(&sock_id)
                .context(format!("no such socket: {:?}", sock_id))?;
            received_size = socket.recv_buffer.len() - socket.recv_param.window as usize;
        }
        let copy_size = cmp::min(buffer.len(), received_size);
        buffer[..copy_size].copy_from_slice(&socket.recv_buffer[..copy_size]);
        socket.recv_buffer.copy_within(copy_size.., 0);
        socket.recv_param.window += copy_size as u16;

        Ok(copy_size)
    }

    /// 接続を閉じる
    pub fn close(&self, sock_id: SockID) -> Result<()> {
        let mut table = self.sockets.write().unwrap();
        let mut socket = table
            .get_mut(&sock_id)
            .context(format!("no such socket: {:?}", sock_id))?;
        socket.send_tcp_packet(
            socket.send_param.next,
            socket.recv_param.next,
            tcpflags::FIN | tcpflags::ACK,
            &[],
        )?;
        socket.send_param.next += 1;
        match socket.status {
            TcpStatus::Established => {
                socket.status = TcpStatus::FinWait1;
                drop(table);
                self.wait_event(sock_id, TCPEventKind::ConnectionClosed);
                let mut table = self.sockets.write().unwrap();
                table.remove(&sock_id);
                dbg!("closed & removed", sock_id);
            }
            TcpStatus::CloseWait => {
                socket.status = TcpStatus::LastAck;
                drop(table);
                self.wait_event(sock_id, TCPEventKind::ConnectionClosed);
                let mut table = self.sockets.write().unwrap();
                table.remove(&sock_id);
                dbg!("closed & removed", sock_id);
            }
            TcpStatus::Listen => {
                table.remove(&sock_id);
            }
            _ => return Ok(()),
        }
        Ok(())
    }

    /// 指定したソケットIDと種別のイベントを待機
    fn wait_event(&self, sock_id: SockID, kind: TCPEventKind) {
        let (lock, cvar) = &self.event_condvar;
        let mut event = lock.lock().unwrap();
        loop {
            if let Some(ref e) = *event {
                if e.sock_id == sock_id && e.kind == kind {
                    break;
                }
            }
            // cvar が notify されるまで event のロックを外して待機
            event = cvar.wait(event).unwrap();
        }
        dbg!(&event);
        *event = None;
    }

    /// 指定したソケットIDにイベントを発行する
    fn publish_event(&self, sock_id: SockID, kind: TCPEventKind) {
        let (lock, cvar) = &self.event_condvar;
        let mut e = lock.lock().unwrap();
        *e = Some(TCPEvent::new(sock_id, kind));
        cvar.notify_all();
    }

    /// 受信スレッド用のメソッド
    fn receive_handler(&self) -> Result<()> {
        dbg!("begin recv thred");

        let (_, mut receiver) = transport::transport_channel(
            65535,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
        )
        .unwrap();

        let mut packet_iter = transport::ipv4_packet_iter(&mut receiver);
        loop {
            let (packet, remote_addr) = match packet_iter.next() {
                Ok((p, r)) => (p, r),
                Err(_) => continue,
            };
            // 受信したパケットの送信元から見た宛先は、自身のアドレスとなる
            let local_addr = packet.get_destination();
            let tcp_packet = match TcpPacket::new(packet.payload()) {
                Some(p) => p,
                None => continue,
            };
            // pnet の TcpPacket から tcp::TCPPacket に変換する
            let packet = TCPPacket::from(tcp_packet);
            let remote_addr = match remote_addr {
                IpAddr::V4(addr) => addr,
                _ => continue,
            };
            let mut table = self.sockets.write().unwrap();
            let socket = match table.get_mut(&SockID(
                local_addr,
                remote_addr,
                packet.get_dest(),
                packet.get_src(),
            )) {
                Some(socket) => socket, // 接続済みソケット
                None => match table.get_mut(&SockID(
                    local_addr,
                    UNDETERMINED_IP_ADDR,
                    packet.get_dest(),
                    UNDETERMINED_PORT,
                )) {
                    Some(socket) => socket, // リスニングソケット
                    None => continue,
                },
            };

            if !packet.is_correct_checksum(local_addr, remote_addr) {
                dbg!("invalid checksum");
                continue;
            }

            let sock_id = socket.get_sock_id();
            if let Err(error) = match socket.status {
                TcpStatus::Listen => self.listen_handler(table, sock_id, &packet, remote_addr),
                TcpStatus::SynRcvd => self.synrcvd_handler(table, sock_id, &packet),
                TcpStatus::SynSent => self.synsent_handler(socket, &packet),
                TcpStatus::Established => self.established_handler(socket, &packet),
                TcpStatus::CloseWait | TcpStatus::LastAck => self.close_handler(socket, &packet),
                TcpStatus::FinWait1 | TcpStatus::FinWait2 => self.finwait_handler(socket, &packet),
                _ => {
                    dbg!("not implemented state");
                    Ok(())
                }
            } {
                dbg!(error);
            }
        }
    }

    /// LISTEN 状態のソケットに到着したパケットの処理
    fn listen_handler(
        &self,
        mut table: RwLockWriteGuard<HashMap<SockID, Socket>>,
        listening_socket_id: SockID,
        packet: &TCPPacket,
        remote_addr: Ipv4Addr,
    ) -> Result<()> {
        dbg!("listen handler");
        if packet.get_flag() & tcpflags::ACK > 0 {
            // 本来なら RST を send する
            return Ok(());
        }

        let listening_socket = table.get_mut(&listening_socket_id).unwrap();
        if packet.get_flag() & tcpflags::SYN > 0 {
            // passive open の処理
            // 後に接続済みソケットとなるソケットを新たに生成する
            let mut connection_socket = Socket::new(
                listening_socket.local_addr,
                remote_addr,
                listening_socket.local_port,
                packet.get_src(),
                TcpStatus::SynRcvd,
            )?;
            connection_socket.recv_param.next = packet.get_seq() + 1;
            connection_socket.recv_param.initial_seq = packet.get_seq();
            connection_socket.send_param.initial_seq = rand::thread_rng().gen_range(1..1 << 31);
            connection_socket.send_param.window = packet.get_window_size();
            connection_socket.send_tcp_packet(
                connection_socket.send_param.initial_seq,
                connection_socket.recv_param.next,
                tcpflags::SYN | tcpflags::ACK,
                &[],
            )?;
            connection_socket.send_param.next = connection_socket.send_param.initial_seq + 1;
            connection_socket.send_param.unacked_seq = connection_socket.send_param.initial_seq;
            connection_socket.listening_socket = Some(listening_socket.get_sock_id());
            dbg!("status: listen -> ", &connection_socket.status);
            table.insert(connection_socket.get_sock_id(), connection_socket);
        }

        Ok(())
    }

    fn synrcvd_handler(
        &self,
        mut table: RwLockWriteGuard<HashMap<SockID, Socket>>,
        sock_id: SockID,
        packet: &TCPPacket,
    ) -> Result<()> {
        dbg!("synrcvd handler");
        let socket = table.get_mut(&sock_id).unwrap();

        let ack = packet.get_ack();

        if packet.get_flag() & tcpflags::ACK > 0
            && socket.send_param.unacked_seq <= ack
            && ack <= socket.send_param.next
        {
            socket.recv_param.next = packet.get_seq();
            socket.send_param.unacked_seq = ack;
            socket.status = TcpStatus::Established;
            dbg!("status: synrcvd -> ", &socket.status);

            if let Some(id) = socket.listening_socket {
                let ls = table.get_mut(&id).unwrap();
                ls.connected_connection_queue.push_back(sock_id);
                self.publish_event(ls.get_sock_id(), TCPEventKind::ConnectionComplated);
            }
        }

        Ok(())
    }

    /// SYNSENT 状態のソケットに到着したパケットの処理
    fn synsent_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        dbg!("synsent handler");

        let flag = packet.get_flag();
        let ack = packet.get_ack();
        let seq = packet.get_seq();

        // ACK フラグが立っているか
        // && SYN フラグが立っているか
        // && すでに確認応答されたシーケンス番号に対応する確認応答が二重に届いていないか
        // && まだ送信していないセグメントに対する確認応答が届いていないか
        if flag & tcpflags::ACK > 0
            && flag & tcpflags::SYN > 0
            && socket.send_param.unacked_seq <= ack
            && ack <= socket.send_param.next
        {
            socket.recv_param.next = seq + 1;
            socket.recv_param.initial_seq = seq;
            socket.send_param.unacked_seq = ack;
            socket.send_param.window = packet.get_window_size();

            if socket.send_param.unacked_seq > socket.send_param.initial_seq {
                socket.status = TcpStatus::Established;
                socket.send_tcp_packet(
                    socket.send_param.next,
                    socket.recv_param.next,
                    tcpflags::ACK,
                    &[],
                )?;
                dbg!("status: synsent -> ", &socket.status);
                self.publish_event(socket.get_sock_id(), TCPEventKind::ConnectionComplated);
            } else {
                socket.status = TcpStatus::SynRcvd;
                socket.send_tcp_packet(
                    socket.send_param.next,
                    socket.recv_param.next,
                    tcpflags::ACK,
                    &[],
                )?;
                dbg!("status: synsent -> ", &socket.status);
            }
        }
        Ok(())
    }

    /// ESTABLISHED 状態のソケットに到着したパケットの処理
    fn established_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        dbg!("established handler");

        let ack = packet.get_ack();
        if socket.send_param.unacked_seq < ack && ack <= socket.send_param.next {
            socket.send_param.unacked_seq = ack;
            self.delete_acked_segment_from_retransmission_queue(socket);
        } else if socket.send_param.next < ack {
            // 未送信セグメントに対する ACK は破棄
            return Ok(());
        }

        if packet.get_flag() & tcpflags::ACK == 0 {
            // ACK が立っていないパケットは破棄
            return Ok(());
        }

        if !packet.payload().is_empty() {
            self.process_payload(socket, &packet)?;
        }

        if packet.get_flag() & tcpflags::FIN > 0 {
            socket.recv_param.next = packet.get_ack() + 1;
            socket.send_tcp_packet(
                socket.send_param.next,
                socket.recv_param.next,
                tcpflags::ACK,
                &[],
            )?;
            socket.status = TcpStatus::CloseWait;
            self.publish_event(socket.get_sock_id(), TCPEventKind::DataArrived);
        }

        Ok(())
    }

    /// FINWAIT1 or FINWAIT2 状態のソケットに到着したパケットの処理
    fn finwait_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        dbg!("finwait handler");

        if socket.send_param.unacked_seq < packet.get_ack()
            && packet.get_ack() <= socket.send_param.next
        {
            socket.send_param.unacked_seq = packet.get_ack();
            self.delete_acked_segment_from_retransmission_queue(socket);
        } else if socket.send_param.next < packet.get_ack() {
            // 未送信セグメントに対する ack は破棄
            return Ok(());
        }
        if packet.get_flag() & tcpflags::ACK == 0 {
            // ACK が立っていないパケットは破棄
            return Ok(());
        }

        if !packet.payload().is_empty() {
            self.process_payload(socket, &packet)?;
        }

        if socket.status == TcpStatus::FinWait1
            && socket.send_param.next == socket.send_param.unacked_seq
        {
            // 送信した FIN が ack されていればFinWait2 へ遷移
            socket.status = TcpStatus::FinWait2;
            dbg!("status: finwait1 -> ", &socket.status);
        }

        if packet.get_flag() & tcpflags::FIN > 0 {
            // 本来は CLOSING state も考慮する必要があるが省略
            socket.recv_param.next += 1;
            socket.send_tcp_packet(
                socket.send_param.next,
                socket.recv_param.next,
                tcpflags::ACK,
                &[],
            )?;
            self.publish_event(socket.get_sock_id(), TCPEventKind::ConnectionClosed);
        }

        Ok(())
    }

    fn close_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        dbg!("closewait|lastack handler");
        socket.send_param.unacked_seq = packet.get_ack();
        Ok(())
    }

    /// パケットのペイロードを受信バッファにコピーする
    fn process_payload(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        // バッファにおける読み込みのヘッド位置
        let offset = socket.recv_buffer.len() - socket.recv_param.window as usize
            + (packet.get_seq() - socket.recv_param.next) as usize;
        let copy_size = cmp::min(packet.payload().len(), socket.recv_buffer.len() - offset);
        socket.recv_buffer[offset..offset + copy_size]
            .copy_from_slice(&packet.payload()[..copy_size]);
        // ロス再送の際に穴埋めされるために max をとる
        socket.recv_param.tail =
            cmp::max(socket.recv_param.tail, packet.get_seq() + copy_size as u32);

        // 順序入れ替わりがない場合は recv_param.next を進める
        if packet.get_seq() == socket.recv_param.next {
            socket.recv_param.next = socket.recv_param.tail;
            socket.recv_param.window -= (socket.recv_param.tail - packet.get_seq()) as u16;
        }

        if copy_size > 0 {
            // 受信バッファにコピー成功
            socket.send_tcp_packet(
                socket.send_param.next,
                socket.recv_param.next,
                tcpflags::ACK,
                &[],
            )?;
        } else {
            // 受信バッファが溢れた場合はセグメントを破棄
            dbg!("recv buffer overflow");
        }

        self.publish_event(socket.get_sock_id(), TCPEventKind::DataArrived);
        Ok(())
    }

    fn delete_acked_segment_from_retransmission_queue(&self, socket: &mut Socket) {
        dbg!("ack accept", socket.send_param.unacked_seq);
        while let Some(item) = socket.retransmission_queue.pop_front() {
            if socket.send_param.unacked_seq > item.packet.get_seq() {
                // ack されているので除去
                dbg!("successfully acked", item.packet.get_seq());
                socket.send_param.window += item.packet.payload().len() as u16;
                self.publish_event(socket.get_sock_id(), TCPEventKind::Acked);
            } else {
                // ack されていないので戻す
                socket.retransmission_queue.push_front(item);
                break;
            }
        }
    }

    fn select_unused_port(&self, rng: &mut ThreadRng) -> Result<u16> {
        for _ in 0..(PORT_RANGE.end - PORT_RANGE.start) {
            let local_port = rng.gen_range(PORT_RANGE);
            let table = self.sockets.read().unwrap();
            // すでにポートが使用されていないかをチェック
            if table.keys().all(|k| local_port != k.2) {
                return Ok(local_port);
            }
        }
        anyhow::bail!("no available port found.");
    }

    /// 全てのソケットの再送キューを見て、タイムアウトしているパケットを再送する
    fn timer(&self) {
        dbg!("begin timer thread");
        loop {
            let mut table = self.sockets.write().unwrap();
            for (sock_id, socket) in table.iter_mut() {
                while let Some(mut item) = socket.retransmission_queue.pop_front() {
                    // 再送キューから ack されたセグメントを除去する
                    // established state 以外の時に送信されたセグメントを除去するために必要
                    if socket.send_param.unacked_seq > item.packet.get_seq() {
                        // ack されている
                        dbg!("successfully acked", item.packet.get_seq());
                        socket.send_param.window += item.packet.payload().len() as u16;
                        self.publish_event(*sock_id, TCPEventKind::Acked);

                        if item.packet.get_flag() & tcpflags::FIN > 0
                            && socket.status == TcpStatus::LastAck
                        {
                            self.publish_event(*sock_id, TCPEventKind::ConnectionClosed);
                        }
                        continue;
                    }

                    // タイムアウトを確認
                    // 通常は RTT を継続的に監視して値を決めるが今回は簡単のため定数値を使用
                    if item.latest_transmission_time.elapsed().unwrap()
                        < Duration::from_secs(RETRANSMITTION_TIMEOUT)
                    {
                        // 取り出したエントリがタイムアウトしていないなら、キューの移行のエントリもタイムアウトしていないので先頭に戻す
                        socket.retransmission_queue.push_front(item);
                        break;
                    }

                    // ack されていなければ再送
                    if item.transmission_count < MAX_TRANSMITTION {
                        dbg!("retransmit");
                        socket
                            .sender
                            .send_to(item.packet.clone(), IpAddr::V4(socket.remote_addr))
                            .context("failed to retransmit")
                            .unwrap();
                        item.transmission_count += 1;
                        item.latest_transmission_time = SystemTime::now();
                        socket.retransmission_queue.push_back(item);
                        break;
                    } else {
                        dbg!("reached MAX_TRANSMITTION");
                        if item.packet.get_flag() & tcpflags::FIN > 0
                            && (socket.status == TcpStatus::LastAck
                                || socket.status == TcpStatus::FinWait1
                                || socket.status == TcpStatus::FinWait2)
                        {
                            self.publish_event(*sock_id, TCPEventKind::ConnectionClosed);
                        }
                    }
                }
            }
            // ロックを外して待機する
            drop(table);
            thread::sleep(Duration::from_millis(100));
        }
    }
}

/// 宛先IPアドレスに対する送信元インターフェースのIPアドレスを取得する
fn get_source_addr_to(addr: Ipv4Addr) -> Result<Ipv4Addr> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ip route get {} | grep src", addr))
        .output()?;
    let mut output = str::from_utf8(&output.stdout)?
        .trim()
        .split_ascii_whitespace();
    while let Some(s) = output.next() {
        if s == "src" {
            break;
        }
    }
    let ip = output.next().context("failed to get src ip")?;
    dbg!("source addr", ip);
    ip.parse().context("failed to parse source ip")
}
