@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

type conto: record {
    synack_count: count;
    ack_count: count;
};

global conteggio: conto = [$synack_count=0, $ack_count=0];

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
    if (flags == "SA") {
        conteggio$synack_count += 1;
    }
    if (flags == "A") {
        conteggio$ack_count += 1;
    }

    print fmt("TCP Packet: %s Syn-Ack Count: %d, Ack Count: %d", payload, conteggio$synack_count, conteggio$ack_count);
}
