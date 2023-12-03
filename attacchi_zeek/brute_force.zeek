@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

type packet: record {
    orig_h: addr;
    orig_p: port;
    resp_h: addr;
    resp_p: port;
    size: count;
    num_pkts: count;
};

global packets: table[addr] of packet = table();

event new_packet(c: connection, p: pkt_hdr){
    local sogliaPkt = 10000;
    local sogliaSize = 10000;
    #analisi pacchetto
    local pacchetto: packet; 
    if (c$id$orig_h !in packets) {
        pacchetto = [$orig_h = c$id$orig_h, $orig_p = c$id$orig_p, $resp_h = c$id$resp_h, $resp_p = c$id$resp_p, $size = c$orig$num_bytes_ip, $num_pkts = 1];
    } else {
        pacchetto = packets[c$id$orig_h];
        local conta = pacchetto$num_pkts + 1;
        local size = pacchetto$size + c$orig$num_bytes_ip;
        pacchetto = [$orig_h = c$id$orig_h, $orig_p = c$id$orig_p, $resp_h = c$id$resp_h, $resp_p = c$id$resp_p, $size = size, $num_pkts = conta];
    }
    packets[c$id$orig_h] = pacchetto;

    #analisi soglia
    if (pacchetto$num_pkts > sogliaPkt || pacchetto$size > sogliaSize) {
        print fmt("Tentativo di Brute-Force-Write = %s:%s -> %s:%s, size: %d, num_pkt = %d", pacchetto$orig_h, pacchetto$orig_p, pacchetto$resp_h, pacchetto$resp_p, pacchetto$size, pacchetto$num_pkts);
    } 
}

    

