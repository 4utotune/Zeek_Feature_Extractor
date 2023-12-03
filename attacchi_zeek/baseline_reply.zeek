@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

type pk: record {
    resp_h: addr;
    orig_h: addr;
    orig_p: port;
    resp_p: port;
    size: count;
    length: count;
    num_pkts: count;
};

global pks: table[addr] of pk = table();

event new_packet(c: connection, p: pkt_hdr){
    #analisi pacchetto
    local pacchetto: pk; 
    if (c$id$resp_h !in pks) {
        pacchetto = [$orig_h = c$id$orig_h, $orig_p = c$id$orig_p, $resp_h = c$id$resp_h, $resp_p = c$id$resp_p, $size = c$orig$num_bytes_ip, $length = p$ip$len, $num_pkts = 1];
    } else {
        pacchetto = pks[c$id$resp_h];
        if (pacchetto$orig_h != c$id$orig_h && pacchetto$resp_p == c$id$resp_p && pacchetto$size == c$orig$num_bytes_ip && pacchetto$length == p$ip$len) {
            print fmt("Tentativo di Brute-Force-Write = %s:%s -> %s:%s", pacchetto$orig_h, pacchetto$orig_p, pacchetto$resp_h, pacchetto$resp_p);
        } else {
            pacchetto = [$orig_h = c$id$orig_h, $orig_p = c$id$orig_p, $resp_h = c$id$resp_h, $resp_p = c$id$resp_p, $size = c$orig$num_bytes_ip, $length = p$ip$len, $num_pkts = 1];

        }
    }
    pks[c$id$resp_h] = pacchetto;
}

event connection_reused(c: connection){
    print fmt("Brute-Force-Write: Connection reused = %s:%s -> %s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
}
    

