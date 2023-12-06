@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

type Stats: record {
    flows: count;
    src_bytes: count;
    dst_bytes: count;
    src_pkt: count;
    dst_pkt: count;
    tcp: count;
    udp: count;
    icmp: count;
    other: count;
};

global Stato: Stats = [$flows=0, $src_bytes=0, $dst_bytes=0, $src_pkt=0, $dst_pkt=0, $tcp=0, $udp=0, $icmp=0, $other=0];

type connect: record {
    uid: string;
};

type connects: table[string] of connect;
global connects_table: connects = table(); 

event zeek_init(){
    #print "zeek_init";
}

event connection_state_remove(c: connection){
    local uid: string = c$uid;
    local connecto: connect;
    if (uid !in connects_table) {
        #se non c'è la inserisco
        connecto = [$uid=uid];
        connects_table[uid] = connecto;
        #aggiorno le stats
        if(c$id$orig_p > 0/tcp && c$id$orig_p < 0/udp){
            Stato = [$flows=Stato$flows+1, $src_bytes=Stato$src_bytes+c$orig$num_bytes_ip, $dst_bytes=Stato$dst_bytes+c$resp$num_bytes_ip, $src_pkt=Stato$src_pkt+c$orig$num_pkts, $dst_pkt=Stato$dst_pkt+c$resp$num_pkts, $tcp=Stato$tcp+1, $udp=Stato$udp, $icmp=Stato$icmp, $other=Stato$other];
        }else if(c$id$orig_p > 0/udp && c$id$orig_p < 0/icmp){
            Stato = [$flows=Stato$flows+1, $src_bytes=Stato$src_bytes+c$orig$num_bytes_ip, $dst_bytes=Stato$dst_bytes+c$resp$num_bytes_ip, $src_pkt=Stato$src_pkt+c$orig$num_pkts, $dst_pkt=Stato$dst_pkt+c$resp$num_pkts, $tcp=Stato$tcp, $udp=Stato$udp+1, $icmp=Stato$icmp, $other=Stato$other];
        }else if(c$id$orig_p > 0/icmp){
            Stato = [$flows=Stato$flows+1, $src_bytes=Stato$src_bytes+c$orig$num_bytes_ip, $dst_bytes=Stato$dst_bytes+c$resp$num_bytes_ip, $src_pkt=Stato$src_pkt+c$orig$num_pkts, $dst_pkt=Stato$dst_pkt+c$resp$num_pkts, $tcp=Stato$tcp, $udp=Stato$udp, $icmp=Stato$icmp+1, $other=Stato$other];
        }else{
            Stato = [$flows=Stato$flows+1, $src_bytes=Stato$src_bytes+c$orig$num_bytes_ip, $dst_bytes=Stato$dst_bytes+c$resp$num_bytes_ip, $src_pkt=Stato$src_pkt+c$orig$num_pkts, $dst_pkt=Stato$dst_pkt+c$resp$num_pkts, $tcp=Stato$tcp+1, $udp=Stato$udp+1, $icmp=Stato$icmp+1, $other=Stato$other+1];
        }
    }
}

event zeek_done(){
    #print "zeek_done";
    print Stato;
}