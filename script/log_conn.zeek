@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

# feature estratte:
# basic feature (state, dur, sbytes, dbytes, service, spkts, dpkts, sload, dload)

type TransportProto: enum {
    TRANSPORT_TCP,
    TRANSPORT_UDP,
    TRANSPORT_ICMP,
};

event zeek_init(){
    print "uid, state-protocol, duration, sbytes, dbytes, service, spkts, dpkts, sload, dload, missed_bytes";
}

# Estrazione e stampa delle feature
event Conn::log_conn(c: Conn::Info)
{
    local uid:  string = c$uid;
    local state: string = c$conn_state;
    local proto: string = "";
    local protocol: TransportProto = c$proto;
    if (protocol == TRANSPORT_UDP) {
        proto = "udp";
    }
    else if (protocol == TRANSPORT_TCP) {
        proto = "tcp";
    }
    else if (protocol == TRANSPORT_ICMP) {
        proto = "icmp";
    }
    else {
        proto = "(-)";
    }
    local sbytes: count = c$orig_ip_bytes;
    local dbytes: count = c$resp_ip_bytes;
    local spkts: count = c$orig_pkts;
    local dpkts: count = c$resp_pkts;

    #per ottenere sload e dload è necessario convertire la duration in secondi
    local missed_bytes: count = c$missed_bytes;

    local key = fmt("%s : %s-%s, %s->%s, %s->%s, %s", uid, state, proto, sbytes, dbytes, spkts, dpkts, missed_bytes);
    print fmt("%s", key);
}









