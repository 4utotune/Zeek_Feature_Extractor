@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

type TransportProto: enum {
    TRANSPORT_TCP,
    TRANSPORT_UDP,
    TRANSPORT_ICMP,
};

event zeek_init(){
    print "uid, state-protocol, duration, sbytes, dbytes, service, spkts, dpkts, sload, dload";
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
    local dur: interval = c$duration;
    local sbytes: count = c$orig_ip_bytes;
    local dbytes: count = c$resp_ip_bytes;
    local service: string = c$service;
    local spkts: count = c$orig_pkts;
    local dpkts: count = c$resp_pkts;

    #per ottenere sload e dload è necessario convertire la duration in secondi
    local dur_seconds: double = interval_to_double(c$duration);
    local sload: double = sbytes / dur_seconds;
    local dload: double = dbytes / dur_seconds;

    # Stampa delle feature nel formato richiesto
    local key = fmt("%s : %s-%s, %.2f, %s-%s, %s, %s-%s, %.2f-%.2f", uid, state, proto, dur_seconds, sbytes, dbytes, service, spkts, dpkts, sload, dload);
    if (key != ""){
        print fmt("%s", key);
    }
}









