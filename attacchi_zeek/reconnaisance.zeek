@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

function is_reconnaissance_uri(uri: string): int {
    local c1: string = "admin";
    local c2: string = "wp-admin";
    local c3: string = "administrator";
    if (c1 in uri || c2 in uri || c3 in uri) {
        return 0;
    }else{
        return 1;
    }
}

function is_reconnaissance_dns(query: string): bool {
    local q1: string = "internal";
    local q2: string = "sensitive";


    if (q1 in query || q2 in query) {
        return T;
    }else{
        return F;
    }
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if (is_reconnaissance_uri(original_URI) == 0) {
        print fmt("HTTP-Reconnaisance: %s da %s", original_URI, c$id$orig_h);
    }
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    if (is_reconnaissance_dns(query)) {
        print fmt("DNS-reconnaissance: %s da %s", query, c$id$orig_h);
    }
}

#effettuo controllo su ping
event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string) {
    print fmt("ICMP-reconnaissance: %s da %s", info, c$id$orig_h);
}

