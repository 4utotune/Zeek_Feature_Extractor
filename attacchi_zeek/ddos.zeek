@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

type DDoSInfo: record {
    uri: string;
    conto: count;
};

type DDoSInfoDNS: record {
    domain: string;
    conto: count;
};

global ddos_table: table[string] of DDoSInfo = table();
global ddos_tabledns: table[string] of DDoSInfoDNS = table();

event connection_state_remove(c: connection){
    local soglia = 100000;
    if (c$orig$num_pkts > soglia) {
        print fmt("Connessione=Possibile attacco DDoS rilevato: %s da %s", c$uid, c$id$orig_h);
    }
}

function update_ddos_count_http(uri: string): count {
    local ddos_info: DDoSInfo;
    if (uri !in ddos_table) {
        ddos_info = [$uri=uri, $conto=1];
    } else {
        ddos_info = ddos_table[uri];
        local conta: count = ddos_info$conto + 1;
        ddos_info = [$uri=uri, $conto=conta];
        #ddos_info$conto += 1;
    }

    ddos_table[uri] = ddos_info;
    return ddos_info$conto;
}

function update_ddos_count_dns(domain: string): count {
    local ddos_info: DDoSInfoDNS;

    if (domain !in ddos_tabledns) {
        ddos_info = [$domain=domain, $conto=1];
    } else {
        ddos_info = ddos_tabledns[domain];
        local conta: count = ddos_info$conto + 1;
        ddos_info = [$domain=domain, $conto=conta];
        #ddos_info$conto += 1;
    }

    ddos_tabledns[domain] = ddos_info;
    return ddos_info$conto;
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    local soglia = 1;
    if (method == "GET" || method == "POST") {
        local uri_count: count = update_ddos_count_http(original_URI);

        if (uri_count > soglia) {
            print fmt("HTTP=Possibile attacco DDoS su URI %s, Count: %d", original_URI, uri_count);
        }
    }
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    local soglia = 1;
    # qtype = 1 -> A
    # qtype = 28 -> AAAA
    if (qtype == 1 || qtype == 28) {
        local domain_count: count = update_ddos_count_dns(query);

        if (domain_count > soglia) {
            print fmt("DNS=Possibile attacco DDoS su dominio %s, Count: %d", query, domain_count);
        }
    }
}
