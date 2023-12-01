@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

function is_fuzzing_request(body: string): int {
    local controllo: string = "\x41\x41\x41";
    if ( controllo in body) {
        return 0;  # Esempio: Rileva la sequenza di byte "AAA"
    }
    return 1;
}

#file labtel
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string){
    if (is_fuzzing_request(payload) == 0) {
        print fmt("TCP=Fuzzing request detected: Connection: %s from %s to %s", c$uid, c$id$orig_h, c$id$resp_h);
    }
}

#file last_capture
event conn_weird(name: string, c: connection, addl: string, source: string){
    print fmt("CONN=Weird: %s, motivo: %s",source, name);
}

event flow_weird(name: string, src: addr, dst: addr, addl: string, source: string){
    print fmt("FLOW=Weird: %s, motivo: %s",source, name);
}

event net_weird(name: string, addl: string, source: string){
    print fmt("NET=Weird: %s, motivo: %s", source, name);
}

#anche analyzer_violation_info