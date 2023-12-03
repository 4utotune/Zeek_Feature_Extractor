@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

function is_shellcode_request(body: string): int {
    local controllo: string = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
    if ( controllo in body) {
        return 0;   # Esempio: Rileva la sequenza di byte "\x90\x90\x90" (NOP sled)
    }
    return 1;
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string){
    if (is_shellcode_request(payload) == 0) {
        print fmt("TCP=Shellcode detected: Connection: %s from %s to %s", c$uid, c$id$orig_h, c$id$resp_h);
    }
}

#shellcode detection -> se non utilizzate porte standard
const standard_ports: set[port] = {80/tcp, 443/tcp, 22/tcp, 53/tcp, 21/tcp};

event connection_state_remove(c: connection)
{
    if (c$id$resp_p !in standard_ports || c$id$orig_p !in standard_ports)
    {
        print fmt("Not Standard Port=Connection between %s:%d and %s:%d is not using a standard port.",
                   c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
}
