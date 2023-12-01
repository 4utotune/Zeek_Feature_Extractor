@load base/protocols/http

# Definizione di una soglia per la dimensione del payload
const soglia_payload: int = 1; 

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    # Verifica se il payload supera la soglia definita
    if (c$orig$size > soglia_payload) {
        print fmt("Loading-Payload= richiesta HTTP %s da parte di %s", original_URI, c$id$orig_h);
    }
}

event http_reply(c: connection, version: string, code: count, reason: string) {
    # Verifica se il payload supera la soglia definita
    if (c$orig$size > soglia_payload) {
        print fmt("Loading-Payload= risposta HTTP da parte di %s", c$id$resp_h);
    }
}

event new_packet(c: connection, p: pkt_hdr){
    # Verifica se il payload supera la soglia definita
    if (c$orig$size > soglia_payload) {
        print fmt("Loading-Payload= pacchetto %s:%s -> %s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
}

