@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

event connection_state_remove(c: connection){
    local uid: string = c$uid;
    local src: addr = c$id$orig_h;
    local dst: addr = c$id$resp_h;
    local orig_pkt: int = c$orig$num_pkts;
    local resp_pkt: int = c$resp$num_pkts;
    local orig_bytes: int = c$orig$num_bytes_ip;
    local resp_bytes: int = c$resp$num_bytes_ip;
    local smeansz: double;
    local dmeansz: double;

    if(orig_pkt > 0){
        smeansz = orig_bytes / orig_pkt;
    }else{
        smeansz = 0;
    }

    if(resp_pkt > 0){
        dmeansz = resp_bytes / resp_pkt;
    } else{
        dmeansz = 0;
    }

    print fmt("Conn: %s , %s -> %s, %.2f smeansz, %.2f dmeansz", uid, src, dst, smeansz, dmeansz);
}