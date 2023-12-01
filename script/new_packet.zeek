@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

#feature estratte:
# ttl
# content features (swin, dwin, stcpb, dtcpb)

event new_packet(c: connection, p: pkt_hdr){
    #ttl
    #content features 
    local t: port = 0/udp;
    local min: port = 0/tcp;

    if(c$id$resp_p < t && c$id$orig_p > min){
        local uid : string = c$uid;
        local src: addr = p$ip$src;
        local dst: addr = p$ip$dst;
        local win: int = p$tcp$win;
        local seq: int = p$tcp$seq;
        print fmt("%s : %s -> %s, win: %d, seq (raw): %d, len: %d, ttl: %d", uid, src, dst, win, seq, p$ip$len, p$ip$ttl);
    }

}

