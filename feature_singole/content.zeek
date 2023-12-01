@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

event new_packet(c: connection, p: pkt_hdr){
    local uid : string = c$uid;
    local src: addr = p$ip$src;
    local dst: addr = p$ip$dst;
    local win: int = p$tcp$win;
    local seq: int = p$tcp$seq;


    print fmt("%s : %s -> %s, win: %d, seq (raw): %d", uid, src, dst, win, seq);
}

