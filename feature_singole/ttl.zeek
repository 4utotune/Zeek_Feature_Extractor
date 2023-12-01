@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

type connpkt: record {
    uid: string;
    orig_h: addr;
    resp_h: addr;
    len : count;
    ttl: int;
};

event new_packet(c: connection, p: pkt_hdr){
    local pkt: connpkt = [$uid=c$uid, $orig_h=p$ip$src, $resp_h=p$ip$dst, $len=p$ip$len, $ttl=p$ip$ttl];
    print pkt;
}
