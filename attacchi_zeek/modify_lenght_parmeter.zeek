@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

const len_max = 1; #expected max length of the response

event http_reply(c: connection, version: string, code: count, reason: string){
    if (c$resp$size >= len_max){
        print fmt("Modify Lenght Parameter-HTTP: %s from %s", c$uid, c$id$orig_h);
    }
}