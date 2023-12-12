@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

event connection_state_remove(c: connection){
    print fmt("Connection: %s", c$id);
    print fmt("%s:%s -> %s:%s, vlan=%s, inner_vlan=%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, c$vlan, c$inner_vlan);
}
