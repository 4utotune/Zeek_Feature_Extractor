@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp



const standard_ports: set[port] = {80/tcp, 443/tcp, 22/tcp, 53/tcp, 21/tcp};

event connection_state_remove(c: connection)
{
    if (c$id$resp_p in standard_ports || c$id$orig_p in standard_ports)
    {
        print fmt("Connection between %s:%d and %s:%d is using a standard port.",
                   c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
}

