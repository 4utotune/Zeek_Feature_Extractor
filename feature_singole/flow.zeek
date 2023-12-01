@load base/protocols/conn

event connection_state_remove(c:connection) {
    local uid = c$uid;
    local srcip = c$id$orig_h;
    local srcport = c$id$orig_p;
    local dstip = c$id$resp_h;
    local dstport = c$id$resp_p;
    local proto = c?$service;

    local key = fmt("%s : %s:%d-%s:%d/%s", uid, srcip, srcport, dstip, dstport, proto);
    print fmt("%s", key);
}