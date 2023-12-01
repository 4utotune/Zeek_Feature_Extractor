@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

event connection_state_remove(c: connection){

    local uid: string = c$uid;
    local orig_h: addr = c$id$orig_h;
    local resp_h: addr = c$id$resp_h;
    local num_pkts: count = c$orig$num_pkts;
    local start_time: double = time_to_double(c$start_time);
    local last_time: double;
    local dur_seconds: double = interval_to_double(c$duration);

    last_time = start_time + dur_seconds;
    if(num_pkts > 1){
        local jitter: double;
        jitter = num_pkts / dur_seconds;
        print fmt("Conn: %s, %s -> %s, jitter=%.2f, start_time=%.2f, last_time=%.2f", uid, orig_h, resp_h, jitter, start_time, last_time);
    }
}

