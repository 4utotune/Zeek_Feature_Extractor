@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

#feature estratte:
# time - jitter
# flow features (srcip, sport, dstip, dport, proto)
# content features (smeansz, dmeansz)

event connection_state_remove(c: connection){
    #jitter
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
        print fmt("Jitter = Conn: %s, %s -> %s, jitter=%.2f, start_time=%.2f, last_time=%.2f", uid, orig_h, resp_h, jitter, start_time, last_time);
    }

    #flow features
    local srcip = c$id$orig_h;
    local srcport = c$id$orig_p;
    local dstip = c$id$resp_h;
    local dstport = c$id$resp_p;
    local proto = c$service;

    local key = fmt("Flow Features = %s : %s:%d-%s:%d/%s", uid, srcip, srcport, dstip, dstport, proto);
    print fmt("%s", key);

    #content features
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

    print fmt("Mean Size = Conn: %s , %s -> %s, %.2f smeansz, %.2f dmeansz", uid, src, dst, smeansz, dmeansz);

    # basic feature (duration, service, sload, dload)
    local sbytes: count = c$orig$num_bytes_ip;
    local dbytes: count = c$resp$num_bytes_ip;
    local service = c$service;
    local dur_seconds1: double = interval_to_double(c$duration);
    local sload: double;
    local dload: double;
    if(dur_seconds1 == 0){
        sload = 0;
        dload = 0;
    }else{
        sload = sbytes / dur_seconds1;
        dload = dbytes / dur_seconds1;
    }
    
    print fmt("Basic Features = Conn: %s, duration=%.2f, service=%s, sload=%.2f, dload=%.2f", uid, dur_seconds1, service, sload, dload);
}

