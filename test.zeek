@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

event Modbus::log_modbus(rec: Modbus::Info){
    print fmt("%s %s %s", rec$ts, rec$tid, rec$id$resp_h);
}