@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

type connessione: record {
    uid: string;
    start_time: time;
    end_time: time;
};

type connessioni: table[string] of connessione;

global connessioni_table: connessioni = table();

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string){
    local uid: string = c$uid;
    local end_time: time;
    local durata: double;
    local nuova_connessione: connessione;

    # Verifica se la stringa uid è già presente nella tabella
    if (uid !in connessioni_table) {
        if (flags == "S"){
            nuova_connessione = [$uid=uid, $start_time=c$start_time, $end_time=c$start_time];
            connessioni_table[uid] = nuova_connessione;
        }
        #print fmt("Nuova connessione: UID %s, Start Time %s, End Time %s", uid, c$start_time, end_time);
    }
    # Altrimenti, la connessione esiste già nella tabella
    else {
        if (flags == "SA"){
            end_time = c$start_time + c$duration;
            nuova_connessione = [$uid=uid, $start_time=c$start_time, $end_time=end_time];
            connessioni_table[uid] = nuova_connessione;
            durata = interval_to_double(end_time - c$start_time);
            print fmt("Connessione TCP: UID %s, Start Time %s, End Time %s, Durata: %s", uid, c$start_time, end_time, durata);
        }
    }

}