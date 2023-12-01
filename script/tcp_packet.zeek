@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
@load base/protocols/ftp

#features estratte:
# tcp rtt
# ack -> time between syn_ack and ack
# syn -> time between syn and syn_ack
# startime
# endtime

#tcprtt
type conto: record {
    synack_count: count;
    ack_count: count;
};
global conteggio: conto = [$synack_count=0, $ack_count=0];

#ack -> time between syn_ack and ack
type connessione: record {
    uid: string;
    start_time: time;
    end_time: time;
};
type connessioni: table[string] of connessione;
global connessioni_table: connessioni = table();

#syn -> time between syn and syn_ack
type connessiones: record {
    uid: string;
    start_time: time;
    end_time: time;
};
type connessionis: table[string] of connessiones;
global connessioni_tables: connessionis = table();

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
    #tcprtt
    if (flags == "SA") {
        conteggio$synack_count += 1;
    }
    if (flags == "A") {
        conteggio$ack_count += 1;
    }
    print fmt("TCP Packet: %s Syn-Ack Count: %d, Ack Count: %d", payload, conteggio$synack_count, conteggio$ack_count);

    #ack -> time between syn_ack and ack
    local uid: string = c$uid;
    local end_time: time;
    local start_time: time;
    local durata: double;
    local nuova_connessione: connessione;
    local vecchia_connessione: connessione;

    if (uid !in connessioni_table) {
        if (flags == "SA"){
            start_time = c$start_time + c$duration;
            nuova_connessione = [$uid=uid, $start_time=start_time, $end_time=c$start_time];
            connessioni_table[uid] = nuova_connessione;
        }
    }
    else {
        if (flags == "A"){
            end_time = c$start_time + c$duration;
            vecchia_connessione = connessioni_table[uid];
            nuova_connessione = [$uid=uid, $start_time=vecchia_connessione$start_time, $end_time=end_time];
            connessioni_table[uid] = nuova_connessione;
            durata = interval_to_double(end_time - c$start_time);
            print fmt("Connessione TCP ACK: UID %s, Start Time %s, End Time %s, Durata: %s", uid, c$start_time, end_time, durata);
        }
    }

    #syn -> time between syn and syn_ack
    local uids: string = c$uid;
    local end_times: time;
    local duratas: double;
    local nuova_connessiones: connessiones;

    # Verifica se la stringa uid è già presente nella tabella
    if (uids !in connessioni_tables) {
        if (flags == "S"){
            nuova_connessiones = [$uid=uids, $start_time=c$start_time, $end_time=c$start_time];
            connessioni_tables[uid] = nuova_connessiones;
        }
    }
    # Altrimenti, la connessione esiste già nella tabella
    else {
        if (flags == "SA"){
            end_times = c$start_time + c$duration;
            nuova_connessiones = [$uid=uids, $start_time=c$start_time, $end_time=end_times];
            connessioni_tables[uid] = nuova_connessiones;
            duratas = interval_to_double(end_times - c$start_time);
            print fmt("Connessione TCP SYN: UID %s, Start Time %s, End Time %s, Durata: %s", uids, c$start_time, end_times, duratas);
        }
    }
}
