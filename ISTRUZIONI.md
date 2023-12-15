## Struttura della repository:
Vengono ora fornite le indicazioni su come testare tutto il codice da me scritto.

### Vlan Hopping:
0. Posizionarsi all'interno della cartella:
```bash
cd vlan_hopping
```
1. Creazione del file output.pcap ovvero il pcap contente il traffico dell'attacco di Vlan Hopping:
```bash
python3 creazione_vlanHopping.py
```
2. Testare lo script Zeek sui due file pcap benigno e malevolo:
```bash
zeek -C -r output.pcap vlan.zeek
zeek -C -r vlan.pcap vlan.zeek
```

### Attacchi Zeek:
0. Posizionarsi all'interno della cartella:
```bash
cd attacchi_zeek
```
1. È possibile testare il singolo script di rilevazione dell'attacco:
```bash
zeek -C -r ../labtel.pcap "nome script da testare"
```
2. Testare tutti gli script insieme come viene effettuato nei veri NIDS:
```bash
zeek -C -r ../labtel.pcap __load__.zeek
```
Ricordarsi di modificare i PATH nel file __load__.zeek

### Script
Le feature singole sono state raggruppate ed ordinate in questa cartella in modo da essere più facilmente testabili.

0. Posizionarsi all'interno della cartella:
```bash
cd script
```
1. È possibile testare il singolo script di estrazione complessivo delle feature (legate all'evento):
```bash
zeek -C -r ../labtel.pcap "nome script da testare"
```
2. Testare tutti gli script insieme come viene effettuato nei veri NIDS:
```bash
zeek -C -r ../labtel.pcap __load__.zeek
```
Ricordarsi di modificare i PATH nel file __load__.zeek

### Rete Neurale:
0. Posizionarsi all'interno della cartella:
```bash
cd ai
```
1. Effettuare test di funzionamento generico limitando la lettura di ogni pcap a 1000 pacchetti:
```bash
python3 dataset1.py
python3 def_ai.py
```
2. Creare ed allenare la rete neurale senza limitazioni:
```bash
python3 dataset1completo.py
python3 fed_ai.py
```

### Feature Singole:
0. Posizionarsi all'interno della cartella:
```bash
cd feature_singole
```
1. È possibile testare il singolo script di rilevazione dell'attacco:
```bash
zeek -C -r ../last_capture.pcap "nome script da testare"
zeek -C -r ../labtel.pcap "nome script da testare"
```
I file pcap sono:
last_capture.pcap -> connessione 3-way-handshake
labtel-pcap -> varie connessioni di tutti i tipi
non tutti gli script funzionano con "last_capture.pcap" poichè questo presenta solo 3 pacchetti e dunque potrebbero non restituire niente.

### Stats
Comandi per ottenere le statistiche del Dataset CIC Modbus 2023 in modo da potrelo confrontare con il dataset UNSW-NB15
0. Posizionarsi all'interno della cartella:
```bash
cd stats
```
1. Dare i permessi ai file bash:
```bash
chmod +x finale_benigno.sh
chmod +x finale_malevolo.sh
chmod +x tot.sh
```
2. Eseguire i file:
```bash
./finale_benigno.sh
./finale_malevolo.sh
```
3. Ottenere le statistiche per ogni file "finale.txt" generato:
```bash
./tot.sh
```

### Ottenere risultati in maniera automatica
0. Posizionarsi nella cartella:
```bash
cd Zeek_Feature_Extractor
```
1. Automatizzare il processo di estrazione di feature del Dataset per connessioni benigne:
```bash
chmod +x auto.sh
./auto.sh 
```
Le Features estratte ed i risultati sono scritti nella cartella di "Results"!
