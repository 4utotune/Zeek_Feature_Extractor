# Zeek_Feature_Extractor

## Introduzione
<a href="https://zeek.org">Zeek</a> (inizialmente Bro) è un Tool Open Source per il Monitoraggio della Sicurezza in rete.
In questo progetto questo potente tool viene utilizzato per personalizzare <b>l'estrazione di Feature partendo da file PCAP</b>, a tale scopo vengono utilizzati:
- Il Dataset: <a href="https://www.unb.ca/cic/datasets/modbus-2023.html">"CIC Modbus Dataset 2023"</a>
- Le Features esposte nell'articolo: <a href="https://ieeexplore.ieee.org/document/7348942">"UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)"</a>
Viene creato inoltre un <b>file bash per automatizzare il processo di estrazione delle features</b> e creazione di file di log partendo da una Dataset. 

Viene inoltre creata una <b>rete neurale di classificazione</b> che permette, partendo da un file PCAP di identificare se un file PCAP fornito in Input presenti dal traffico legittimo o meno ed in caso che sia in grado di identificare l'attacco che è stato eseguito.

Infine viene utilizza Zeek per <b> l'analisi dell'attacco di VLAN Hopping</b> di tipo Double Tagging, per vedere se è possibile individuare tramite Zeek attacchi di questo tipo.

Il paper completo del progetto è disponibile <a href="https://github.com/4utotune/Zeek_Feature_Extractor/blob/main/Zeek%202.pdf">QUI</a>

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
