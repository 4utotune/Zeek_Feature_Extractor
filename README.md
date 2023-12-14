# Zeek_Feature_Extractor

## Introduzione
<a href="https://zeek.org">Zeek</a> (inizialmente Bro) è un Tool Open Source per il Monitoraggio della Sicurezza in rete.
In questo progetto questo potente tool viene utilizzato per personalizzare <b>l'estrazione di Feature partendo da file PCAP</b>, a tale scopo vengono utilizzati:
- Il Dataset: <a href="https://www.unb.ca/cic/datasets/modbus-2023.html">"CIC Modbus Dataset 2023"</a>
- Le Features esposte nell'articolo: <a href="https://ieeexplore.ieee.org/document/7348942">"UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)"</a>
Viene creato inoltre un <b>file bash per automatizzare il processo di estrazione delle features</b> e creazione di file di log partendo da una Dataset. 

Viene inoltre creata una <b>rete neurale di classificazione</b> che permette, partendo da un file PCAP di identificare se un file PCAP fornito in Input presenti dal traffico legittimo o meno ed in caso che sia in grado di identificare l'attacco che è stato eseguito.

Infine viene utilizza Zeek per <b> l'analisi dell'attacco di VLAN Hopping</b> di tipo Double Tagging, per vedere se è possibile individuare tramite Zeek attacchi di questo tipo.

Il paper completo del progetto è disponibile <a href="">QUI</a>

### Per avviare il feature extractor usare i comandi:
1. Posizionarsi nella cartella:
```bash
cd Zeek_Feature_Extractor
```
2. Testare gli script singoli: (last_capture.pcap -> connessione 3-way-handshake
labtel-pcap -> varie connessioni di tutti i tipi)
```bash
zeek -C -r last_capture.pcap ./script/"nome script da testare"
zeek -C -r labtel.pcap ./script/"nome script da testare"
```
3. Automatizzare il processo di estrazione di feature del Dataset per connessioni benigne:
```bash
chmod +x auto.sh
./auto.sh 
```
Features estratte ed i risultati sono scritti nella cartella di "Results"!
<a name="attacchi"></a>
### Rilvamento attacchi:
Il Dataset fornito viene da me testato per le seguenti tipologie di attacco:
- Reconnaissance
- DDoS
- Loading payloads 
- Fuzzing
- Modify length parameters
- Shellcode
- Brute force write
- Baseline replay
Gli script per il rilevamento si torvano nella cartella "Attacchi_zeek". Comandi:
```bash
zeek -C -r labtel.pcap ./attacchi_zeek/"nome script da testare"
```
### Feature Singole
Nella cartella "feature_singole" sono presenti gli script che estraggono le singole feature [Vai alla Sezione Collegata](#feature).