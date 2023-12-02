# Zeek_Feature_Extractor

## Introduzione
<a href="https://zeek.org">Zeek</a> (inizialmente Bro) è un Tool Open Source per il Monitoraggio della Sicurezza in rete.
In questo progetto questo potente tool viene utilizzato per personalizzare <b>l'estrazione di Feature partendo da file PCAP</b>, a tale scopo vengono utilizzati:
- Il Dataset: <a href="https://www.unb.ca/cic/datasets/modbus-2023.html">"CIC Modbus Dataset 2023"</a>
- Le Features esposte nell'articolo: <a href="https://ieeexplore.ieee.org/document/7348942">"UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)"</a>
Viene creato inoltre un <b>file bash per automatizzare il processo di estrazione delle features</b> e creazione di file di log partendo da una Dataset. 

Viene inoltre creata una rete neurale di classificazione che permette, partendo da un file PCAP di identificare se un file PCAP fornito in Input presenti dal traffico legittimo o meno ed in caso che sia in grado di identificare l'attacco che è stato eseguito.
## Progetto
Il progetto si suddivide nelle seguenti parti:
<a name="feature"></a>
### Regole zeek:
Le regole zeek sono utilizzate per personalizzare l'estrazione delle features, in particolare in questo caso sono state crearete le regole zeek per estrarre le features esposte nell'articolo: <a href="https://ieeexplore.ieee.org/document/7348942">https://ieeexplore.ieee.org/document/7348942</a>. Le feature sono le seguenti:
- Flow Features = Source IP address, Source port number, Destination IP address, Destination port number, Trasaction Portocol
- Basic Features = The state, Record total duration, Source to destination bytes, Destination to source bytes, Source to destination time to live, Destination to source time to live, Source packets retransimetted or dropped, Destination packets retransimetted or dropped, http/ftp/ssh/dns/(-), Source bits per second, Destination bits per second, Source to destination packet count, Destination to source packet count
- Content Features = Source TCP window advertisement, Destination TCP window advertisement, Source TCP sequence number, Destination TCP sequence number, Mean of the flow packet size transmitted by the src, Mean of the flow packet size transmitted by the dst, the depth into the connection of the http request/response transaction
- Time Features = Source jitter, Destination jitter, record start time, record last time, the sum of 'synack' and 'ackdat' of the TCP, the time between the 'syn' and the 'synack' packets of the TCP, the time between the 'synack' and the 'ack' packets of the TCP
- Attacchi Category Features = le regole sono esposte [qui](#attacchi)

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