# Zeek_Feature_Extractor

## Introduzione
Il progetto mira a creare delle regole zeek per l'estrazione delle features esposte nell'articolo: 
https://ieeexplore.ieee.org/document/7348942
da applicare al Dataset CIC Modbus Dataset 2023 https://www.unb.ca/cic/datasets/modbus-2023.html .
Il dataset si suddivide in due tipologie di file pcap, abbiamo così la cartella "Benign" dove vengono salvati diversi file pcap per ogni computer in rete, secondo la seguente architettura:

e la cartella "Attack" dove vengono estratti

## Progetto
Il progetto si suddivide in diverse parti:

### Regole zeek:
Il primo step riguarda la creazione di regole zeek per l'estrazione delle features esposte nell'articolo:
https://ieeexplore.ieee.org/document/7348942
Le feature sono le seguenti
- Flow Features = Source IP address, Source port number, Destination IP address, Destination port number, Trasaction Portocol
- Basic Features = The state, Record total duration, Source to destination bytes, Destination to source bytes, Source to destination time to live, Destination to source time to live, Source packets retransimetted or dropped, Destination packets retransimetted or dropped, http/ftp/ssh/dns/(-), Source bits per second, Destination bits per second, Source to destination packet count, Destination to source packet count
- Content Features = Source TCP window advertisement, Destination TCP window advertisement, Source TCP sequence number, Destination TCP sequence number, Mean of the flow packet size transmitted by the src, Mean of the flow packet size transmitted by the dst, the depth into the connection of the http request/response transaction
- Time Features = Source jitter, Destination jitter, record start time, record last time, the sum of 'synack' and 'ackdat' of the TCP, the time between the 'syn' and the 'synack' packets of the TCP, the time between the 'synack' and the 'ack' packets of the TCP

### Per avviare il feature extractor usare i comandi:
Posizionarsi nella cartella:
'''cd Zeek_Feature_Extractor'''
Testare gli script singoli:
''' zeek -C -r last_capture.pcap ./script/"nome script da testare"'''
''' zeek -C -r labtel.pcap ./script/"nome script da testare"'''
last_capture.pcap -> connessione 3-way-handshake
labtel-pcap -> varie connessioni di tutti i tipi
Automatizzare il processo di estrazione di feature del Dataset per connessioni benigne:
''' chmod +x auto.sh '''
```bash ./auto.sh ```
