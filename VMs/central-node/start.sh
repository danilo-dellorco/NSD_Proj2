# Configurazione Interfacce e Rotte
echo "Configuring Host Interfaces & Routes.."
sudo ip route del 0/0 2>/dev/null
sudo ip addr add 10.23.1.2/24 dev enp0s3 2>/dev/null
sudo ip route add 10.123.0.0/16 via 10.23.1.1 2>/dev/null
sudo ip route add 10.23.0.0/24 via 10.23.1.1 2>/dev/null

# Avvio Servizio di NotifyWait per i nuovi file scaricati
echo "Starting AV Listening Service.."
inotifywait -m $(cat .conf/to_scan) -e create -e moved_to |
    while read dir action file; do
        echo "The executable '$file' is received in directory '$dir' via '$action'"
        path=$dir$file
        q_path=./av/quarantine/$file
        mv $path $q_path
        echo "Starting Remote Analysis.."
        python3 ./av/remote_analysis.py $q_path $path
    done