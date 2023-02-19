# Configurazione Interfacce
ip addr add  10.23.1.2/24 dev enp0s3

# DOVREBBERO CONOSCERLA CON MPLS/BGP/VRF
#ip route add 10.123.0.0/16 via 10.23.1.1 

# Avvio Servizio di NotifyWait per i nuovi file scaricati

inotifywait -m $(cat .conf/to_scan) -e create -e moved_to |
    while read dir action file; do
        echo "The executable '$file' is received in directory '$dir' via '$action'"
        path=$dir$file
        q_path=./av/quarantine/$file
        mv $path $q_path
        python3 ./av/remote_analysis.py $q_path
    done