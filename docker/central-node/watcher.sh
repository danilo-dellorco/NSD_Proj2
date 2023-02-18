inotifywait -m $(cat .conf/to_scan) -e create -e moved_to |
    while read dir action file; do
        echo "The executable '$file' is received in directory '$dir' via '$action'"
        path=$dir$file
        q_path=./av/quarantine/$file
        mv $path $q_path
        python3 client.py $q_path
    done