inotifywait -m /malwares -e create -e moved_to |
    while read dir action file; do
        echo "The executable '$file' is received in directory '$dir' via '$action'"
        path=$dir$file
        python3 client.py $path
    done