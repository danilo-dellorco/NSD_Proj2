import socket
import os
import sys

# Defining port and host
SEND_PORT = 8806
SEND_IP = '0.0.0.0'


def send_file(file_path, file_name):
    # Initialize Socket Instance
    sock = socket.socket()
    print("Socket created successfully.")

    # Connect socket to the host and port
    sock.connect((SEND_IP, SEND_PORT))
    print('Connection Established.')

    # Send filename to the server, and wait for ACK to continue
    print("Filename:", file_name)
    sock.send(file_name.encode())
    ack = sock.recv(2)
    print(ack.decode())

    # Read File in binary
    file = open(file_path, 'rb')
    line = file.read(1024)

    # Keep sending data to the server
    while(line):
        sock.send(line)
        line = file.read(1024)

    file.close()
    sock.close()
    print('File has been transferred successfully.')
    return 0


if __name__ == "__main__":
    file_path = sys.argv[1]
    file_name = os.path.basename(file_path)
    send_file(file_path, file_name)
