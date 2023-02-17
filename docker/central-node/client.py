import socket
import os
import sys

# Defining port and host
SEND_PORT = 8800
REPORT_PORT = 8900
AV1_IP = '127.0.0.1'
AV2_IP = '127.0.0.2'
AV3_IP = '127.0.0.3'


def send_file(file_path, file_name, dest_ip):
    # Initialize Socket Instance
    sock = socket.socket()
    print("Socket created successfully.")

    # Connect socket to the host and port
    sock.connect((dest_ip, SEND_PORT))
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
    print(f'File has been transferred successfully to {dest_ip}.')
    return 0


if __name__ == "__main__":
    file_path = sys.argv[1]
    file_name = os.path.basename(file_path)
    send_file(file_path, file_name, AV1_IP)
    # send_file(file_path, file_name, AV2_IP)
    # send_file(file_path, file_name, AV3_IP)
