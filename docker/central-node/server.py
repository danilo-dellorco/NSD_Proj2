import socket
import os
from threading import Thread

MALWARE_DIR = "av-framework/quarantine/"
REPORT_DIR = "av-framework/reports/"
CENTRAL_IP = "127.0.0.0"
AV1_REP_PORT = 8801
AV2_REP_PORT = 8802
AV3_REP_PORT = 8803


def start_listening(port):
    # Initialize Socket Instance
    sock = socket.socket()
    print("Socket created successfully.")

    # binding to the host and port
    sock.bind((CENTRAL_IP, port))

    # Accepts up to 10 connections
    sock.listen(10)
    print('Socket is listening...')

    # Establish connection with the clients.
    con, addr = sock.accept()
    print('Connected with ', addr)

    # Get filename from the client
    data = con.recv(1024)
    file_name = data.decode()
    print("Filename:", file_name)

    # Send ACK
    con.send("OK".encode())

    # Write File in binary
    file_path = REPORT_DIR+file_name
    file = open(file_path, 'wb')

    # Keep receiving data from the client
    line = con.recv(1024)

    while(line):
        file.write(line)
        line = con.recv(1024)

    print('File has been received successfully.')
    file.close()
    con.close()


if __name__ == "__main__":
    av1_rep = Thread(target=start_listening, args=AV1_REP_PORT)
    av2_rep = Thread(target=start_listening, args=AV2_REP_PORT)
    av3_rep = Thread(target=start_listening, args=AV3_REP_PORT)
