import socket
import os

MALWARE_DIR = "av-framework/quarantine/"
REPORT_DIR = "av-framework/reports/"
CENTRAL_IP = "127.0.0.0"
REPORT_PORT = 8900


def start_listening():
    # Initialize Socket Instance
    sock = socket.socket()
    print("Socket created successfully.")

    # binding to the host and port
    sock.bind((CENTRAL_IP, REPORT_PORT))

    # Accepts up to 10 connections
    sock.listen(10)
    print('Socket is listening...')

    while True:

        # Establish connection with the clients.
        con, addr = sock.accept()
        print('Connected with ', addr)

        # Get filename from the client
        data = con.recv(1024)
        print(type(data))
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
    start_listening()
