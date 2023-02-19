import socket
import os

MALWARE_DIR = "av/quarantine/"
REPORT_DIR = "av/reports/"
CENTRAL_IP = "10.23.1.2"
HOST_IP = '10.123.0.2'
REPORT_SUFFIX = "_REPav1.log"

MALWARE_PORT = 8800
REPORT_PORT = 8801


def analyze_file(file_path, file_name):

    print("Analyzing", file_path)
    report_path = REPORT_DIR+file_name+REPORT_SUFFIX
    report_name = file_name+REPORT_SUFFIX
    os.system(f"clamscan {file_path} > {report_path}")
    os.system(f"rm {file_path}")
    send_file(report_path, report_name)


def start_listening():
    # Initialize Socket Instance
    sock = socket.socket()
    print("Socket created successfully.")

    # binding to the host and port
    sock.bind((HOST_IP, MALWARE_PORT))

    # Accepts up to 10 connections
    sock.listen(10)
    print('Socket is listening...')

    while True:

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
        file_path = MALWARE_DIR+file_name
        file = open(file_path, 'wb')

        # Keep receiving data from the client
        line = con.recv(1024)

        while(line):
            file.write(line)
            line = con.recv(1024)

        print('File has been received successfully.')
        file.close()
        con.close()
        analyze_file(file_path, file_name)


def send_file(file_path, file_name):
    # Initialize Socket Instance
    sock = socket.socket()
    print("Socket created successfully.")

    # Connect socket to the host and port
    sock.connect((CENTRAL_IP, REPORT_PORT))
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
    start_listening()
