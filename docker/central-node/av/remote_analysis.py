from threading import Thread
import socket
import os
import sys

# Defining port and host
SEND_PORT = 8800

AV1_IP = '127.0.0.1'
AV2_IP = '127.0.0.2'
AV3_IP = '127.0.0.3'

MALWARE_DIR = "av/quarantine/"
REPORT_DIR = "av/reports/"
CENTRAL_IP = "127.0.0.0"
AV1_REP_PORT = 8801
AV2_REP_PORT = 8802
AV3_REP_PORT = 8803


def send_file(file_path, file_name, dest_ip, rep_port):
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

    # Listening for Response only after Malware it's succesfully sent
    report_thread = Thread(target=start_listening, args=[rep_port])
    report_thread.start()
    return 0


def start_listening(port):
    print(f"Spawned thread, listening on {port} for incoming report")

    # Initialize Socket & Bind Address
    sock = socket.socket()
    sock.bind((CENTRAL_IP, port))
    sock.listen(1)  # max 1 incoming connnection

    # Waiting for client connections.
    con, addr = sock.accept()

    # Get filename from the client
    data = con.recv(1024)
    file_name = data.decode()

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

    print(f'{port}: Report has been received successfully. Saved on {file_path}')
    file.close()
    con.close()


if __name__ == "__main__":
    file_path = sys.argv[1]
    file_name = os.path.basename(file_path)

    # Sending File to AVs
    send_file(file_path,    file_name, AV1_IP, AV1_REP_PORT)
    send_file(file_path, file_name, AV2_IP, AV2_REP_PORT)
    # send_file(file_path, file_name,AV3_IP, AV3_REP_PORT)
