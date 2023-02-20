import socket
from lib import comparator
import os

MALWARE_DIR = "av/quarantine/"
REPORT_DIR = "av/reports/"
CENTRAL_IP = "10.23.1.2"
HOST_IP = "10.123.0.4"

REPORT_SUFFIX = "_REPav3.log"
LOG_DIR = "/var/log/"
BASELINE_LOG = "rkhunter_baseline.log"
LOG_NAME = "_rkhunter.log"

MALWARE_PORT = 8800
REPORT_PORT = 8803
ELF_FORMAT = "ELF"

SUMMARY_TAG = '<DIFF_SUMMARY>'
END_SUMMARY_TAG = '<DIFF_SUMMARY_END>'
ANALYSIS_TAG = '<RKHunter_ANALYSIS>'
END_ANALYSIS_TAG = '<END_RKHunter_ANALYSIS>'


def analyze_file(file_path, file_name):
    print("Analyzing...")
    report_path = REPORT_DIR+file_name+REPORT_SUFFIX
    report_name = file_name+REPORT_SUFFIX

    report_file = open(report_path, 'w')

    file_info = os.popen(f"file {file_path}").read()

    if ELF_FORMAT not in file_info:
        report_file.write("Can't execute on this environment\n")
        send_file(report_path, report_name)

    # binary execution
    os.system(f"chmod 777 /{file_path} ; ./{file_path}")

    # rkhunter analysis
    os.system("rkhunter --check --sk --nocolors > " +
              LOG_DIR+file_name+LOG_NAME)

    print("Analysis Completed")

    # compare with baseline log
    with open(LOG_DIR+BASELINE_LOG) as baseline, open(LOG_DIR+file_name+LOG_NAME) as log:
        difference = comparator.compare_report(baseline, log)

    summary_str = SUMMARY_TAG + "\n"\
        + difference + \
        END_SUMMARY_TAG + "\n\n\n" +\
        ANALYSIS_TAG + "\n"

    with open(LOG_DIR+file_name+LOG_NAME) as log:
        summary_str += ''.join(log.readlines())

    summary_str += END_ANALYSIS_TAG+"\n"
    report_file.write(summary_str)
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

        while (line):
            file.write(line)
            line = con.recv(1024)

        print('File has been received successfully.')
        file.close()
        con.close()
        analyze_file(file_path, file_name, )


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
    while (line):
        sock.send(line)
        line = file.read(1024)

    file.close()
    sock.close()
    print('File has been transferred successfully.')
    return 0


if __name__ == "__main__":
    start_listening()
