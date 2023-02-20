import threading
import socket
import os
import sys
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox as mb
from functools import partial

# Defining Directories
MALWARE_DIR = "av/quarantine/"
REPORT_DIR = "av/reports/"

# Defining Ports and IPs
AV1_REP_PORT = 8801
AV2_REP_PORT = 8802
AV3_REP_PORT = 8803

CENTRAL_IP = "10.23.1.2"
AV1_IP = '10.123.0.2'
AV2_IP = '10.123.0.3'
AV3_IP = '10.123.0.4'

# TAGs to Parse the Report
REPORT_SUFFIXES = ["_REPav1.log", "_REPav2.log", "_REPav3.log"]
AGGREGATE_SUFFIX = "_report.log"
SUMMARY_TAG = "<SUMMARY>"
SUMMARY_ENDTAG = "<SUMMARY_END>"
BINARY_TAG = "<BINARY_ANALYSIS>"
BINARY_ENDTAG = "<BINARY_ANALYSIS_END>"
DIFF_SUMMARY_TAG = "<DIFF_SUMMARY>"
DIFF_SUMMARY_ENDTAG = "<DIFF_SUMMARY_END>"
START_TAGS = ["<AV1_START>", "<AV2_START>", "<AV3_START>"]
END_TAGS = ["<AV1_END>", "<AV2_END>", "<AV3_END>"]

lock_av1 = threading.Lock()
lock_av2 = threading.Lock()
lock_av3 = threading.Lock()


def delete_mw(quarantine_path, window):
    """Choose to Delete the malware from the Central-Node"""

    tk.messagebox.showinfo("Message", "File has Been Deleted.")
    os.system(f"rm {quarantine_path}")
    window.withdraw()
    window.destroy()


def keep_mw(quarantine_path, original_path, window):
    """Choose to Keep the malware in the Central-Node"""

    tk.messagebox.showinfo(
        "Message", "File has been kept in "+quarantine_path)
    window.withdraw()
    window.destroy()


def send_file(file_path, file_name, dest_ip, rep_port):
    """ Send the malware to the test node dest_ip"""

    if rep_port == AV1_REP_PORT:
        lock = lock_av1
    elif rep_port == AV2_REP_PORT:
        lock = lock_av2
    elif rep_port == AV3_REP_PORT:
        lock = lock_av3
    lock.acquire()

    print(f"Spawned thread, sending malware on {rep_port}")

    # Initialize Socket Instance
    sock = socket.socket()
    print("Socket created successfully.")

    # Connect socket to the host and port
    sock.connect((dest_ip, rep_port))
    print('Connection Established.')

    # Send filename to the server, and wait for ACK to continue
    print("Filename:", file_name)
    sock.send(file_name.encode())
    sock.recv(2)  # Receive ACK

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
    start_listening(rep_port, lock)
    return 0


def start_listening(port, lock):
    """ Listen for report from test node"""

    print(f"Thread listening on {port} for incoming report")
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
    lock.release()


def extract_information(start_tag, end_tag, fp):
    """ Returns the string between two tags in a file """

    copy = False
    out = ""
    for line in fp:
        if line.strip() == start_tag:
            copy = True
            continue
        elif line.strip() == end_tag:
            copy = False
            continue
        elif copy:
            out += line

    fp.seek(0)
    return out


def make_decision(report_path, file_path, original_path):
    """ 
    Evaluates the report and decides if the executable it's dangerous or not.
    If the exec it's dangerous a prompt it's showed to the user to decide to delete the mw or not
    """

    threats_found = []
    report = open(report_path, "r")
    report_av1 = extract_information(START_TAGS[0], END_TAGS[0], report)
    report_av2 = extract_information(SUMMARY_TAG, SUMMARY_ENDTAG, report)[2:-3]
    report_av3 = extract_information(
        DIFF_SUMMARY_TAG, DIFF_SUMMARY_ENDTAG, report)

    result_av1 = report_av1.split("\n")[0].split()
    result_av2 = report_av2.split(",\n")
    result_av3 = report_av3.split("\n")

    if ("FOUND" in result_av1):
        threats_found.append(result_av1[1])

    for entry in result_av2:
        entry = entry.replace('\"', "")
        entry = entry.replace(' ', "")
        if ("not_safe" in entry):
            threats_found.append(entry)

    for diff in result_av3:
        diff = diff.replace('!', "")
        diff = diff.replace(' ', "")
        if ("Found" in diff or "Warning" in diff):
            diff = diff.replace('[', "  [")
            threats_found.append(diff)

    if threats_found != []:
        ask_user(file_path, threats_found, original_path)


def ask_user(file_path, threats, original_path):
    """ Ask the user to delete or Keep the malware, showing the threats encountered"""

    ws = tk.Tk()
    ws.eval('tk::PlaceWindow . center')
    ws.title(string='Antivirus Framework')
    ws.geometry('700x300')

    frame = tk.LabelFrame(
        ws,
        text=f"The following issues has been found on {original_path}",
        font=("ubuntu-mono 15 bold")
    )
    frame.pack(expand=True, fill=tk.BOTH)

    for y in range(0, len(threats)):
        label = tk.Label(
            frame,
            text=" - " + threats[y],
            fg="red",
            font="ubuntu-mono 10 bold",
            anchor="w"
        )
        label.grid(row=y, sticky="W")

    frame = tk.LabelFrame(
        ws,
        text="",
        font=(20)
    )
    frame.pack(expand=True, fill=tk.BOTH)

    tk.Button(
        frame,
        text='Delete File',
        command=partial(delete_mw, file_path, ws)
    ).pack()

    tk.Button(
        frame,
        text=' Keep File ',
        command=partial(keep_mw, file_path, original_path, ws)
    ).pack()
    ws.mainloop()


def merge_file(infile, outfile, separator=""):
    """ Helper to merge two files"""

    for line in infile:
        outfile.write(line.strip("\n")+separator+"\n")


def merge_files(paths, outpath, separator=""):
    """ Merge two files """
    with open(outpath, 'w') as outfile:
        for i in range(0, len(paths)):
            with open(paths[i]) as infile:
                outfile.write(START_TAGS[i]+"\n")
                merge_file(infile, outfile, separator)
                outfile.write(END_TAGS[i]+"\n\n")


def aggregate_reports(filename):
    """ Generates the aggregate report of the AVs"""

    report_files = [0, 0, 0]
    for i in range(0, 3):
        report_files[i] = (REPORT_DIR+filename+REPORT_SUFFIXES[i])
    out_path = REPORT_DIR+filename+AGGREGATE_SUFFIX
    merge_files(report_files, out_path)
    return out_path


if __name__ == "__main__":
    file_path = sys.argv[1]
    original_path = sys.argv[2]
    file_name = os.path.basename(file_path)

    # Sending File to AVs
    av1_thr = threading.Thread(target=send_file, args=[
                               file_path, file_name, AV1_IP, AV1_REP_PORT])
    av2_thr = threading.Thread(target=send_file, args=[
                               file_path, file_name, AV2_IP, AV2_REP_PORT])
    av3_thr = threading.Thread(target=send_file, args=[
                               file_path, file_name, AV3_IP, AV3_REP_PORT])
    av1_thr.start()
    av2_thr.start()
    av3_thr.start()

    # Make decision on file only after all AVs reports has been received
    lock_av1.acquire()
    lock_av2.acquire()
    lock_av3.acquire()

    aggregate_rep_path = aggregate_reports(file_name)
    make_decision(aggregate_rep_path, MALWARE_DIR+file_name, original_path)
    # TODO send to http server

    # Clean Local Reports
    os.system("/bin/rm av/reports/*")
