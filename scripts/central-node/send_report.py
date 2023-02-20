import requests

def send_file():
    f = open('reports/_report.log', 'rb')
    r = requests.put('http://127.0.0.1:8080', data=f.read())
    print("Scan file send to web servers.")

send_file()