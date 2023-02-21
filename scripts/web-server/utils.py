# extract info between two tags
def extract_information(start_tag, end_tag, fp):
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

# remove unuseful fields from report
def remove_fields(dictionary):
    dictionary.pop("Engine version")
    dictionary.pop("Known viruses")
    dictionary.pop("Scanned directories")
    dictionary.pop("Scanned files")
    dictionary.pop("Infected files")
    dictionary.pop("Data read")

# send html page of detailed analysis
def download_details(self):
    if self.path.split("/")[1] == "details":
        f = open(self.path[1:]).read()
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(bytes(f, 'utf-8'))
        return True
    return False