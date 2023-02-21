def extract_information(start_tag, end_tag, fp):
    """ Extract Report Info Between two tags """

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


def remove_fields(dictionary):
    """ Remove the useless Fields from the Clamav Report"""

    dictionary.pop("Engine version")
    dictionary.pop("Known viruses")
    dictionary.pop("Scanned directories")
    dictionary.pop("Scanned files")
    dictionary.pop("Infected files")
    dictionary.pop("Data read")


def download_details(self):
    """ Handle the download request for the Extended Txt Report  """

    if self.path.split("/")[1] == "details":
        f = open(self.path[1:]).read()
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(bytes(f, 'utf-8'))
        return True
    return False
