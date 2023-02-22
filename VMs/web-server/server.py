import utils
from http.server import BaseHTTPRequestHandler, HTTPServer
import netifaces as ni
from jinja2 import Environment, FileSystemLoader
import time
import os

scan = {}
scan_list = []


class WebServer(BaseHTTPRequestHandler):
    """ Handle the GET and PUT requests, updating the html Web Page """

    index = "index.html"
    updated = "updated.html"
    dir1 = "scans/"
    dir2 = "details/"
    filename = "report"

    # send html page to clients
    def do_GET(self):
        # notify details page
        if utils.download_details(self):
            return

        # notify index or updated page
        if len(os.listdir(self.dir1)) == 0:
            f = open(self.index).read()
            if os.path.exists(self.updated):
                os.remove(self.updated)
        else:
            f = open(self.updated).read()

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(bytes(f, 'utf-8'))

    # retrieve new scan information from central node

    def do_PUT(self):
        """ Receives report from the central-node, and parse it to update html Report Table """

        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        try:
            ts = time.strftime("%Y%m%d-%H%M%S")
            file_ts = self.filename + "_" + ts + ".txt"
            path = os.path.join(self.dir1, file_ts)
            output = open(path, 'wb')
            output.write(body)
            output.close()
            self.send_response(201, 'Created')
            self.end_headers()
            response = "Report updated correctly"
            self.wfile.write(response.encode('utf-8'))
            self.update_html()
        except:
            output = "file open error"
            self.send_error(404, output)

    def update_html(self):
        """ Updates the HTML Web Page scanning the report folders, and parsing it into a Table """

        if len(os.listdir(self.dir1)) == 0:
            if os.path.exists(self.updated):
                os.remove(self.updated)
        environment = Environment(loader=FileSystemLoader("templates/"))
        environment.globals['STATIC PREFIX'] = '/'
        count = 0
        check = True
        for filename in os.listdir(self.dir1):
            path1 = os.path.join(self.dir1, filename)
            report = open(path1, 'r')
            self.get_clamav_data(report, check)
            self.get_full_analysis(report, count)
            scan_list.append(scan.copy())
            scan.clear()
            count += 1
        result_template2 = environment.get_template("template-home.html")
        htmlfile = open(self.updated, 'w')
        htmlfile.write(result_template2.render(scan_list=scan_list))
        htmlfile.close()
        scan_list.clear()
        print("HTML report generated.\n")

    def get_clamav_data(self, report, check):
        """ Extract and Parse the Clamav Data from the Global Report """

        clamav = utils.extract_information("<AV1_START>", "<AV1_END>", report)
        print(clamav)
        splitcontent = clamav.splitlines()
        for line in splitcontent:
            res = line.split(":", 1)
            # get only valid info
            if len(res) == 2:
                key, value = res
                # create separated program name and vulnerabilities field from first line
                if check:
                    scan["Program Name"] = key
                    scan["Security"] = value
                    check = False
                else:
                    scan[key] = value
        check = True
        utils.remove_fields(scan)   # remove unuseful fields of clamav

    def get_full_analysis(self, report, count):
        """ Extract the Extended Information from JMDav and Rkhav and writes into a txt file """

        # details field with href for download extended details file
        prog_name = os.path.basename(scan["Program Name"])
        path2 = os.path.join(self.dir2, "analysis_" +
                             str(count) + "_" + prog_name + ".txt")
        scan["Details"] = path2
        # save more details to file for download
        tmp1 = utils.extract_information("<SUMMARY>", "<SUMMARY_END>", report)
        tmp2 = utils.extract_information(
            "<BINARY_ANALYSIS>", "<BINARY_ANALYSIS_END>", report)
        tmp3 = utils.extract_information(
            "<RKHunter_ANALYSIS>", "<END_RKHunter_ANALYSIS>", report)
        # notify that there are other warnings if no malware was found
        if not self.check_security(tmp1):
            scan["Security"] = "WARNING"
        details = open(path2, 'w')
        details.write(tmp1 + "\n\n" + tmp2 + "\n\n" + tmp3)
        details.close()

    def check_security(self, tmp2):
        content = tmp2.splitlines()
        for line in content:
            if "not_safe" in line:
                return False
        return True


if __name__ == "__main__":
    print("Server starting...")
    address = (ni.ifaddresses('macsec0')[ni.AF_INET][0]['addr'], 80)
    #address = ("127.0.0.1", 8080)
    server = HTTPServer(address, WebServer)
    print(time.asctime(), "Start Server - %s:%s" % (address[0], address[1]))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    print(time.asctime(), "\nStop Server - %s:%s" % (address[0], address[1]))
