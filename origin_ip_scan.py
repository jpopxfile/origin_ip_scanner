import sys
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import ssl
import OpenSSL

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def check_cn(ip, cn_host):
    cert = ssl.get_server_certificate((ip, 443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    details = x509.get_subject().get_components()
    for detail in details:
        if detail[0] == "CN" and cn_host in detail[1]:
            return True

    return False

API_URL = "https://censys.io/api/v1/search/ipv4"
UID = "youruid"
SECRET = "yoursecret"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)

    domain = sys.argv[1]

    data = {"query": domain, "fields":["ip", "location.country", "autonomous_system", "notes"]}

    session = requests.Session()
    #session.verify = False
    res = session.post(API_URL , auth=(UID, SECRET), data=json.dumps(data))
    if res.status_code != 200:
        print "error occurred: %s" % res.json()["error"]
        sys.exit(1)

    json_data = json.loads(res.content)

    if json_data["status"] == "ok":
        no_verify_sess = requests.Session()
        no_verify_sess.verify = False
        for result in json_data["results"]:
            description = result["autonomous_system.description"]
            if description.find("CLOUDFLARENET") < 0:
            
                ip = result["ip"]
                ip_link = "https://"+ip

                r = no_verify_sess.get(ip_link)

                if (r.status_code == 200 or r.status_code == 301 or r.status_code == 302) and check_cn(ip,domain):
                    print ("{} --  {}  -- {}".format(ip, ip_link, result["autonomous_system.description"]))

