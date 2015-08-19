class Certificate:

    def __init__(self, cert_dict, cipher):
        self.not_before = cert_dict["notBefore"]
        self.not_after = cert_dict["notAfter"]
        self.serial_number = cert_dict["serialNumber"]
        self.version = cert_dict["version"]
        self.cipher = cipher

        self.country = cert_dict["subject"][0][0][1]
        self.state = cert_dict["subject"][1][0][1]
        self.locality = cert_dict["subject"][2][0][1]
        self.organization = cert_dict["subject"][3][0][1]
        self.unit = cert_dict["subject"][4][0][1]
        self.commonName = cert_dict["subject"][5][0][1]
        self.email = cert_dict["subject"][6][0][1]

    def to_string(self):
        return "Serial=" + self.serial_number + " [C=" + self.country + " ST=" + self.state + " L=" + self.locality \
               + " O=" + self.organization + " OU=" + self.unit + " CN=" + self.commonName + "/" + self.email + "]" \
               + " Version " + str(self.version) + " Valid " + self.not_before + " until " + self.not_after + " Using " \
               + str(self.cipher)

    def __str__(self):
        return self.to_string()

    def __repr__(self):
        return self.to_string()


user_certificate = None

import configuration
import ssl
cipher_list = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:" \
              "ECDHE-ECDSA-AES256-SHA384:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:" \
              "ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:AES256-GCM-SHA384:AES256-SHA256:" \
              "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:" \
              "ECDHE-ECDSA-AES128-SHA256:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:" \
              "ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:AES128-GCM-SHA256:AES128-SHA256"
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_OPTIONAL
context.load_cert_chain(configuration.cert_chain, keyfile=configuration.keyfile, password=configuration.cert_pass)
context.set_ciphers(cipher_list)


def verify_request(self, request, client_address):
    global user_certificate
    from datetime import datetime
    date_time = str(datetime.utcnow()).split(" ")
    log_file = open("logs/" + date_time[0]+".log", 'a')
    log_file.write("[" + ' '.join(date_time) + "] " + str(request.getpeername()) + " ")
    # request is of type ssl.SSLSocket
    cert = request.getpeercert(False)  # False makes this function return a dict, True returns in binary

    if cert is None:
        log_file.write("No_certificate_supplied.\n")
        log_file.close()
        return True

    certificate = Certificate(cert, request.cipher())
    print certificate.to_string()
    log_file.write(str(certificate) + "\n")
    log_file.close()
    user_certificate = certificate
    return True


def get_user_certificate_str():
    global user_certificate
    return str(user_certificate)


def get_user_certificate():
    global user_certificate
    return user_certificate