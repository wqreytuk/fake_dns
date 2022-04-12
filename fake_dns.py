import socketserver
import sys
import argparse

DNS_HEADER_LENGTH = 12

# dns query type
query_type = {
    b'\x00\x01': 'A',
    b'\x00!': 'SRV'
}

g_target_domain = ""
g_server_fqdn = ""
g_server_ip = ""


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        socket = self.request[1]
        data = self.request[0].strip()

        # If request doesn't even contain full header, don't respond.
        if len(data) < DNS_HEADER_LENGTH:
            return

        # Try to read questions - if they're invalid, don't respond.
        try:
            all_questions = self.dns_extract_questions(data)
        except IndexError:
            return

        # Filter only those questions, which have QTYPE=A and QCLASS=IN
        # TODO this is very limiting, remove QTYPE filter in future, handle different QTYPEs
        accepted_questions = []
        for question in all_questions:
            name = str(b'.'.join(question['name']), encoding='UTF-8')
            print(name)
            if g_target_domain not in name or '_ldap' not in name and g_server_fqdn not in name:
                continue
            print("[*] query type:\n\t" + query_type[question['qtype']])
            print("[*] query name:\n\t" + name)
            if question['qtype'] == b'\x00\x01' and question['qclass'] == b'\x00\x01':
                # this is a A record query, we should response with a A(IP) record
                response = (
                        self.dns_response_header(data) +
                        self.dns_generate_question_section(question) +
                        self.dns_generate_A_answers()
                )
                socket.sendto(response, self.client_address)
            elif question['qtype'] == b'\x00!' and question['qclass'] == b'\x00\x01':
                # this is a SRV record query, we should response with a SRV record
                response = (
                        self.dns_response_header(data) +
                        self.dns_generate_question_section(question) +
                        self.dns_generate_SRV_answers(name)
                )
                socket.sendto(response, self.client_address)
            else:
                print('[-] what is this?\n\t' + name)

    def dns_extract_questions(self, data):
        """
        Extracts question section from DNS request data.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        questions = []
        # Get number of questions from header's QDCOUNT
        n = (data[4] << 8) + data[5]
        # Where we actually read in data? Start at beginning of question sections.
        pointer = DNS_HEADER_LENGTH
        # Read each question section
        for i in range(n):
            question = {
                'name': [],
                'qtype': '',
                'qclass': '',
            }
            length = data[pointer]
            # Read each label from QNAME part
            while length != 0:
                start = pointer + 1
                end = pointer + length + 1
                question['name'].append(data[start:end])
                pointer += length + 1
                length = data[pointer]
            # Read QTYPE
            question['qtype'] = data[pointer + 1:pointer + 3]
            # Read QCLASS
            question['qclass'] = data[pointer + 3:pointer + 5]
            # Move pointer 5 octets further (zero length octet, QTYPE, QNAME)
            pointer += 5
            questions.append(question)
        return questions

    def dns_response_header(self, data):
        """
        Generates DNS response header.
        See http://tools.ietf.org/html/rfc1035 4.1.1. Header section format.
        """
        header = b''
        # ID - copy it from request
        header += data[:2]
        # QR     1    response
        # OPCODE 0000 standard query
        # AA     0    not authoritative
        # TC     0    not truncated
        # RD     0    recursion not desired
        # RA     0    recursion not available
        # Z      000  unused
        # RCODE  0000 no error condition
        header += b'\x80\x00'
        # QDCOUNT - question entries count, set to QDCOUNT from request
        header += data[4:6]
        # ANCOUNT - answer records count, set to QDCOUNT from request
        header += data[4:6]
        # NSCOUNT - authority records count, set to 0
        header += b'\x00\x00'
        # ARCOUNT - additional records count, set to 0
        header += b'\x00\x00'
        return header

    def dns_generate_question_section(self, question):
        """
        https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
        according to the rfc, the for mat Queries segment is:
        ++++++++++
        |Name    |
        ++++++++++
        |QType   |
        ++++++++++
        |QClass  |
        ++++++++++
        the Name field is consist of a sequence of labels
        a label consist of a length(1 byte) and data followed(determined by length)
        """
        section = b''
        for label in question['name']:
            section += bytes([len(label)])
            section += label
        # add terminate byte \x00
        section += b'\x00'
        # qtype and qclass
        section += question['qtype']
        section += question['qclass']
        return section

    def dns_generate_SRV_answers(self, name):
        """
        during the dns packet analysing, I found that there is always a c00c bytes in the response packet
        here is the official document about it: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
        turns out this is a packet compression trick
        to eliminate to repetition of DNS name
        so the first two octets is a pointer, which points to the occurrence of the DNS name
        the first two bits is set to 1 to distinguish from label
        the left 14 bits is the offset of the occurrence of the DNS name in this message
        c00c's binary form: 1100 0000 0000 1100
        after removing the first '1', the value will be 1100, which is 12 in decimal
        and yes, according to the packet in wireshark, this is 12 bytes from the beginning to the first occurrence of the DNS name
        here is the screen shot: https://img-blog.csdnimg.cn/85009b5077084ccf8d6adc8bf2fbf8d3.png
        at least in A and SRV record response, the value will always be c00c
        """
        # here is the first two octets which indicate the occurrence of the DNS name
        record = b'\xc0\x0c'
        # then Type, 33(0x21) for SRV
        record += b'\x00\x21'
        # the Class, 0x0001 for IN(internet)
        record += b'\x00\x01'
        # then TTL, just set it to 600
        record += b'\x00\x00\x02\x58'
        # then Data Length, this is the desired DC FQDN length + 4
        # the additional 4 bytes is occupied by Priority(2) and Weight(2)
        record += b'\x00\x25'  # which is 37 len(WIN-BTAP0QG1S13.mother.fucker) + 4
        # then Priority, set it to 0
        record += b'\x00\x00'
        # then Weight, set it to 100
        record += b'\x00\x64'
        # server port, 2 bytes, we set this value according to the name in SRV query
        if 'kerberos' in name:
            print('[*] kerberos HIT')
            record += b'\x00\x58'
        elif 'ldap' in name:
            print('[*] ldap HIT')
            record += b'\x01\x85'
        # finally, the FQDN of the DC(ldap server)
        for label in g_server_fqdn.split('.'):
            record += len(label).to_bytes(1, 'big')
            for char in label:
                record += ord(char).to_bytes(1, 'big')
        record += b'\x00'
        print(" ".join([hex(int(i)) for i in record]))
        print("SRV response generated for " + g_server_fqdn)
        return record

    def dns_generate_A_answers(self):
        """
        the A record foramt is similar with SRV record
        name compression: 0cc0
        Type: 2 bytes
        Class: 2 bytes
        TTL: 4 bytes
        Data Length: 2 bytes
        IP: 4 bytes
        """
        # here is the first two octets which indicate the occurrence of the DNS name
        record = b'\xc0\x0c'
        # then Type, 1(0x01) for A
        record += b'\x00\x01'
        # the Class, 0x0001 for IN(internet)
        record += b'\x00\x01'
        # then TTL, just set it to 600
        record += b'\x00\x00\x02\x58'
        # then Data Length, IP length, for IPV4, will always be 4 byte
        record += b'\x00\x04'
        # finally, the IP of the DC(ldap server)
        for num in g_server_ip.split('.'):
            record += int(num).to_bytes(2, 'big')
        print("A response generated for " + g_server_ip)
        return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False, description="this is a fake DNS server, "
                                                                 "it only responses to specific domain's SRV and "
                                                                 "A query, "
                                                                 "this is just a little toy for fun!")
    parser._optionals.title = "Main options"

    parser.add_argument("-h", "--help", action="help", help='show this help message and exit')
    parser.add_argument('-domain', '--target-domain', action='store', help='Domain of the ldap server')
    parser.add_argument('-fqdn', '--server-fqdn', action='store', help='FQDN of the ldap server')
    parser.add_argument('-ip', '--server-ip', action='store', help='IP of the ldap server')
    options = parser.parse_args()

    g_target_domain = options.target_domain
    g_server_fqdn = options.server_fqdn
    g_server_ip = options.server_ip

    server = socketserver.ThreadingUDPServer(('', 53), DNSHandler)
    print('DNS server started...')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        sys.exit(0)
