from scapy.all import *

file_number = 5
list_IP = []
most_frequent_IP = []


def main(path):
    file = open("output.txt", "w+")
    while 1:
        try:
            open_file_in_a_way_to_be_readable(path, file)
            for i in list_IP:
                file.write(i + "\n")
            most = (most_frequent(most_frequent_IP))
            file.write(most)
            file.close()
            exit()
        except FileNotFoundError:
            print('File not found.')
            exit()


def hex_add(data):
    hex_addr = ""

    for i in range(0, len(data), 2):
        hex_addr += data[i:i + 2]
        hex_addr += " "
    return hex_addr.upper()


def hex_all(data):
    hexa = ""
    temp = 1

    for i in range(2, len(data) + 2, 2):
        hexa += data[i:i + 2]
        hexa += " "
        if i == 8 * temp * 2:
            if i == 16 * temp and i % 32 == 0:
                hexa += "\n"
                temp += 1
            else:
                hexa += "  "
                temp += 1
    return hexa.upper()


def get_ip(data):
    ip_addr = ""

    for i in range(0, len(data), 3):
        ip_addr += str(int(data[i:i + 2], 16))
        if i < len(data) - 4:
            ip_addr += "."
    return ip_addr


def get_nested(data, protocol):
    E_type = struct.unpack('! H', data[12:14])
    E_type = int(E_type[0])
    if E_type >= 1500:
        f = open("E_proto.txt")
    else:
        f = open("802_proto.txt")

    for lines in f:
        inner_list = [elt.strip() for elt in lines.split(' ', maxsplit=1)]
        if inner_list[0] == protocol:
            result = inner_list[1]
            f.close()
            return str(result)
    return "unidentified protocol [" + protocol + "]"


def get_protocol(protocol):
    prots = open("protocols.txt")
    protocol = str(protocol)

    for lines in prots:
        inner_list = [elt.strip() for elt in lines.split(' ', maxsplit=1)]
        if inner_list[0] == protocol:
            result = inner_list[1]
            prots.close()
            return str(result)
    return "unidentified protocol [" + protocol + "]"


'''
    switcher = {
        "2048": "Internet Protocol version 4 (IPv4)",
        "2054": "Address Resolution Protocol (ARP)",
        "0000": "IEEE 802.3 Lenght Field",
    }
    return switcher.get(protocol, "unidentified_protocol [" + protocol + "]")
'''


def calculate_length(length):
    if length < 60:
        length = 64
    else:
        length += 4
    return length


def nested(number, data):
    prot = ""
    if number == "2048":
        prot = IPv4(data[23])
    elif number == "2054":
        prot = ARP()
    elif number == "34525":
        prot = IPv6()
    return prot


def ARP():
    return "ARP"


def IPv4(data):
    return get_protocol(data)


def IPv6():
    return "IPv6"


def save_IP(ip):
    global list_IP
    global most_frequent_IP
    most_frequent_IP.append(ip)
    i = 0
    while True:
        if i >= len(list_IP):
            list_IP.append(ip)
            return
        elif list_IP[i] == ip:
            return
        i += 1


def most_frequent(List):
    counter = 0
    num = List[0]

    for i in List:
        frequency = List.count(i)
        if frequency > counter:
            counter = frequency
            num = i
    return "\n" + num + "   " + str(counter)


def tato_funkcia_zisti_aky_je_to_protokol(data):
    E_type = struct.unpack('! H', data[12:14])
    E_type = int(E_type[0])
    if E_type >= 1500:
        return "Ethernet II\n"
    else:
        IE = struct.unpack('! H', data[14:16])
        # IEE = struct.unpack('! B', data[15:16])
        if int(IE[0]) == 65535:
            return "IEEE 802.3 – Raw\n"
        # elif int(IEE[0]) == 170:
        elif int(data[15]) == 170:
            return "IEEE 802.3 LLC + SNAP\n"
        else:
            return "IEEE 802.3 LLC\n"


def printing(data, src_mac, dest_mac, proto, vers, length, src_ip, dest_ip, file):
    file.write("\nFrame Length pcap API " + str(len(data)) + "\n")
    leng = calculate_length(len(data))
    file.write("Captured Length " + str(leng) + "\n")
    file.write(tato_funkcia_zisti_aky_je_to_protokol(data))
    file.write("Destination MAC: " + hex_add(dest_mac.hex()) + "\n")
    file.write("Source MAC: " + hex_add(src_mac.hex()) + "\n")
    file.write("Protocol = " + get_nested(data, str(proto)) + "\n")
    # file.write("Protocol number = " + str(proto) + "\n")
    # file.write("Version = " + str(vers) + "\n")
    # file.write("Header Length = " + str(length) + "\n")
    file.write("Source IP: " + get_ip(hex_add(src_ip.hex())) + "\n")
    file.write("Destination IP: " + get_ip(hex_add(dest_ip.hex())) + "\n")
    file.write(nested(str(proto), data) + "\n\n")
    file.write(hex_all("00" + data.hex()))
    file.write("\n")
    file.write("\n")


def collecting_data(data, file):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    header = data[14]
    h_version = header >> 4  # prve 4 bity su verzia
    h_length = (header & 15) * 4  # dalsie 4 su dlzka
    src_addr, dest_addr = struct.unpack('! 4s 4s', data[26:34])

    printing(data, src_mac, dest_mac, protocol, h_version, h_length, src_addr, dest_addr, file)
    if str(protocol) == "2048":
        save_IP(get_ip(hex_add(src_addr.hex())))     # heh


def open_file_in_a_way_to_be_readable(path, output_file):
    file = rdpcap(path)
    i = 1
    for frames in file:
        output_file.write("Frame " + str(i))
        i += 1
        collecting_data(raw(frames), output_file)
        output_file.write("\n")
    return


file_path = r"D:\vzorky_pcap_na_analyzu\\"
final_file = r"eth-" + str(file_number) + ".pcap"
# main(file_path+final_file)
main(r"D:\vzorky_pcap_na_analyzu\trace-22.pcap")
