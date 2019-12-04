from scapy.all import *

file_number = 5
list_IP = []
most_frequent_IP = []
filt = ""
frame_num = 1


def main():
    global filt
    global frame_num
    file_path = r"D:\vzorky_pcap_na_analyzu\\"
    final_file = input("Meno suboru: ")
    path = file_path + final_file
    try:
        while 1:
            filt = input("Filter: ")
            if filt == "exit":
                exit()
            file = open("output.txt", "w+")
            open_file_in_a_way_to_be_readable(path, file)
            for i in list_IP:
                file.write(i + "\n")
            most = (most_frequent(most_frequent_IP))
            file.write(most)
            file.close()
            frame_num = 1
    except FileNotFoundError:
        print('File not found.')


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


def find_in_file(file, protocol):
    protocol = str(protocol)
    for lines in file:
        inner_list = [elt.strip() for elt in lines.split(' ', maxsplit=1)]
        if inner_list[0] == protocol:
            result = inner_list[1]
            file.close()
            return str(result)
    file.close()
    return "unidentified protocol [" + protocol + "]"


def get_nested(data, protocol):
    E_type = struct.unpack('! H', data[12:14])
    E_type = int(E_type[0])
    if tato_funkcia_zisti_aky_je_to_protokol(data) == "IEEE 802.3 LLC + SNAP\n":
        f = open("E_proto.txt")
        protocol = struct.unpack('! H', data[20:22])
        protocol = int(protocol[0])
    elif E_type >= 1500:
        f = open("E_proto.txt")
    elif tato_funkcia_zisti_aky_je_to_protokol(data) == "IEEE 802.3 LLC\n":
        f = open("802_proto.txt")
        protocol = int(data[15])
        protocol = str(protocol)
    else:
        return ""
    return "Protocol = " + find_in_file(f, protocol)


def get_protocol(protocol, leng, data, n):
    prots = open("protocols.txt")
    protocol = str(protocol)

    for lines in prots:
        inner_list = [elt.strip() for elt in lines.split(' ', maxsplit=1)]
        if inner_list[0] == protocol:
            result = inner_list[1]
            result = str(result)
            prots.close()
            switcher = {
                "ICMP": ICMP(data, leng, n),
                "TCP": TCP(data, leng, n),
                "UDP": TCP(data, leng, n),
            }
            L24 = switcher.get(result, " ")
            if n == 0:
                return str(L4)
            return result + str(L4)
    return ""


def calculate_length(length):
    if length < 60:
        length = 64
    else:
        length += 4
    return length


def nested(number, data, n):
    prot = ""
    if number == "2048":
        prot = IPv4(data[23], int(data[14]), data, n)
    elif number == "2054":
        prot = ARP()
    elif number == "34525":
        prot = IPv6()
    return prot


def unpack(data, i, j, file):
    d = struct.unpack('! H', data[i:j])
    d = int(d[0])
    find_in_file(file, d)


def ARP():
    return "ARP"


def IPv4(proto, leng, data, n):
    leng = (leng & 15) * 4  # dalsie 4 su dlzka
    return get_protocol(proto, leng, data, n)


def IPv6():
    return "IPv6"


def ICMP(data, leng, n):
    if n == 0:
        return "ICMP"
    prots = open("icmp_proto.txt")
    typ = int(data[14+leng])
    typ = str(typ)
    for lines in prots:
        inner_list = [elt.strip() for elt in lines.split(' ', maxsplit=1)]
        if inner_list[0] == typ:
            result = inner_list[1]
            result = str(result)
            prots.close()
            if n == 1:
                return " -> " + result.upper()
            else:
                return result.upper()
    prots.close()
    return ""


'''
    prots = open("icmp_proto.txt")
    protocol = str(protocol)

    for lines in prots:
        inner_list = [elt.strip() for elt in lines.split(' ', maxsplit=1)]
        if inner_list[0] == protocol:
            result = inner_list[1]
            result = str(result)
            prots.close()
    return
'''


def TCP(data, leng, n):
    source = struct.unpack('! H', data[14+leng:16+leng])
    prots = open("protocols.txt")
    source = int(source[0])
    source = str(source)
    dest = struct.unpack('! H', data[16+leng:18+leng])
    dest = int(dest[0])
    dest = str(dest)
    for lines in prots:
        inner_list = [elt.strip() for elt in lines.split(' ', maxsplit=1)]
        if inner_list[0] == source:
            result = inner_list[1]
            result = str(result)
            prots.close()
            if n == 1:
                return " -> " + result.upper() + "\n" + "Source port: " + source + "\n" + "Destination port: " + dest
            else:
                return result
    prots.close()
    protz = open("protocols.txt")
    for line in protz:
        inner_list = [elt.strip() for elt in line.split(' ', maxsplit=1)]
        if inner_list[0] == dest:
            result = inner_list[1]
            result = str(result)
            protz.close()
            if n == 1:
                return " -> " + result.upper() + "\n" + "Source port: " + source + "\n" + "Destination port: " + dest
            else:
                return result
    protz.close()
    return ""


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
    return "\n" + num + "   " + str(counter) + " paketov"


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


def printing(data, src_mac, dest_mac, proto, src_ip, dest_ip, file):
    file.write("Frame " + str(frame_num))
    file.write("\nFrame Length pcap API " + str(len(data)) + "\n")
    leng = calculate_length(len(data))
    file.write("Captured Length " + str(leng) + "\n")
    file.write(tato_funkcia_zisti_aky_je_to_protokol(data))
    file.write("Destination MAC: " + hex_add(dest_mac.hex()) + "\n")
    file.write("Source MAC: " + hex_add(src_mac.hex()) + "\n")
    file.write(get_nested(data, str(proto)) + "\n")
    if get_nested(data, str(proto)) == "Protocol = Internet IP (IPv4)":
        file.write("Source IP: " + get_ip(hex_add(src_ip.hex())) + "\n")
        file.write("Destination IP: " + get_ip(hex_add(dest_ip.hex())) + "\n")
        file.write(nested(str(proto), data, 1) + "\n")
    file.write(hex_all("00" + data.hex()))
    file.write("\n\n\n")


def collecting_data(data, file):
    global frame_num
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    src_addr, dest_addr = struct.unpack('! 4s 4s', data[26:34])
    if filt == '':
        printing(data, src_mac, dest_mac, protocol, src_addr, dest_addr, file)
    elif filt.upper() == nested(str(protocol), data, 0).upper():
        printing(data, src_mac, dest_mac, protocol, src_addr, dest_addr, file)
    frame_num += 1
    if str(protocol) == "2048":
        save_IP(get_ip(hex_add(src_addr.hex())))     # heh


def open_file_in_a_way_to_be_readable(path, output_file):
    file = rdpcap(path)
    i = 1
    for frames in file:
        i += 1
        collecting_data(raw(frames), output_file)
    return


main()
