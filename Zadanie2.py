from scapy.all import *

file_number = 5


def main(path):
    file = open("output.txt", "w+")
    while 1:
        try:
            open_file_in_a_way_to_be_readable(path, file)
            file.close()
            exit()
        except FileNotFoundError:
            print('File not found.')


def hex_add(data):
    hex_addr = ""

    for i in range(0, len(data), 2):
        hex_addr += data[i:i+2]
        hex_addr += " "
    return hex_addr.upper()


def hex_all(data):
    hexa = ""
    temp = 1

    for i in range(2, len(data) + 2, 2):
        hexa += data[i:i+2]
        hexa += " "
        if i == 8*temp*2:
            if i == 16*temp and i % 32 == 0:
                hexa += "\n"
                temp += 1
            else:
                hexa += "  "
                temp += 1
    return hexa.upper()


def get_ip(data):
    ip_addr = ""

    for i in range(0, len(data), 3):
        ip_addr += str(int(data[i:i+2], 16))
        if i < len(data) - 4:
            ip_addr += "."
    return ip_addr


def get_protocol(protocol):

    protocol = str(protocol)
    switcher = {
        "2048": "Internet Protocol version 4 (IPv4)",
        "2054": "Address Resolution Protocol (ARP)",
        "0000": "IEEE 802.3 Lenght Field",
    }
    return switcher.get(protocol, "unidentified_protocol ["+protocol+"]")


def calculate_length(length):
    if length < 60:
        length = 64
    else:
        length += 4
    return length


def printing(data, src_mac, dest_mac, proto, vers, length, src_ip, dest_ip, file):
    file.write("\nFrame Length pcap " + str(len(data)) + "\n")
    leng = calculate_length(len(data))
    file.write("Capture Length " + str(leng) + "\n")
    file.write("Destination MAC: " + hex_add(dest_mac.hex()) + "\n")
    file.write("Source MAC: " + hex_add(src_mac.hex()) + "\n")
    file.write("Protocol = " + get_protocol(proto) + "\n")
    file.write("Protocol number = " + str(proto) + "\n")
    file.write("Version = " + str(vers) + "\n")
    file.write("Header Length = " + str(length) + "\n")
    file.write("Source IP = " + get_ip(hex_add(src_ip.hex())) + "\n")
    file.write("Destination IP = " + get_ip(hex_add(dest_ip.hex())) + "\n")
    file.write("\n")
    file.write(hex_all("00" + data.hex()))
    file.write("\n")
    file.write("\n")


def collecting_data(data, file):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    header = data[14]
    h_version = header >> 4           # prve 4 bity su verzia
    h_length = (header & 15) * 4      # dalsie 4 su dlzka
    # time_to_live, proto, src_addr, dest_addr = struct.unpack('! 8x B B 2x 4s 4s', data[14:34])
    src_addr, dest_addr = struct.unpack('! 4s 4s', data[26:34])

    printing(data, src_mac, dest_mac, protocol, h_version, h_length, src_addr, dest_addr, file)


def get_mac_addr(bytes_addr):
    bytes_str = map(format, bytes_addr)
    return ':'.join(bytes_str).upper()


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
#main(file_path+final_file)
main(r"D:\vzorky_pcap_na_analyzu\trace-2.pcap")
