import socket
import threading
import json

# GunBound Thor's Hammer packet layout:
# Packet Data: 0c 00 eb cb 12 13 30 00 ff ff ff ff
# Index:       00 01 02 03 04 05 06 07 08 09 0a 0b
#
# 00, 01 = Packet size, 00 = LSB, 01 = MSB
# 02, 03 = Packet sequence
# 04, 05 = Packet command
# 06 onwards = Packet parameters

# To package as single binary: pyinstaller --onefile broker.py


# convert a bytes-like input into a hex-string
def bytes_to_hex(input_bytes):
    return "".join("{:02X}".format(b) for b in input_bytes)


# convert an integer into a series of little-endian bytes
# broker is strange where data is sometimes presented in big-endian
def int_to_bytes(input_integer, size, big_endian=False):
    output_bytes = bytearray()
    if big_endian:
        for i in range(size):
            output_bytes.insert(0, input_integer & 0xff)
            input_integer = input_integer >> 8
    else:
        for i in range(size):
            output_bytes.append(input_integer & 0xff)
            input_integer = input_integer >> 8
    return output_bytes


# GunBound packet sequence, generated from sum of packet lengths
# Normally the overall length is stored/incremented per socket, but the broker only uses this once (hence unnecessary)
# Taken from function at 0x40B760 in GunBoundServ2.exe (SHA-1: b8fce1f100ef788d8469ca0797022b62f870b79b)
#
# ECX: packet length
# 0040B799  IMUL CX,CX,43FD ; Multiply packet length with 43FD (int16)
# 0040B79E  ...
# 0040B7A1  ...
# 0040B7A9  ...
# 0040B7AB  ...
# 0040B7B2  ADD ECX,FFFFAC03 ; Inverted sign of FFFFAC03 equivalent would be SUB 53FD (implemented below)
#
# The client checks this output value. For the server to verify the client's packet sequence, subtract 0x613D instead
def get_sequence(sum_packet_length):
    return (((sum_packet_length * 0x43FD) & 0xFFFF) - 0x53FD) & 0xFFFF


class ServerOption:
    # Describes a server to be broadcast by the broker server
    def __init__(self, server_name: str, server_description: str, server_address: str, server_port: int,
                 server_utilization: int, server_capacity: int, server_enabled: bool):
        self.server_name = server_name
        self.server_description = server_description
        self.server_address = server_address
        self.server_port = server_port
        self.server_utilization = server_utilization
        self.server_capacity = server_capacity
        self.server_enabled = server_enabled


class BrokerServer(object):
    server_options = []
    world_session = []

    def __init__(self, host, port, in_options, in_world_session):
        self.host = host
        self.port = port
        self.server_options = in_options
        self.world_session = in_world_session
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        print("Broker TCP Bound")
        print("GunBound Broker - Directory: ")
        for server_option in self.server_options:
            print("Server:", server_option.server_name, "-", server_option.server_description,
                  "on port", server_option.server_port)

    def listen(self):
        self.sock.listen(5)
        print("BS: Listening on", self.host, ":", self.port)
        while True:
            client, address = self.sock.accept()
            client.settimeout(6000)
            threading.Thread(target=self.client_connection, args=(client, address)).start()

    def client_connection(self, client, address):
        print("BS: New connection from", address)
        socket_rx_size = 1024
        # This value should be used during calculation of the sequence bytes
        socket_rx_sum = 0

        while True:
            try:
                data = client.recv(socket_rx_size)
                if data:
                    if len(data) < 6:
                        print("Invalid Packet (length < 6)")
                        print(data)
                    else:
                        # Try parse basic packet information
                        payload_size = (data[1] << 8) | data[0]
                        client_command = (data[5] << 8) | data[4]

                        print("")
                        socket_rx_sum += payload_size

                        # Reply client if the service request is recognized
                        if client_command == 0x1013:
                            print("BS: Authentication Request")
                            login_packet = BrokerServer.generate_packet(-1, 0x1312,
                                                                        int_to_bytes(0x0000, 2, big_endian=True))
                            client.send(login_packet)

                        elif client_command == 0x1100:
                            print("BS: Server Directory Request")
                            directory_packet = bytearray()
                            directory_packet.extend([0x00, 0x00, 0x01])  # unknown
                            directory_packet.append(len(self.server_options))

                            for i in range(len(self.server_options)):
                                # hack: assumes that we only use one world.
                                # For multiple worlds, tag id in the Session class
                                self.server_options[i].server_utilization = len(self.world_session)
                                directory_packet.extend(BrokerServer.get_individual_server(self.server_options[i], i))

                            directory_packet = BrokerServer.generate_packet(0, 0x1102, directory_packet)
                            client.send(directory_packet)

                else:
                    print("BS: Client disconnected")
                    return True
            except:
                client.close()
                print("EXCEPTION: (BS) client forcibly closed without cleanup")
                return False

    @staticmethod
    def generate_packet(sent_packet_length, command, data_bytes):
        packet_expected_length = len(data_bytes) + 6
        packet_sequence = get_sequence(sent_packet_length + packet_expected_length)

        # broker-specific: first packet of connection uses a different sequence
        if sent_packet_length == -1:
            packet_sequence = 0xCBEB

        response = bytearray()
        response.extend(int_to_bytes(packet_expected_length, 2))
        response.extend(int_to_bytes(packet_sequence, 2))
        response.extend(int_to_bytes(command, 2))

        response.extend(data_bytes)
        return response

    @staticmethod
    def get_individual_server(entry: ServerOption, position):
        extended_description = entry.server_description + \
                               "\r\n[" + str(entry.server_utilization) + \
                               "/" + str(entry.server_capacity) + "] players online"
        response = bytearray()
        response.extend([position, 0x00, 0x00])
        response.append(len(entry.server_name))
        response.extend(entry.server_name.encode("ascii"))
        response.append(len(extended_description))
        response.extend(extended_description.encode("ascii"))
        response.extend(map(int, entry.server_address.split('.')))
        response.extend(int_to_bytes(entry.server_port, 2, big_endian=True))
        response.extend(int_to_bytes(entry.server_utilization, 2,  big_endian=True))
        response.extend(int_to_bytes(entry.server_utilization, 2,  big_endian=True))
        response.extend(int_to_bytes(entry.server_capacity, 2,  big_endian=True))
        response.append(int(entry.server_enabled))
        return response


# this remains here for people who would like to run the broker server as a standalone script
def load_json_from_file():
    # List of servers to be broadcast by the broker server
    server_options = []
    with open('directory.json') as directory_data_text:
        directory_data = json.load(directory_data_text)
        for json_row in directory_data["server_options"]:
            server_options.append(ServerOption(json_row["server_name"], json_row["server_description"],
                                               json_row["server_address"], json_row["server_port"],
                                               json_row["server_utilization"], json_row["server_capacity"],
                                               json_row["server_enabled"]))
    return server_options


if __name__ == "__main__":
    options = load_json_from_file()
    BrokerServer("0.0.0.0", 8372, options).listen()
