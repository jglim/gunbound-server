import socket
import threading
import secrets
import random
import cryptography
import datetime
import json

# TODO:
# Tunnel - firewall test pc to force tunnel, figure out whats going on
# Figure out positional data. right now everyone's spawned on the same spot
# closing of rooms, handling people leaving the room
# clean the 518 client to make it "as stock as possible"
# make data persistent - flat-file or peewee
# fix dragon, knight issue

# FIXME:
# update client when player leaves channel to enter a game
# above bug probably causes a rejoin to fail
# more than 6 rooms: pagination
# room is orphaned if host leaves
# key handover announces wrong slot
# when joining a room, primary/secondary bot should be random 0xFF


# convert a bytes-like input into a hex-string
def bytes_to_hex(input_bytes):
    return "".join("{:02X}".format(b) for b in input_bytes)


# convert an integer into a series of little-endian bytes
def int_to_bytes(input_integer, size):
    # LSB on left (little endian)
    output_bytes = bytearray()
    for i in range(size):
        output_bytes.append(input_integer & 0xff)
        input_integer = input_integer >> 8
    return output_bytes


# convert a series of bytes into a little-endian integer given a size
def bytes_to_int(input_bytes, size):
    # parsed as little endian
    if len(input_bytes) < size:
        print("bytes_to_int: requested size is smaller than input bytes")
        return 0
    output_int = 0
    for i in range(size):
        output_int |= input_bytes[i] << (i * 8)
    return output_int


# internally used in resize_bytes
def pad_bytes(input_bytes, desired_size):
    output = bytearray()
    output.extend(input_bytes)
    output.extend(bytearray.fromhex("00" * (desired_size - len(output))))
    return output


# internally used in resize_bytes
def truncate_bytes(input_bytes, desired_size):
    if len(input_bytes) > desired_size:
        return input_bytes[:desired_size]


# extends (pad: 00) or clips a bytes-like input to fit the desired size
def resize_bytes(input_bytes, desired_size):
    if len(input_bytes) > desired_size:
        return input_bytes[:desired_size]
    else:
        return pad_bytes(input_bytes, desired_size)


# goes through as many bytes as possible and creates a string, stopping at the first null terminator
def string_decode(input_bytes):
    result = ""
    for input_byte in input_bytes:
        if input_byte != 0:
            result += chr(input_byte)
        else:
            return result
    return result


# converts a string IP into a bytes representation
def ip_to_bytes(in_ip):
    ip_bytes = bytearray()
    ip_bytes.extend(map(int, in_ip.split('.')))
    return ip_bytes


class FunctionRestrict:
    AVATAR_ENABLED: int = 1 << 4
    EFFECT_FORCE: int = 1 << 13
    EFFECT_TORNADO: int = 1 << 14
    EFFECT_LIGHTNING: int = 1 << 15
    EFFECT_WIND: int = 1 << 16
    EFFECT_THOR: int = 1 << 17
    EFFECT_MOON: int = 1 << 18
    EFFECT_ECLIPSE: int = 1 << 19
    EVENT1_ENABLE: int = 1 << 20
    EVENT2_ENABLE: int = 1 << 21
    EVENT3_ENABLE: int = 1 << 22
    EVENT4_ENABLE: int = 1 << 23

    @staticmethod
    def get_function_value(effect_flags):
        result_function_out: int = 0
        for effect_flag in effect_flags:
            result_function_out |= effect_flag
        return result_function_out


# class Avatar:
#     @staticmethod
#     def get_avatar_by_user(in_username):
#         user_extended_avatar = []
#         if in_username == "saneusername":
#             user_extended_avatar.append(bytes.fromhex("0100 0100"))  # space marine (H)
#             user_extended_avatar.append(bytes.fromhex("0100 0000"))  # space marine (B)
#             user_extended_avatar.append(bytes.fromhex("0100 0200"))  # battle goggles (E)
#             user_extended_avatar.append(bytes.fromhex("0180 0300"))  # blue flag (F)
#             user_extended_avatar.append(bytes.fromhex("8F80 0100"))  # love cupid M (F)
#             user_extended_avatar.append(bytes.fromhex("0380 0300"))  # violet flag (F)
#         if in_username == "amigos":
#             user_extended_avatar.append(bytes.fromhex("A5800100"))
#             user_extended_avatar.append(bytes.fromhex("4B800000"))
#             user_extended_avatar.append(bytes.fromhex("3D800200"))
#             user_extended_avatar.append(bytes.fromhex("3D800300"))
#         return user_extended_avatar


class Room:
    room_id: int = -1
    room_name = ""
    password = ""
    map_id = 0
    game_settings = bytes.fromhex("00 00 00 00")
    occupants_max = 0
    room_state = 0  # waiting: 0, play: 1
    player_sessions = []

    def __init__(self, in_id, in_room_name, in_password, in_map_id, in_game_settings, in_occupants_max):
        self.room_id = in_id
        self.room_name = in_room_name
        self.password = in_password
        self.map_id = in_map_id
        self.game_settings = in_game_settings
        self.occupants_max = in_occupants_max
        self.player_sessions = []

    @staticmethod
    def find_room_position(in_world_room):
        # find a free room id
        for index in range(0xFF):
            index_is_occupied = False
            for room_item in in_world_room:
                if room_item.room_id == index:
                    index_is_occupied = True
                    break
            if not index_is_occupied:
                return index
        print("No room ids available")
        return 0

    @staticmethod
    def find_room_slot(in_room):
        # find a free room id
        for index in range(0x10):
            index_is_occupied = False
            for session_item in in_room.player_sessions:
                if session_item.room_slot == index:
                    index_is_occupied = True
                    break
            if not index_is_occupied:
                return index
        print("No room slots available")
        return 0

    @staticmethod
    def find_room_team(in_room):
        # find a team to insert a new player
        team_a_size = 0
        team_b_size = 0
        for session_item in in_room.player_sessions:
            if session_item.room_team == 0:
                team_a_size += 1
            else:
                team_b_size += 1

        if team_a_size > team_b_size:
            return 1
        else:
            return 0

    @staticmethod
    def find_room_by_id(in_world_room, room_id):
        for room_item in in_world_room:
            if room_item.room_id == room_id:
                return room_item
        return None

    @staticmethod
    def find_room_by_user(in_world_room, in_username):
        for room_item in in_world_room:
            for player in room_item.player_sessions:
                if player.user.username == in_username:
                    return room_item
        return None

    @staticmethod
    def remove_session(in_world_room, in_username):
        for room_item in in_world_room:
            for player_index in range(len(room_item.player_sessions)):
                if room_item.player_sessions[player_index].user.username == in_username:
                    room_item.player_sessions.pop(player_index)
                    # destroy room if last player has quit
                    return True
        return False

    @staticmethod
    def remove_empty_rooms(in_world_room):
        cleanup_still_required = True

        while cleanup_still_required:
            for in_room_index in range(len(in_world_room)):
                if len(in_world_room[in_room_index].player_sessions) == 0:
                    in_world_room.pop(in_room_index)
                    break
            else:
                cleanup_still_required = False


class User:
    username = ""
    password = ""
    guild = ""
    rank_current = 10
    rank_season = 10
    cash: int = 999999
    gold: int = 999999

    # 2 types of avatars - equipped (WORD) and extended (DWORD)
    # extended:
    # first (LSB) and second byte are the shortened avatar code
    # shortened avatar code's LSB is 0 when no avatar is worn
    # second byte's most significant bit determines gender (1=male)
    # third byte describes the slot (body: 0, head: 1, eye: 2, flag: 3)
    # fourth byte (MSB) is unknown, maybe upper byte of slot (3rd byte)
    # equipped:
    # truncate extended avatar from DWORD to WORD. 4x for head, body, eye and flag
    avatar_equipped = bytes.fromhex("00 80 00 80 00 80 00 00")
    avatar_inventory = []  # list of DWORD-sized bytes

    def __init__(self, in_username, in_password, in_guild, in_rank_current, in_rank_season):
        self.username = in_username
        self.password = in_password
        self.guild = in_guild
        # self.gender = in_gender  # gender is not used for now - see avatar bytes
        self.rank_current = in_rank_current
        self.rank_season = in_rank_season
        self.avatar_equipped = bytes.fromhex("00 80 00 80 00 80 00 00")  # default: male
        self.avatar_inventory = []

    @staticmethod
    def get_users():
        user_instances = []
        with open("user_data.json") as user_data_text:
            data_users = json.load(user_data_text)
            for data_user in data_users:
                user_instance: User = User(data_user["username"], data_user["password"], data_user["guild"], data_user["rank_current"], data_user["rank_season"])
                user_instance.cash = data_user["cash"]
                user_instance.gold = data_user["gold"]
                user_instance.avatar_equipped = bytes.fromhex(data_user["avatar_equipped"])
                for user_avatar_inventoryitem in data_user["avatar_inventory"]:
                    user_instance.avatar_inventory.append(bytes.fromhex(user_avatar_inventoryitem))
                # print(user_instance, user_instance.username)
                user_instances.append(user_instance)
        return user_instances

    @staticmethod
    def get_user_by_name(world_user, in_username):
        for user_item in world_user:
            if user_item.username == in_username:
                return user_item
        return None

    def to_json(self):
        return json.dumps(User.user_to_serializable(self))

    @staticmethod
    def user_to_serializable(in_user):
        data_to_serialize = {}
        data_to_serialize["username"] = in_user.username
        data_to_serialize["password"] = in_user.password
        data_to_serialize["guild"] = in_user.guild
        data_to_serialize["rank_current"] = in_user.rank_current
        data_to_serialize["rank_season"] = in_user.rank_season
        data_to_serialize["cash"] = in_user.cash
        data_to_serialize["gold"] = in_user.gold
        data_to_serialize["avatar_equipped"] = bytes_to_hex(in_user.avatar_equipped)
        inventory_to_serialize = []
        for avatar_item in in_user.avatar_inventory:
            inventory_to_serialize.append(bytes_to_hex(avatar_item))

        data_to_serialize["avatar_inventory"] = inventory_to_serialize
        return data_to_serialize

    @staticmethod
    def save_users(in_user_list):
        users_to_serialize = []
        for user_item in in_user_list:
            users_to_serialize.append(User.user_to_serializable(user_item))
        print(json.dumps(users_to_serialize))
        with open("user_data.json", "w") as data_file_handle:
            data_file_handle.write(json.dumps(users_to_serialize))
        print("Save complete")


class Session:
    auth_token = bytearray()
    session_unique = bytearray()
    user: User = None
    channel_position = -1
    client_version = 0
    socket_tx_sum = 0
    client = None
    address = None

    # room stuff
    is_room_key = False
    room_slot = -1
    room_team = 0
    room_tank_primary = 0xFF
    room_tank_secondary = 0xFF

    def __init__(self, client_socket, in_address):
        self.auth_token = secrets.token_bytes(4)
        self.session_unique = secrets.token_bytes(4)
        self.client = client_socket
        self.address = in_address
        self.room_slot = -1
        self.is_room_key = False
        print("New session initialized")
        if self.client is not None:
            print("Session IP:", self.address[0], "Port:", self.address[1])

    def decrypt(self, encrypted_bytes, client_command):
        return cryptography.gunbound_dynamic_decrypt(
            encrypted_bytes, self.user.username, self.user.password, self.auth_token, client_command)

    def encrypt(self, plain_bytes, client_command):
        # align to encryption block size
        mutable_plain_bytes = bytearray()
        mutable_plain_bytes.extend(plain_bytes)
        for unused_pad_byte in range(12 - (len(plain_bytes) % 12)):
            mutable_plain_bytes.append(0x00)

        return cryptography.gunbound_dynamic_encrypt(
            mutable_plain_bytes, self.user.username, self.user.password, self.auth_token, client_command)

    def send(self, command, bytes_to_send, rtc=None):
        payload = None
        if rtc is None:
            payload = Session.generate_packet(self.socket_tx_sum, command, bytes_to_send)
        else:
            mutable_bytes_to_send = bytearray()
            mutable_bytes_to_send.extend(int_to_bytes(rtc, 2))
            mutable_bytes_to_send.extend(bytes_to_send)
            payload = Session.generate_packet(self.socket_tx_sum, command, mutable_bytes_to_send)

        if self.client is None:
            print("SEND requested on bot, ignoring")
            return
        self.client.send(payload)
        print("SEND>> ", hex(command), bytes_to_hex(payload))
        self.socket_tx_sum += len(payload)

    def send_encrypted(self, command, bytes_to_send, rtc=None):
        self.send(command, self.encrypt(bytes_to_send, command), rtc=rtc)

    # Generate a valid packet (header with length, sequence, command) with a given payload
    @staticmethod
    def generate_packet(sent_packet_length, command, data_bytes):
        packet_expected_length = len(data_bytes) + 6
        packet_sequence = Session.get_sequence(sent_packet_length + packet_expected_length)

        response = bytearray()
        response.extend(int_to_bytes(packet_expected_length, 2))
        response.extend(int_to_bytes(packet_sequence, 2))
        response.extend(int_to_bytes(command, 2))

        response.extend(data_bytes)
        return response

    # Gunbound packet sequence, generated from sum of packet lengths
    @staticmethod
    def get_sequence(sum_packet_length):
        return (((sum_packet_length * 0x43FD) & 0xFFFF) - 0x53FD) & 0xFFFF

    @staticmethod
    def get_session(in_world_session, in_username):
        for session_item in in_world_session:
            if session_item.user.username == in_username:
                return session_item
        return None

    @staticmethod
    def remove_session(in_world_session, in_username):
        for index in range(len(in_world_session)):
            if in_world_session[index].user.username == in_username:
                in_world_session.pop(index)

    @staticmethod
    def find_channel_position(in_world_session):
        # find a new channel position
        for index in range(0xFF):
            index_is_occupied = False
            for session_item in in_world_session:
                if session_item.channel_position == index:
                    index_is_occupied = True
                    break
            if not index_is_occupied:
                return index
        print("No channel slots available")
        return 0

    @staticmethod
    def find_highest_channel_position(in_world_session):
        highest_position = 0
        for session_item in in_world_session:
            if session_item.channel_position > highest_position:
                highest_position = session_item.channel_position
        return highest_position

    @staticmethod
    def sendall(in_world_session, in_command, in_data):
        for session_item in in_world_session:
            session_item.send(in_command, in_data)


class GameUDPServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        print("UDP Bound")

    def listen(self):
        while True:
            udp_payload, udp_client_address = self.sock.recvfrom(1024)
            print("UDP: Echoing data back to " + str(udp_client_address), bytes_to_hex(udp_payload))
            self.sock.sendto(udp_payload, udp_client_address)
            print("UDP Done")


class CommandProcessor:
    world_session = []
    world_room = []

    def __init__(self, in_world_session, in_world_room):
        self.world_session = in_world_session
        self.world_room = in_world_room

    def join_channel(self, data, client_session, motd_channel):
        # check where the player was previously from - if from game/room, clean up
        if client_session.room_slot != -1:
            print("Room cleanup requested")
            previous_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
            new_keybearer_session: Session = None
            for session_item in previous_room.player_sessions:
                if session_item.user.username != client_session.user.username:
                    new_keybearer_session = session_item
                    break

            migration_packet = bytearray()
            if new_keybearer_session is not None:
                # if host leaves the room, the packet is never built or sent
                # team A/B data seems to get messy after this
                migration_packet.append(new_keybearer_session.room_slot)
                migration_packet.append(len(previous_room.room_name))
                migration_packet.extend(previous_room.room_name.encode("ascii"))
                migration_packet.append(previous_room.map_id)
                migration_packet.extend(previous_room.game_settings)
                migration_packet.extend(bytes.fromhex("FF FF FF FF FF FF FF FF"))  # unknown
                migration_packet.append(previous_room.occupants_max)  # guessed

            for session_item in previous_room.player_sessions:
                if session_item.user.username != client_session.user.username:
                    print("Sending migration packet")
                    session_item.send(0x3020, int_to_bytes(client_session.room_slot, 2))
                    # assuming 3040 is a broadcast since everyone needs to know of key migration
                    session_item.send(0x3400, migration_packet)

            if Room.remove_session(self.world_room, client_session.user.username):
                Room.remove_empty_rooms(self.world_room)
                print("Room cleanup completed successfully")
            else:
                print("Room cleanup requested but failed")

            client_session.room_slot = -1
            client_session.is_room_key = False

        # last 2 bytes indicate desired channel LSB MSB end
        desired_channel = bytes_to_int(data[-2:], 2)
        if desired_channel == 0xFFFF:
            # fresh login requesting for a free channel. In this case we will default to channel 1
            print("Fresh login, routing to channel 1", hex(desired_channel))
            desired_channel = 0
        extended_channel_motd = motd_channel + "\r\nRequesting SVC_CHANNEL_JOIN " + \
                                str(desired_channel) + " at " + \
                                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\r\n" + \
                                "Client Version: " + str(client_session.client_version)

        # find all ACTIVE channel participants (!= sessions). room_slot must be -1
        active_channel_users = []
        for session_item in self.world_session:
            if session_item.room_slot == -1:
                active_channel_users.append(session_item)

        channel_join_packet_new = bytearray()
        channel_join_packet_new.extend(bytes.fromhex("00 00"))
        channel_join_packet_new.extend(int_to_bytes(desired_channel, 2))
        channel_join_packet_new.append(Session.find_highest_channel_position(active_channel_users))
        channel_join_packet_new.append(len(active_channel_users))

        # channel participants are sessions with a room slot of -1 (aka not in a room)
        for session_item in active_channel_users:
            channel_player = bytearray()
            channel_player.append(session_item.channel_position)
            channel_player.extend(resize_bytes(session_item.user.username.encode("ascii"), 12))
            channel_player.extend(session_item.user.avatar_equipped)  # gender determined from avatar?
            channel_player.extend(resize_bytes(session_item.user.guild.encode("ascii"), 8))
            channel_player.extend(int_to_bytes(session_item.user.rank_current, 2))
            channel_player.extend(int_to_bytes(session_item.user.rank_season, 2))
            channel_join_packet_new.extend(channel_player)

        channel_join_packet_new.extend(extended_channel_motd.encode("ascii"))

        client_session.send(0x2001, channel_join_packet_new)

        # channel data DOES affect room state - whether tunnel will be used bc user cannot be found

        # advertise channel join to existing clients
        join_notification = bytearray()
        join_notification.append(client_session.channel_position)
        join_notification.extend(resize_bytes(client_session.user.username.encode("ascii"), 0xC))
        join_notification.extend(client_session.user.avatar_equipped)  # avatar
        join_notification.extend(resize_bytes(client_session.user.guild.encode("ascii"), 8))
        join_notification.extend(int_to_bytes(client_session.user.rank_current, 2))  # current rank
        join_notification.extend(int_to_bytes(client_session.user.rank_season, 2))  # season rank

        for session_item in active_channel_users:
            if session_item.user.username != client_session.user.username:
                session_item.send(0x200E, join_notification)

    def cash_update(self, client_session):
        # 1032: cash update
        # unknown dword in the middle, all zeroes
        # some sort of dword at the end of 0x1032
        # could be "crap" padding bytes to fit encryption's 12-byte block
        client_session.send_encrypted(0x1032, int_to_bytes(client_session.user.cash, 4))

    def print_to_client(self, client_session, in_message):
        client_session.send(0x5101, in_message.encode("ascii"))

    def room_update(self, client_session):
        client_session.send(0x3105, bytes.fromhex(""), rtc=0)

    def start_game_serv2(self, data, client_session):
        unknown_data = data[6:]  # A2 89 CB 01 / seems different every time, longer for multiplayer
        selected_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
        selected_room.room_state = 1  # waiting -> playing
        start_data = bytearray()
        start_data.append(selected_room.map_id)  # map

        turn_order = list(range(len(selected_room.player_sessions)))
        random.shuffle(turn_order)

        # below size of WORD seems excessive, value is guessed
        start_data.extend(int_to_bytes(len(selected_room.player_sessions), 2))
        for session_item in selected_room.player_sessions:
            # random bot selection
            if session_item.room_tank_primary == 0xFF:
                session_item.room_tank_primary = random.randint(0, 13)
            if session_item.room_tank_secondary == 0xFF:
                session_item.room_tank_secondary = random.randint(0, 13)

            start_data.append(session_item.room_slot)
            start_data.extend(resize_bytes(session_item.user.username.encode("ascii"), 0xC))
            start_data.append(session_item.room_team)  # guessed
            start_data.append(session_item.room_tank_primary)
            start_data.append(session_item.room_tank_secondary)
            # unknown positional data. looks nothing like the *_stage_pos.txt content
            start_data.extend(bytes.fromhex("36 02 00 00"))
            start_data.extend(int_to_bytes(turn_order[session_item.room_slot], 2))  # turn position. thanks @phnx
        # unknown: would guess FuncRestrict but it's short of a byte
        # default FFFF, setting 0000 activates event
        start_data.extend(bytes.fromhex("00 FF"))
        start_data.extend(unknown_data)  # echo the stuff sent by game host

        for session_item in selected_room.player_sessions:
            session_item.send_encrypted(0x3432, start_data)

    def start_game_gis(self, data, client_session):
        # GIS experiment
        unknown_data = data[6:]  # see start_game_serv2
        selected_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
        selected_room.room_state = 1  # waiting -> playing
        start_data = bytearray()
        # start_data.extend(selected_room.game_settings)
        # start_data.extend(bytes.fromhex("00 00 00 00"))

        start_data.extend(bytes.fromhex("00 00 00 00"))
        # start_data.extend(unknown_data)  # echo the stuff sent by game host

        start_data.append(selected_room.map_id)  # map
        # below size of WORD seems excessive, value is guessed
        start_data.extend(int_to_bytes(len(selected_room.player_sessions), 2))
        for session_item in selected_room.player_sessions:
            # random bot selection
            if session_item.room_tank_primary == 0xFF:
                session_item.room_tank_primary = random.randint(0, 13)
            if session_item.room_tank_secondary == 0xFF:
                session_item.room_tank_secondary = random.randint(0, 13)

            start_data.append(session_item.room_slot)
            start_data.extend(resize_bytes(session_item.user.username.encode("ascii"), 0xC))
            start_data.append(session_item.room_team)  # guessed
            start_data.append(session_item.room_tank_primary)  # comsik.txt: looks correct
            start_data.append(session_item.room_tank_secondary)
            # unknown positional data. looks nothing like the *_stage_pos.txt content
            # map position's theory:
            # grab the 8 possible slots from *_stage_pos.txt
            # if player count is below (?), enter "small mode", selecting denser slot positions
            # assign player's slot position (prefer alternating)
            # set the position below
            # right now i have no idea how this value works, so everyone uses the same value
            # as a consequence, everyone spawns on the same spot
            start_data.extend(bytes.fromhex("36 02 00 00"))
            start_data.append(session_item.room_slot)  # hack - this value needs incrementing
            start_data.append(0)  # hack
        # current event
        # default FFFF, setting 0000 activates event
        start_data.extend(bytes.fromhex("12 34"))
        # start_data.extend(unknown_data)  # echo the stuff sent by game host

        for session_item in selected_room.player_sessions:
            session_item.send_encrypted(0x3432, start_data)
        print("GIS: sending structured data")

    def start_game_anyhowly(self, data, client_session):
        # GIS experiments
        # this gets into game: cozy tower, bottom left (no foothold), solo, 1 other opponent
        # 0x3432,
        # 01010101 6A000101 01010101 01010101 01010101 01010101 01010101 01010101 01010101
        # position 4 (0-indexed): map
        # position 5, non-zero value
        # this gets into game: nirvana left side, 3 players
        # position 7: first player channel index
        # pos 24, 26 set first player x, y
        # 21, 22 = mobile 1, 2 (0B 0A)
        gamesession_data = bytearray()
        gamesession_data.extend(bytearray.fromhex("44 44 44 44 04 01 00 00 44 44 44 44"))
        gamesession_data.extend(bytearray.fromhex("44 44 11 22 33 44 55 66 77 0B 0A 00"))
        gamesession_data.extend(bytearray.fromhex("02 ff 02 55 55 55 55 55 55 55 55 55"))
        print("GIS: sending fuzzed data")
        client_session.send_encrypted(0x3432, gamesession_data)



class GameServer(object):
    host = None
    port = 0
    motd_channel = "$Channel MOTD"
    motd_room = "$Room MOTD"
    gs_funcrestrict = 0xFFFFF
    world_session = []
    world_room = []
    world_user = []
    command_processor: CommandProcessor = None

    def __init__(self, host, port, in_world_session, in_world_room, in_world_user):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

        self.world_session = in_world_session
        self.world_room = in_world_room
        self.world_user = in_world_user
        print("GS: TCP Bound")

        udp_server = GameUDPServer(host, port)
        threading.Thread(target=udp_server.listen).start()

        self.command_processor = CommandProcessor(self.world_session, self.world_room)
        self.insert_test_data()

    def listen(self):
        self.sock.listen(5)
        print("GS: Listening on", self.host, self.port)
        while True:
            client, address = self.sock.accept()
            client.settimeout(6000)
            threading.Thread(target=self.client_connection, args=(client, address)).start()

    def insert_test_data(self):
        # create lobby and channel test users
        virtual_users = ["us", "jg", "admin"]
        room_index = 0
        for virtual_user in virtual_users:
            virtual_session = Session(None, None)
            virtual_session.user = User.get_user_by_name(self.world_user, virtual_user)
            virtual_session.user.guild = "virtual"
            virtual_session.channel_position = Session.find_channel_position(self.world_session)
            self.world_session.append(virtual_session)
            test_room = Room(room_index, virtual_session.user.username + " virtual", "", 0, bytes.fromhex("B2620C00"),
                             2)
            test_room.player_sessions.append(virtual_session)
            self.world_room.append(test_room)
            room_index += 1

    def client_connection(self, client, address):
        print("GS: New connection from", address)
        socket_rx_size = 1024
        client_session = Session(client, address)
        socket_rx_sum = 0

        while True:
            try:
                data = client.recv(socket_rx_size)
                if data:
                    if len(data) < 6:
                        print("RECV BROKEN PACKET>>")
                        print(bytes_to_hex(data))
                    else:
                        # Try parse basic packet information
                        payload_size = bytes_to_int(data[0: 2], 2)
                        # sequence = bytes_to_int(data[2:4], 2)
                        client_command = bytes_to_int(data[4:6], 2)

                        print("")
                        print("RECV>> ", hex(client_command), bytes_to_hex(data[6:]))

                        socket_rx_sum += payload_size

                        # Reply client if the service request is recognized
                        if client_command == 0x1000:
                            # uncomment below for debug token override - INSECURE
                            # client_session.auth_token = bytes.fromhex("00 98 6B C4")
                            print("Generated token:", bytes_to_hex(client_session.auth_token))
                            client_session.send(0x1001, client_session.auth_token)

                        elif client_command == 0x0000:
                            print("RECV> KEEPALIVE")

                        elif client_command == 0x1010:
                            print("RECV> SVC_LOGIN/ADMIN")

                            username_bytes = cryptography.gunbound_static_decrypt(data[6:6 + 0x10])
                            queried_user = User.get_user_by_name(self.world_user, string_decode(username_bytes))

                            if queried_user is None:
                                # User not found, send disconnection packet
                                print("Queried user could not be found, disconnecting socket")
                                client_session.send(0x1012, bytes.fromhex("10 00"))
                            else:
                                # future: check user if already logged in, *across worlds*
                                client_session.user = queried_user
                                dynamic_payload = client_session.decrypt(data[6 + 0x20:], client_command)
                                received_password = string_decode(dynamic_payload[0:0xC])
                                print("Username:", client_session.user.username, "RX Password:", received_password,
                                      "DB Password:", client_session.user.password)

                                if received_password != client_session.user.password:
                                    # reject client with incorrect password notice
                                    client_session.send(0x1012, bytes.fromhex("11 00"))
                                else:
                                    client_session.client_version = dynamic_payload[0x14] | (dynamic_payload[0x15] << 8)
                                    print("Client version", client_session.client_version)
                                    client_session.channel_position = Session.find_channel_position(self.world_session)
                                    # client_session.channel_position = 0x0a
                                    self.world_session.append(client_session)

                                    login_packet = bytearray()
                                    login_packet.extend(bytearray.fromhex("00 00"))  # maybe gender?
                                    login_packet.extend(client_session.session_unique)  # "seems unused
                                    login_packet.extend(resize_bytes(client_session.user.username.encode("ascii"), 0xC))
                                    login_packet.extend(client_session.user.avatar_equipped)  # currently worn avatar
                                    login_packet.extend(resize_bytes(client_session.user.guild.encode("ascii"), 8))
                                    login_packet.extend(int_to_bytes(client_session.user.rank_current, 2))
                                    login_packet.extend(int_to_bytes(client_session.user.rank_season, 2))
                                    login_packet.extend(int_to_bytes(3333, 2))  # guild member count
                                    login_packet.extend(int_to_bytes(1337, 2))  # rank position, current
                                    login_packet.extend(int_to_bytes(0, 2))  # ?
                                    login_packet.extend(int_to_bytes(1337, 2))  # rank position, season
                                    login_packet.extend(int_to_bytes(0, 2))  # ?
                                    login_packet.extend(int_to_bytes(3332, 2))  # individual's guild rank
                                    # most likely shot history, vs mobile etc.
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 0000"))

                                    login_packet.extend(int_to_bytes(888888, 4))  # gp, current
                                    login_packet.extend(int_to_bytes(888888, 4))  # gp, season
                                    login_packet.extend(int_to_bytes(client_session.user.gold, 4))  # gold
                                    # unknown
                                    login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                    login_packet.append(0)  # still unknown
                                    login_packet.extend(int_to_bytes(self.gs_funcrestrict, 4))  # weather, event etc

                                    if client_session.client_version == 313 or client_session.client_version == 376:
                                        # GIS protocol - throwing in cash state to appease client
                                        # this is an odd packet combining both encrypted and plain data
                                        login_packet.extend(client_session.encrypt(
                                            int_to_bytes(client_session.user.cash, 4), 0x1012))

                                    client_session.send(0x1012, login_packet)

                                    self.command_processor.cash_update(client_session)

                                if client_session.client_version == 313 or client_session.client_version == 376:
                                    # force GIS to change state; reply from channel join does that
                                    self.command_processor.join_channel(data, client_session, self.motd_channel)

                        elif client_command == 0x1020:
                            print("RECV> SVC_USER_ID")
                            payload_data = client_session.decrypt(data[6:], 0x1020)
                            requested_username = string_decode(payload_data[0:0xC])
                            found_id = User.get_user_by_name(self.world_user, requested_username)
                            print("Querying for", requested_username)
                            if found_id is None:
                                print("No user found:", requested_username)
                            else:
                                print("Found id:", found_id.username)
                            # if an id is not found, everything below should be automatically 0
                            # we don't distinguish between login/game id, so echo the request back
                            # 1020 is unusual as it requires a user to be authenticated before use (for crypto)
                            id_crypted_response = bytearray()
                            id_crypted_response.extend(resize_bytes(found_id.username.encode("ascii"), 0xC))
                            id_crypted_response.extend(resize_bytes(found_id.username.encode("ascii"), 0xC))
                            # guild (8 bytes)
                            id_crypted_response.extend(resize_bytes(found_id.guild.encode("ascii"), 8))
                            # current rank (2 bytes), season rank (2 bytes)
                            id_crypted_response.extend(int_to_bytes(found_id.rank_current, 2))
                            id_crypted_response.extend(int_to_bytes(found_id.rank_season, 2))
                            client_session.send_encrypted(0x1021, id_crypted_response, rtc=0)

                        elif client_command == 0x2000:
                            print("RECV> SVC_CHANNEL_JOIN")
                            self.command_processor.join_channel(data, client_session, self.motd_channel)

                        elif client_command == 0x2100:
                            print("RECV> SVC_ROOM_SORTED_LIST")
                            # first byte: room filter type, 1 = all, 2 = waiting
                            # direct room join is technically under filter: ALL (longer payload)
                            room_filter_mode = data[6]
                            if room_filter_mode == 1:
                                print("Filter: ALL")
                            elif room_filter_mode == 2:
                                print("Filter: WAITING")
                            else:
                                print("Filter: UNKNOWN")

                            # FIXME: room directory pagination is done on server
                            # where is the "next/previous page is available" indicator?
                            # client does strange things if more than 6 rooms are sent
                            room_reply = bytearray()
                            room_reply.extend(int_to_bytes(len(self.world_room), 2))
                            # room_reply.append(len(self.world_room))
                            # room_reply.append(0xFF)  # was hoping that this is the indicator for multiple pages..

                            for room_item in self.world_room:
                                room_entry = bytearray()
                                room_entry.extend(int_to_bytes(room_item.room_id, 2))  # 0-indexed room number, as WORD
                                room_entry.append(len(room_item.room_name))
                                room_entry.extend(room_item.room_name.encode("ascii"))
                                room_entry.append(room_item.map_id)  # map: 0 = random, 1 = miramo ..
                                room_entry.extend(room_item.game_settings)  # example bytes: B2620C00
                                room_entry.append(len(room_item.player_sessions))  # occupant count
                                room_entry.append(room_item.occupants_max)  # max occupants
                                room_entry.append(room_item.room_state)  # play state or ready (play = 1, waiting = 0)
                                if len(room_item.password) > 0:
                                    room_entry.append(1)  # room locked: 1 = password required
                                else:
                                    room_entry.append(0)  # room locked: 0 = default open
                                room_reply.extend(room_entry)

                            client_session.send(0x2103, room_reply, rtc=0)

                        elif client_command == 0x2104:
                            print("RECV> SVC_ROOM_DETAIL")
                            requested_room_id = bytes_to_int(data[6:], 2)
                            requested_room = Room
                            for room_item in self.world_room:
                                if room_item.room_id == requested_room_id:
                                    requested_room = room_item
                                    print("Room found")
                                    break
                            response = bytearray()
                            # see command 0x2100 - same stuff with user details appended
                            response.append(len(requested_room.room_name))
                            response.extend(requested_room.room_name.encode("ascii"))
                            response.append(requested_room.map_id)  # map: 0 = random, 1 = miramo ..
                            response.extend(requested_room.game_settings)
                            response.append(len(requested_room.player_sessions))  # occupant count
                            response.append(requested_room.occupants_max)  # max occupants
                            response.append(requested_room.room_state)  # play state
                            if len(requested_room.password) > 0:
                                response.append(1)  # room locked: 1 = password required
                            else:
                                response.append(0)  # room locked: 0 = default open

                            for room_player in requested_room.player_sessions:
                                response.extend(resize_bytes(room_player.user.username.encode("ascii"), 0xC))
                                response.extend(room_player.user.avatar_equipped)  # currently worn avatar
                                response.extend(resize_bytes(room_player.user.guild.encode("ascii"), 8))
                                response.extend(int_to_bytes(room_player.user.rank_current, 2))
                                response.extend(int_to_bytes(room_player.user.rank_season, 2))

                            # decent chunk copied from 0x2100
                            client_session.send(0x2105, response, rtc=0)

                        elif client_command == 0x2110:
                            print("RECV> SVC_ROOM_JOIN")
                            # first 2 bytes are requested room number, subsequent: join password
                            requested_room_id = bytes_to_int(data[6:8], 2)
                            requested_room_password = string_decode(data[8:])
                            # future: check if room id actually exists, and verify password
                            requested_room: Room = Room.find_room_by_id(self.world_room, requested_room_id)

                            if requested_room is None:
                                print("Requested an invalid room. things are going to break")
                            else:
                                client_session.room_team = Room.find_room_team(requested_room)
                                client_session.room_slot = Room.find_room_slot(requested_room)
                                client_session.room_tank_primary = 0xFF
                                client_session.room_tank_secondary = 0xFF
                                requested_room.player_sessions.append(client_session)

                            client_ip = ip_to_bytes(client_session.address[0])
                            client_port = bytes.fromhex("20 AB")  # 8363 seems to be hardcoded
                            print(client_session.user.username, "-", requested_room_id, requested_room_password)

                            # decent chunk copied from 0x2100
                            # 20AB = port 8363, client listens there for UDP

                            # respond to the client first
                            # the start of the client_join_request are room-specific details
                            # how does the client know who the host is?
                            client_session.send(0x21F5, bytes.fromhex("03"), rtc=0)  # unknown - why 3?
                            client_join_request = bytearray()
                            client_join_request.extend(int_to_bytes(0, 2))  # probably RTC but not sure
                            client_join_request.extend(int_to_bytes(0x0100, 2))  # unknown
                            client_join_request.extend(int_to_bytes(requested_room.room_id, 2))  # probably room id
                            client_join_request.append(len(requested_room.room_name))
                            client_join_request.extend(requested_room.room_name.encode("ascii"))
                            client_join_request.append(requested_room.map_id)
                            client_join_request.extend(requested_room.game_settings)
                            client_join_request.extend(bytes.fromhex("FF FF FF FF FF FF FF FF"))  # 4x WORDs?
                            # a bit unusual that occupants_max comes before number of players, normally swapped
                            # unless everything else is wrong..
                            client_join_request.append(requested_room.occupants_max)
                            client_join_request.append(len(requested_room.player_sessions))

                            for session_item in requested_room.player_sessions:
                                session_ip = ip_to_bytes(session_item.address[0])
                                client_join_request.append(session_item.room_slot)
                                client_join_request.extend(resize_bytes(session_item.user.username.encode("ascii"), 0xC))
                                client_join_request.extend(session_ip)
                                client_join_request.extend(client_port)
                                client_join_request.extend(session_ip)
                                client_join_request.extend(client_port)
                                client_join_request.append(session_item.room_tank_primary)  # primary tank
                                client_join_request.append(session_item.room_tank_secondary)  # secondary tank
                                client_join_request.append(session_item.room_team)  # team side (0 = A, 1 = B)
                                client_join_request.append(0x01)  # unknown, stays at 1
                                client_join_request.extend(session_item.user.avatar_equipped)  # currently worn avatar
                                client_join_request.extend(resize_bytes(session_item.user.guild.encode("ascii"), 8))
                                client_join_request.extend(int_to_bytes(session_item.user.rank_current, 2))
                                client_join_request.extend(int_to_bytes(session_item.user.rank_season, 2))

                            client_join_request.extend(self.motd_room.encode("ascii"))
                            client_session.send(0x2111, client_join_request)

                            # notify room host of new join (3010)
                            for session_item in requested_room.player_sessions:
                                if session_item.is_room_key:
                                    print("Sending join request to room host", session_item.user.username)
                                    join_request = bytearray()
                                    join_request.append(client_session.room_slot)
                                    join_request.extend(resize_bytes(client_session.user.username.encode("ascii"), 0xC))
                                    join_request.extend(client_ip)
                                    join_request.extend(client_port)
                                    join_request.extend(client_ip)
                                    join_request.extend(client_port)
                                    join_request.append(client_session.room_tank_primary)  # primary tank
                                    join_request.append(client_session.room_tank_secondary)  # secondary tank
                                    join_request.append(client_session.room_team)  # team side
                                    join_request.extend(client_session.user.avatar_equipped)  # currently worn avatar
                                    join_request.extend(resize_bytes(client_session.user.guild.encode("ascii"), 8))
                                    join_request.extend(int_to_bytes(client_session.user.rank_current, 2))
                                    join_request.extend(int_to_bytes(client_session.user.rank_season, 2))
                                    session_item.send(0x3010, join_request)

                        elif client_command == 0x2010:
                            print("RECV> SVC_CHANNEL_CHAT")
                            dynamic_payload = client_session.decrypt(data[6:], client_command)
                            chat_message = string_decode(dynamic_payload[1:dynamic_payload[0] + 1])
                            print("Channel Chat from", client_session.user.username, ":", chat_message)

                            padded_username = resize_bytes(client_session.user.username.encode("ascii"), 0xC)
                            chat_broadcast_packet = bytearray()
                            chat_broadcast_packet.append(client_session.channel_position)  # user's channel position
                            chat_broadcast_packet.extend(padded_username)
                            chat_broadcast_packet.append(len(chat_message))
                            chat_broadcast_packet.extend(chat_message.encode("ascii"))

                            # broadcast to all open sockets
                            for session_item in self.world_session:
                                session_item.send_encrypted(0x201F, chat_broadcast_packet)

                        elif client_command == 0x2120:
                            print("RECV> SVC_ROOM_CREATE")
                            received_data = data[6:]
                            room_title = string_decode(received_data[1:received_data[0] + 1])
                            # [0:3] game configuration - see 3101, [4:7] pass, [8] room capacity
                            room_other_data = received_data[received_data[0] + 1:]
                            room_playmode = bytes_to_int(room_other_data[2:4], 2)
                            room_playmode_string = "UNKNOWN"
                            if room_playmode == 0:
                                room_playmode_string = "SOLO"
                            elif room_playmode == 0x44:
                                room_playmode_string = "SCORE"
                            elif room_playmode == 0x08:
                                room_playmode_string = "TAG"
                            elif room_playmode == 0x0C:
                                room_playmode_string = "JEWEL"
                            room_password = string_decode(room_other_data[4:8])
                            room_capacity = room_other_data[8]
                            created_room = Room(Room.find_room_position(self.world_room), room_title, room_password, 0,
                                                room_other_data[0:4], room_capacity)
                            client_session.room_slot = 0  # host room slot
                            client_session.is_room_key = True  # indicates host
                            created_room.player_sessions.append(client_session)
                            self.world_room.append(created_room)
                            print("Creating room", room_title, "with password", room_password,
                                  "playing", room_playmode_string, "for", room_capacity, "players.")

                            room_join_reply = bytearray()
                            room_join_reply.extend(bytes.fromhex("00 00 00"))  # unknown
                            room_join_reply.extend(int_to_bytes(created_room.room_id, 2))
                            room_join_reply.extend(self.motd_room.encode("ascii"))
                            client_session.send(0x2121, room_join_reply)

                        elif client_command == 0x3102:
                            print("RECV> SVC_ROOM_CHANGE_USEITEM")
                            prop_state_data = data[6:]
                            prop_state = bytes_to_int(prop_state_data[0:2], 2)
                            print("Room use item changed:", hex(prop_state), bin(prop_state))
                            self.command_processor.room_update(client_session)

                        elif client_command == 0x3100:
                            print("RECV> SVC_ROOM_CHANGE_STAGE")
                            new_map_id = data[6]  # map 0 = random
                            selected_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            if selected_room is not None:
                                selected_room.map_id = new_map_id
                                print("RoomID:", selected_room.room_id, "map set to", new_map_id)
                            else:
                                print("Selected room is None - ignoring")
                            self.command_processor.room_update(client_session)

                        elif client_command == 0x3101:
                            print("RECV> SVC_ROOM_CHANGE_OPTION")
                            map_properties = data[6:]
                            # game config is stored in a bitwise manner, but the details don't matter on the server
                            selected_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            if selected_room is not None:
                                selected_room.game_settings = map_properties
                            self.command_processor.room_update(client_session)

                        elif client_command == 0x3104:
                            print("RECV> SET_ROOM_TITLE")
                            new_title_raw = data[6:]
                            new_title_string = string_decode(new_title_raw)
                            print("SET_ROOM_TITLE", new_title_string)
                            selected_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            if selected_room is not None:
                                selected_room.room_name = new_title_string
                            self.command_processor.room_update(client_session)

                        elif client_command == 0x3103:
                            print("RECV> SVC_ROOM_CHANGE_MAXMEN")
                            room_capacity = data[6]  # map 0 = random
                            selected_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            if selected_room is not None:
                                selected_room.occupants_max = room_capacity
                                print(selected_room.room_id, "new room capacity:", room_capacity)
                            self.command_processor.room_update(client_session)

                        elif client_command == 0x3210:
                            print("RECV> SVC_ROOM_SELECT_TEAM")
                            new_team_position = data[6]
                            print("Changing team to", new_team_position)
                            client_session.room_team = new_team_position
                            # probably "RTC" command in IDA
                            client_session.send(0x3211, bytes.fromhex(""), rtc=0)

                        elif client_command == 0x3200:
                            print("RECV> SVC_ROOM_SELECT_TANK")
                            mobile_string = {0: "Armor",
                                             1: "Mage",
                                             2: "Nak",
                                             3: "Trico",
                                             4: "Bigfoot",
                                             5: "Boomer",
                                             6: "Raon",
                                             7: "Lightning",
                                             8: "J.D.",
                                             9: "A.Sate",
                                             10: "Ice",
                                             11: "Turtle",
                                             12: "Grub",
                                             13: "Aduka",
                                             14: "Dragon",  # technically 14 (from GS), other sources say 125
                                             15: "Knight",  # technically 15, other sources say 209
                                             255: "Random"}

                            tank_primary = data[6]
                            tank_secondary = data[7]
                            client_session.room_tank_primary = tank_primary
                            client_session.room_tank_secondary = tank_secondary
                            print(client_session.user.username, "selected", tank_primary, tank_secondary)
                            client_session.send(0x3201, bytes.fromhex(""), rtc=0)

                        elif client_command == 0x3230:
                            print("RECV> SVC_ROOM_USER_READY")
                            ready_state = data[6]
                            print("SVC_ROOM_USER_READY", ready_state)
                            # technically the server should know about this too but we aren't going to check yet
                            client_session.send(0x3231, bytes.fromhex(""), rtc=0)

                        elif client_command == 0x3232:
                            print("RECV> SVC_ROOM_RETURN_RESULT")
                            client_room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            if client_room is not None:
                                client_room.room_state = 0  # switch room state back to "waiting"
                            client_session.send(0x3233, bytes.fromhex(""), rtc=0)

                        elif client_command == 0x3430:
                            print("RECV> SVC_START_GAME")
                            if client_session.client_version == 314:  # actually 313, but swapped below when debugging
                                self.command_processor.start_game_anyhowly(data, client_session)
                            elif client_session.client_version == 313 or client_session.client_version == 342:
                                self.command_processor.start_game_gis(data, client_session)
                            else:  # serv2 protocol
                                self.command_processor.start_game_serv2(data, client_session)

                        elif client_command == 0x4200:
                            print("RECV> SVC_PLAY_END_JEWEL")
                            # probably rebroadcast to all clients (authoritative)
                            message_to_rebroadcast = client_session.decrypt(data[6:], 0x4200)
                            client_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            for session_item in client_room.player_sessions:
                                session_item.send_encrypted(0x4410, message_to_rebroadcast)

                        elif client_command == 0x4100:
                            print("RECV> SVC_PLAY_USER_DEAD")
                            # input data looks something like 13 00 00 00 00
                            # 4100 is responded with 4102, 4410, 4101
                            # 4102 -> 00130000 00000000 44344700 (broadcast)
                            # 4410 -> FF130000 4BD80DF4 4BD80DF4 (broadcast)
                            client_session.send(0x4101, bytes.fromhex(""))  # reply to origin

                        elif client_command == 0x4412:
                            print("RECV> SVC_PLAY_RESULT")
                            # host requests 4412, but everyone receives a 4413
                            client_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            for session_item in client_room.player_sessions:
                                session_item.send(0x4413, bytes.fromhex(""))

                        elif client_command == 0x4500:
                            print("RECV> SVC_TUNNEL")
                            # first 0xC bytes: metadata? next 0xC bytes: origin, next 0xC bytes: dest
                            # i would have assumed first 0xC bytes were the payload, but sometimes data comes AFTER dest
                            # edit 2: when blocking the client's udp listen port, the client makes a tunnel request
                            # server then forwards the client its own data without the first 2 bytes (wtf?)
                            # normally tunnel activates when something broke somewhere
                            tunnel_bytes = data[6:]
                            # unknown_prefix = tunnel_bytes[0:0xC]
                            requester_id = tunnel_bytes[0xC: 0x18]
                            destination_id = tunnel_bytes[0x18: 0x24]
                            print("Tunnel requested:", string_decode(requester_id), "to", string_decode(destination_id))

                        elif client_command == 0x6000:
                            print("RECV> SVC_PROP_GET")
                            flag_send_extended = data[6]
                            user_extended_avatar = client_session.user.avatar_inventory
                            prop_reply = bytearray()
                            prop_reply.extend(client_session.user.avatar_equipped)  # 8 bytes of equipped "short" avatar
                            prop_reply.extend(int_to_bytes(client_session.user.gold, 4))  # user's gold as DWORD
                            if flag_send_extended == 1:
                                prop_reply.extend(int_to_bytes(len(user_extended_avatar), 2))  # avatar count as WORD
                                for avatar_item in user_extended_avatar:
                                    prop_reply.extend(avatar_item)  # add "long" avatar codes (DWORDs)
                            client_session.send_encrypted(0x6001, prop_reply, rtc=0)
                            # send a 1032 cash update too
                            self.command_processor.cash_update(client_session)

                        elif client_command == 0x6004:
                            print("RECV> SVC_PROP_SET")
                            plain_avatar_equipped = client_session.decrypt(data[6:], 0x6004)
                            avatar_equipped = plain_avatar_equipped[0:8]  # 8 bytes of equipped avatar
                            # should verify if user owns these avatars
                            client_session.user.avatar_equipped = bytes(avatar_equipped)
                            print(client_session.user.username, "equipping", bytes_to_hex(bytes(avatar_equipped)))
                            client_session.send(0x6005, bytes.fromhex(""), rtc=0)
                            User.save_users(self.world_user)

                        elif client_command == 0x6011:
                            print("RECV> SVC_PROP_BUY_PP")
                            plain_bought_avatar = client_session.decrypt(data[6:], 0x6011)
                            extended_avatar = plain_bought_avatar[0:4]  # DWORD avatar
                            # normally this is the part where we check the item's price (serverside),
                            # check if player has the cash to purchase, deduct accordingly, send a 1032 update
                            # and store new purchase. for now we're skipping everything
                            print(client_session.user.username, "bought (cash)", bytes_to_hex(bytes(extended_avatar)))
                            client_session.user.avatar_inventory.append(extended_avatar)
                            client_session.send(0x6017, bytes.fromhex(""), rtc=0)
                            self.command_processor.cash_update(client_session)
                            User.save_users(self.world_user)

                        elif client_command == 0x6010:
                            print("RECV> SVC_PROP_BUY")
                            plain_bought_avatar = client_session.decrypt(data[6:], 0x6010)
                            extended_avatar = plain_bought_avatar[0:4]  # DWORD avatar
                            # this is 6011 but with gold instead
                            print(client_session.user.username, "bought (gold)", bytes_to_hex(bytes(extended_avatar)))
                            client_session.user.avatar_inventory.append(extended_avatar)
                            client_session.send(0x6017, bytes.fromhex(""), rtc=0)
                            User.save_users(self.world_user)

                        elif client_command == 0x6020:
                            print("RECV> SVC_PROP_SELL")
                            plain_bought_avatar = client_session.decrypt(data[6:], 0x6020)
                            # item_position = plain_bought_avatar[0]  # item position in inventory
                            extended_avatar = plain_bought_avatar[1:5]  # DWORD avatar
                            # we'll acknowledge with OK but not do anything internally
                            print(client_session.user.username, "sold", bytes_to_hex(bytes(extended_avatar)))
                            client_session.send(0x6027, bytes.fromhex(""), rtc=0)
                            User.save_users(self.world_user)

                        elif client_command == 0x6030:
                            print("RECV> SVC_PROP_GIFT")
                            gift_plain_packet = client_session.decrypt(data[6:], 0x6030)
                            gift_recipient = string_decode(gift_plain_packet[0:0xC])
                            # unknown_four_bytes = gift_plain_packet[0xC:0x10]
                            # item_position = gift_plain_packet[0x10]  # item position in inventory
                            extended_avatar = gift_plain_packet[0x11:0x15]  # DWORD avatar
                            gift_message = resize_bytes(gift_plain_packet[0x16:], gift_plain_packet[0x15])
                            gift_message = string_decode(gift_message)
                            # we'll acknowledge with OK but not do anything internally
                            print(client_session.user.username, "gifting", bytes_to_hex(bytes(extended_avatar)), "to",
                                  gift_recipient, "with message:", gift_message)
                            # 6037 might *not* actually be the OK. I can't remember how gifts worked
                            client_session.send(0x6037, bytes.fromhex(""), rtc=0x6005)
                            User.save_users(self.world_user)

                        elif client_command == 0x5100:
                            print("RECV> GENERIC_COMMAND")
                            # acknowledgement is optional
                            command_received_raw = string_decode(data[7:]).split(" ")
                            command_received = command_received_raw.pop(0)
                            command_parameters = " ".join(command_received_raw)

                            if command_received == "q":
                                client_session.send(0x3FFF, bytes.fromhex(""))
                                self.command_processor.print_to_client(client_session, "Room closed")

                            if command_received == "close":
                                client_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                                if client_room is not None:
                                    for room_player in client_room.player_sessions:
                                        room_player.send(0x3FFF, bytes.fromhex(""))
                                        self.command_processor.print_to_client(room_player, "Room closed")

                            elif command_received == "test":
                                client_session.send(0x5101, "Connection still alive".encode("ascii"))

                            elif command_received == "bcm":
                                for session_item in self.world_session:
                                    self.command_processor.print_to_client(session_item, command_parameters)

                            elif command_received == "tankset":
                                tank_value = int(command_parameters)
                                client_session.room_tank_primary = tank_value
                                response_message = "Your primary tank will be set as " + str(tank_value)
                                response_message += "\r\n" + "This takes effect after joining a room"
                                self.command_processor.print_to_client(client_session, response_message)

                            elif command_received == "gender":
                                if command_parameters == "m":
                                    client_session.user.avatar_equipped = bytes.fromhex("00 80 00 80 00 80 00 00")
                                else:
                                    client_session.user.avatar_equipped = bytes.fromhex("00 00 00 00 00 00 00 00")
                                response_message = "Re-login required for changes to take effect"
                                self.command_processor.print_to_client(client_session, response_message)

                            elif command_received == "sessions":
                                for session_item in self.world_session:
                                    if session_item.client is not None:
                                        message_row = session_item.user.username + " : " + session_item.address[0]
                                        self.command_processor.print_to_client(client_session, message_row)

                            elif command_received == "save":
                                self.command_processor.print_to_client(client_session, "Saving - check python console.")
                                User.save_users(self.world_user)
                                self.command_processor.print_to_client(client_session, "World user state saved")

                            elif command_received == "json":
                                self.command_processor.print_to_client(client_session, client_session.user.to_json())

                            elif command_received == "credits":
                                credits = "CREDITS"

                                credits += "\r\n\r\n" + "SOFTNYX: ethera knights blash45 pirania chuko scjang " \
                                                          "loserii johnny5 designer reddragon jchlee75 yaong2 " \
                                                          "jaeyong yesoori enddream cozy comsik"
                                credits += "\r\n" + "RZ: phnx, Kimberly, LeoTheFox - Clients, GunBound theory"
                                credits += "\r\n" + "UC: vkiko2 - IDAPython GameGuard string decryption"
                                credits += "\r\n" + "InsideGB (XFSGAMES)"
                                self.command_processor.print_to_client(client_session, credits)

                        else:
                            print("Unknown response to client command:", client_command)
                else:
                    print("GS: Client disconnected")
                    if client_session is not None:
                        if client_session.channel_position != -1:
                            for session_item in self.world_session:
                                if session_item.user.username != client_session.user.username:
                                    user_channel = bytearray()
                                    user_channel.append(client_session.channel_position)
                                    session_item.send(0x200F, user_channel)
                        if client_session.room_slot != -1:
                            Room.remove_session(self.world_room, client_session.user.username)
                            Room.remove_empty_rooms(self.world_room)
                        Session.remove_session(self.world_session, client_session.user.username)
                    return True
            except Exception as e:
                client.close()
                print("EXCEPTION: (GS) client forcibly closed without cleanup")
                print(e)
                return False


# for standalone operation (without coordinator)
if __name__ == "__main__":
    world_session = []
    world_room = []
    world_user = User.get_users()
    enabled_server_functions = [FunctionRestrict.EFFECT_THOR, FunctionRestrict.EFFECT_FORCE,
                                FunctionRestrict.EFFECT_MOON, FunctionRestrict.EFFECT_LIGHTNING,
                                FunctionRestrict.AVATAR_ENABLED]

    server: GameServer = GameServer("0.0.0.0", 8370, world_session, world_room, world_user)
    server.gs_funcrestrict = FunctionRestrict.get_function_value(enabled_server_functions)
    threading.Thread(target=server.listen).start()