from broker import BrokerServer, ServerOption
from gameserver import FunctionRestrict, GameServer, User
import threading
import json


def load_broker_directory_from_file():
    # List of servers to be broadcast by the broker server
    server_options = []
    with open("directory.json") as directory_data_text:
        directory_data = json.load(directory_data_text)
        for json_row in directory_data["server_options"]:
            server_options.append(ServerOption(json_row["server_name"], json_row["server_description"],
                                               json_row["server_address"], json_row["server_port"],
                                               json_row["server_utilization"], json_row["server_capacity"],
                                               json_row["server_enabled"]))
    return server_options


if __name__ == "__main__":
    world_session = []
    world_room = []
    world_user = User.get_users()
    broker_options = []
    bind_address = "0.0.0.0"

    # broker_options = load_broker_directory_from_file()

    broker_options.append(ServerOption("Python Emulator", "Avatar ON", "192.168.1.12", 8370, 0, 20, True))

    enabled_server_functions = [FunctionRestrict.EFFECT_THOR, FunctionRestrict.EFFECT_FORCE,
                                FunctionRestrict.EFFECT_MOON, FunctionRestrict.EFFECT_LIGHTNING,
                                FunctionRestrict.AVATAR_ENABLED]

    broker_server = BrokerServer(bind_address, 8372, broker_options, world_session)
    game_server: GameServer = GameServer(bind_address, 8370, world_session, world_room, world_user)

    game_server.gs_funcrestrict = FunctionRestrict.get_function_value(enabled_server_functions)

    threading.Thread(target=broker_server.listen).start()
    threading.Thread(target=game_server.listen).start()
