# Gunbound (Thor's Hammer) Server Emulator

This project attempts to emulate the server components of GunBound Thor's Hammer, which was discontinued in 2006.

**Screenshots**

![Channel Chat](https://raw.github.com/jglim/gunbound-server/master/Other/channelchat.gif)
![Game Load](https://raw.github.com/jglim/gunbound-server/master/Other/gb-gameload.png)
![In Game](https://raw.github.com/jglim/gunbound-server/master/Other/gb-ingame.png)
![Game End](https://raw.github.com/jglim/gunbound-server/master/Other/gb-gameend.png)
![Post Game Lobby](https://raw.github.com/jglim/gunbound-server/master/Other/gb-postgame.png)
![Avatar](https://raw.github.com/jglim/gunbound-server/master/Other/gb-avatar.png)

### Objective

- Fully emulate a server that supports GunBound Thor's Hammer "Serv2" clients, and the GIS 313 client
- Publicly document the client and server protocols, operating processes, as well as disassembly notes to preserve GunBound. Hopefully this may be of use to others who might want to start a project to rescue old games too

### Status

**Broker Server: Fully implemented**
- Supports multiple servers with different addresses and ports
- When used with coordinator, server load indicator is also functional
- Servers may be listed but disabled (grayed)

**Game Server: Mostly implemented**
- Login fully supports Serv2 protocol, and some GIS/GKS clients
    - Credentials and client version can be validated, and clients can be optionally rejected
    - (new!) Cryptography fully implemented in Python (completely portable)
    - User's game rank can be changed
    - User's guild name can be changed
    - Guild rank value is indicated but unused
    - GP value is indicated but unused
    - Gold/Cash value can be changed 
    - Server functions ("FuncRestrict") can be changed
    - Past performance (shot history etc.) are not implemented
- Channel join/leave/chat/"id query" is fully functional
- Cash update `0x1032` is fully functional
- Avatar shop is functional
    - Cash/Gold are not deducted when buying or selling
    - Selling is equivalent to deleting
    - Gifting is acknowledged but not implemented
- Room directory is functional
    - Room list provides an entire directory regardless of filter
    - Room details (right click on room) is implemented
    - Direct room join is not implemented
    - Pagination is not implemented
- Room session is functional
    - Room join is implemented
    - Room creation is implemented
    - Room config changes are implemented (propagates to room directory)
    - Room core features (tank select, team change, item lock, ready) are implemented
    - Password checks are acknowledged but ignored
    - Room host/key migration (appears to be) functional
    - Room start is implemented (Serv2 only - GIS: buggy)
    - Room start position is fixed (does not look up `*_stage_pos.txt`)
    - Room rejoin after game end is implemented
    - Room kick is not implemented
- Game session is partially implemented
    - Multiplayer is functional for Serv2 clients
    - Jewel game mode is fully functional (Serv2)
    - Solo game mode is partially implemented (bug: ends only after host dies) 
    - Score game mode is untested
    - Play result (game end) is acknowledged, but unimplemented
    - "Buggy" singleplayer is available for GIS clients
- Some administrative features are implemented
    - `/q` to quit from own game
    - `/close` to close entire room (self)
    - `/bcm` to broadcast a message to all sessions
    - `/tankset` to force the server to assign a specific primary tank when responding to a game start packet. This may be useful to debug the dragon/knight issue
    - `/gender` sets own gender (m/f). Changes take place after relogin
    - `/sessions` prints all active sessions
    - `/save` serializes world user state and saves it to the database/flatfile
    - `/json` prints own session data in JSON format
    - `/credits` thanks everyone who has contributed to this project
- TCP Tunneling `0x4500` is not implemented
- Basic storage/data persistence is implemented (JSON/flat file)


**Buddy Server: Not implemented**
- Very low priority, and might only be worked on when everything else works

### Getting started

_Requires Python 3.6_

1. Clone the project into a directory of your preference, preferably in a _venv_
2. Install the project's requirements (`pip install -r requirements.txt`)
3. In `coordinator.py`, replace the `192.168.1.x` address with your current IP
4. Run `coordinator.py` to launch the game server and the broker server
5. Configure your [client](https://github.com/jglim/gunbound-launcher) to connect to your server

### TODO / Please help!

- Fix room start for "GIS" clients (targeting version 313)
    - It appears similar to Serv2, but starts with 4 (?) new unknown bytes
    - I somehow end up with Armor even though the client's debug log indicates that the tank data is correctly read. Fuzzing the entire packet does not change the tank I receive.
    - Something is probably broken somewhere in the game start because the client bugs up when returning to the lobby after a game.
- Fix Dragon/Knight "random"
    - According to the disassembly, there is a small chance that the server will give the user tank 14 (dragon) or tank 15 (knight) as a random tank. 
    - However when this occurs, the client shows an invisible tank in the lobby, and defaults to Armor in game. 
    - The dragon/knight assets are present in the client
    - How can the intended behavior be restored?
    - Use the command `/tankset 14` or `/tankset 15` after joining a room to reproduce this bug
- Set start position
    - When a game starts, players are randomly assigned in-game positions
    - The data should be read off `*_stage_pos.txt` and slots are picked based on the map
    - If the player count is below a certain (?) threshold, "Small mode" is enabled and players spawn closer to each other.
    - There seems to be 4 bytes that decide this, but they don't match up with values from the text files above. How are the values correlated?
- Fix GIS login
    - The GIS client accepts the login response `0x1012` without issue, but never requests to join the channel.
    - A hacky solution I used is to send the *response* for channel join even though it was not requested, as that changes the gamemode to 3 (channel/directory). Everything else seems to work fine from there.
    - Why is the channel join request never made? Is it a CSAuth issue?
- Test multiplayer that's more than just 1v1. I don't have enough machines, and VMs do not play well with my wireless NIC.
- Tidy up `CommandProcessor`, split `gameserver.py` into manageable-sized chunks

---

### Contributors / Credits


**Softnyx**
ethera knights blash45 pirania chuko scjang loserii johnny5 designer reddragon jchlee75 yaong2 jaeyong yesoori enddream cozy comsik
- **phnx** (RZ) - _GunBound theory_
- **Kimberly** (RZ) - _Clients_
- **LeoTheFox** (RZ) - _GunBound theory_
- **vkiko2** (UC) - _IDAPython GameGuard string decryption_
- **XFSGAMES** (?) - _InsideGB_


_There are plenty of `# unknown`, comments in the code, TODOs, as well as guessed packet structures. If you spot an error, or would like to add information, **please** open an issue or PR. Don't worry about the formatting - I'll fix it._

---
# License

MIT

Game client and artwork assets belong to Softnyx

---

# GunBound Documentation

This attempts to be a comprehensive GunBound documentation (no specific scope). There might be some overlaps with my other repositories.

## Client

### Minimal Client
To start the game, these files are required as a minimum

- `avatar.xfs` - avatar description and stats
- `sound.xfs` - almost all sound/music used by the client
- `graphics.xfs` - all images, animations and accessory files such as localization strings, "bad words" etc. If a file does not fit into the existing XFS file, it gets placed here.
- `characterdata.dat`, `itemdata.dat`, `specialdata.dat`, `stage.dat` - game configuration data. `characterdata.dat` describes the tank's attack properties such as angle ranges and damage type. In later versions, the `*.dat` files were moved into `graphics.xfs`. 
- `GunBound.gme` - the main game client, a 32-bit MSVC7 binary packed with Yoda's cryptor/ASPack/ASProtect.

### Launcher

The main `GunBound.gme` client is launched via the `GunBound.exe` launcher. However it is possible (and desirable) to skip the launcher for the following reasons:
- GunBound's original "Fetch" system has to be emulated
- The updating/patching system is proprietary
- Existing fetch emulation does not validate the user's credentials
- Credential checking is done again when the client connects to the world

To launch the client directly:
- Generate an array of 48 bytes containing 
    - ASCII-encoded username (bytes 0-15). Pad with `0`
    - ASCII-encoded password (bytes 16-31). Pad with `0`
    - The last set of 16 bytes can safely remain as `0`s. They appear to used be for a "invite-to-game" feature 
- Encrypt the data with AES-128 in ECB mode. The key is fixed as `FAEE85F24073D9161390197F6E562A67`
- Convert the bytes to an uppercase hex string. The result should be a 96-character credentials string
- Start `GunBound.gme` with the above value as its **only** command line parameter. 
    - Conventionally when a process is started with arguments, its own path is also prepended e.g. `"C:\Windows\system32\NOTEPAD.EXE" C:\some_file.txt`. 
    - Most implementations (batch files, `subprocess.run`, `System.Diagnostics.Process.Start` etc. do this by default)
    - The client exits if the executing path is included with the credentials string
    - Call `CreateProcess` with the credentials string for the `lpCommandLine` parameter get around this issue 

An open-source replacement launcher is available [here](https://github.com/jglim/gunbound-launcher). 

### Unpacking

Most GunBound.gme clients that I've seen are packed with ASProtect/ASPack, which can be unpacked using _stripper v2.07_ by syd, kiev. Look around online for `stripper_v207ht`.

### Enabling debug logs

In some clients, very useful debug logging is included, but not enabled. If a string containing `"None Debug Mode\n"` exists, the feature is most likely present. Find the xref to that string, and look for the subsequent `CALL` to find the debug function.

The original code likely had `#define` directives to create a logfile and store its handle, located at a static address. Thereafter, when the function is called, the client checks if the handle is valid before writing to it. This handle has to be restored for the debug logs to work again

My preferred way to enable logging is to inject a DLL into the process, conveniently after starting it using `CreateProcess` with the `CREATE_SUSPENDED` flag. Thereafter, `CreateFile` is called and the resulting handle is "restored" into the client. This also allows arbitary file names to be used. The debug log can alternatively be routed to a console using `AllocConsole`, and calling ``CreateFile`` with `"CONOUT$"` as the `lpFileName` parameter. A nearby jump also has to be disabled to prevent the handle from being overwritten.

### Disabling GameGuard

GameGuard (anti-cheat rootkit) prevents the game from launching normally, as the compatible GameGuard servers are no longer operating. 

**GameGuard from Softnyx's perspective**

- Softnyx licenses GameGuard from INCA, and is provided an SDK and a guide (nProtect GameGuard 적용 매뉴얼)
- The SDK contains a header `NPGameLib.h` and a static library `NPGameLib.lib` to be compiled into the client, along with external supporting files
- The class `CNPGameLib` is initialized. If the GameGuard functions do not respond with `NPGAMEMON_SUCCESS`, the client is expected to exit
- For most of GunBound's clients: `#define NPGAMEMON_SUCCESS 0x755`

From our perspective, the easiest way to disable GameGuard is to:

- Remove the GameGuard supporting files, so that it always fails to initialize and is unable to update
- Look for checks with `0x755`, and invert the jump so the client always believes that GameGuard is healthy 

GameGuard strings are encrypted, and are only decrypted right before they are used. They can be fixed using [this IDAPython script](https://www.unknowncheats.me/forum/anti-cheat-bypass/185476-idapython-gameguard-string-deobfuscator.html) by _vkiko2_. The automatic detection feature does not work by default, and requires manually finding the decryption method and plugging the address in the script. Thereafter, finding the GameGuard functions is much easier, with obvious strings like `'== InitNPGameMon done'` .

The above technique has worked for me on the official GIS 313 client (protocol-incompatible with Serv2), where I could successfully play a buggy round of Jewel. 

### XFS Container Format

XFS (Xenesis File System) is a container format which is used for most of GunBound's assets, that is (probably) preferred for its ability to compress data while keeping changes contiguous to enable efficient patching. XFS2 is a versioned filesystem, and the client will compare the container's version with the registry value during startup to determine if it is outdated.

Softnyx appears to have leaked their editor `XFS2.EXE` (XFS2 응용 프로그램), and `XFS2.EXE` is the preferred tool for modifying GunBound Thor's Hammer files. For browsing, an _"open source"_ tool `InsideGB` works well. There is no clear origin/author or license to it.

---

## Server

### Components
These are the key "Serv2" components required for full GunBound functionality:
- Broker Server
    - Directory server that despatches clients to game servers
    - Connects with Center Server
    - Only one instance runs
    - Official files were never released
- Buddy Server: Single server that supports all buddy functionality
    - Handles all buddy functionality
    - Connects with Center Server
- Game Server
    - Handles world-related matters (room, channel, game despatch) as well as avatar commands.
    - Multiple instances can run, each representing a game "world"
    - Connects with Center Server
- Center Server
    - Acts as a coordinator between all the server modules
    - Client never interacts directly with the Center

### Why not stick to Serv2?
- Serv2 has known security issues (vulnerable to SQL injection)
- Serv2 is compiled with an old MySQL binary requires a OLD_PASSWORD (insecure) workaround
- It is hard to add new features to Serv2

---

# Communications

### Sequence

After establishing a connection, both client and server both track of the number of bytes that they have sent and received. "Sequence" is a 16-bit value (WORD) that can be calculated from the number of sent bytes:

Server to Client, where `sum_packet_length` is the total number of bytes that the server has sent the client. 

`(((sum_packet_length * 0x43FD) & 0xFFFF) - 0x53FD) & 0xFFFF`

When generating a sequence value for sending a packet, take note that the `sum_packet_length` also includes the size of the outgoing packet.

This server does not verify the client's sequence, as TCP implies that the packet order and values are already checked at a lower layer. The sequence value may be more useful in UDP, especially during GunBound's in-game P2P communication.

### Cryptography

GunBound encrypts some packets such as channel communications, avatar shop interactions, and places  where sensitive data is exchanged. The process for setting up the encryption is as follows:

- Client sends a PING `0x1000` packet
- Server acknowledges with PONG `0x1001`, with a 4-byte nonce
- Client generates a dynamic AES key:
    - A SHA0-like function is initialized
    - Username, _plain_ password and nonce is individually added
    - The hash is finalized, and the first 16 bytes are used as the dynamic AES key
- The login packet begins with the username and hashed password (AES-128, ECB) using a fixed key `FFB3B3BEAE97AD83B9610E23A43C2EB0`
- Additional data such as client version is encrypted using the dynamic AES key and appended to the packet
- The login packet is sent from the client (`0x1010`). Subsequent encrypted packets will use the same dynamic AES key

Because of the way which the dynamic key is determined (during the hashing process), **user passwords have to be stored in plaintext**.

#### Modified SHA-0

A modified SHA-0 hash is used when the client and server generate a shared dynamic AES key. The hash itself is SHA-0, although every DWORD in the output (5 total) is endian-flipped. AES only requires 16 bytes for a key, so the last 4 bytes are discarded. The original code used by GunBound appears to be from OpenSSL, sharing the same `SHA_CTX` structure.


#### AES

For secure network traffic and passing of login parameters, GunBound uses AES-128 in ECB mode. **This configuration is insecure**.

- Key for encrypting command line parameters: `FAEE85F24073D9161390197F6E562A67`
- Key for login packet's first 32 bytes `FFB3B3BEAE97AD83B9610E23A43C2EB0`

Padding is required to align to the 16-byte boundary during block encryption. The client does not care about the padding content. In fact the client sometimes sends irrelevant neighbouring bytes which may be mistaken for meaningful data.

To find the AES block operation, travel up the xrefs from the S/S-inv box (for encryption/decryption, respectively), which can be found in its expanded form. The right function should appear as a lot of move, shift and xor operations, along with comparisons/jumps for 10/12/14 (number of rounds for AES 128/192/256).

Keys can be found by placing a breakpoint before the AES block operation, and reading the memory region of the key schedule parameter. The memory region should contain two 176-byte key schedules, one of which is reversed in blocks of 16 bytes, each used for encryption and decryption. The key is the first 16 bytes of the encryption schedule, or the last 16 bytes of the decryption schedule.

### Packet structure

**Normal**

Most unencrypted packets follow this format
```
Packet length: 2 Bytes / WORD
Sequence: 2 Bytes / WORD
Command: 2 Bytes / WORD
Payload: 0-N Bytes, defined by packet length
```

**RTC**

Essentially a normal packet with an extra "RTC" value before the payload. This is used in room-related packets. I have no idea what "RTC" stands for; the name is simply lifted from the disassembly.
```
Packet length: 2 Bytes / WORD
Sequence: 2 Bytes / WORD
Command: 2 Bytes / WORD
RTC: 2 Bytes / WORD
Payload: 0-N Bytes, defined by packet length
```

**Encrypted**

There are commands that encrypt the payload of the packet _(cash-updates, avatar commands, user query, game start, channel chat and in-game server commands)_. Depending on the command, they can either be in the style of a "Normal" or "RTC" packet. 

To encrypt a packet
- Calculate the check value, a 32-bit result of `0x8631607E + command`
- Pad the payload until the payload size is a multiple of 12.
- Split the payload into chunks of 12 bytes
- For every chunk of 12 bytes, prepend the check value
- Reassemble the chunks, which should now be 16 bytes each
- The reassembled bytes can now be encrypted (AES) using the client's dynamic key


### P2P
TODO: describe host "key"

### UDP Echo
TODO

### Tunnel
TODO

---
### Misc

The Softnyx programmers appear to be big fans of [Neon Genesis Evangelion](https://en.wikipedia.org/wiki/Neon_Genesis_Evangelion) (1995)

**Mobile/Bot/Tanks** _Internally represented as a BYTE_

|Name|Name (KR)|ID|Remarks|
|-|-|-|-|
|Armor|아머|`0x00` (0)|Defaults to Armor when ID is invalid|
|Mage|메이지|`0x01` (1)||
|Nak|나크|`0x02` (2)||
|Trico|트리코|`0x03` (3)||
|Bigfoot|빅풋|`0x04` (4)||
|Boomer|부머|`0x05` (5)||
|Raon|레온런쳐|`0x06` (6)||
|Lightning|라이트닝|`0x07` (7)||
|J.D.|제이디|`0x08` (8)||
|A.Sate|에세트|`0x09` (9)||
|Ice|아이스|`0x0A` (10)||
|Turtle|터틀|`0x0B` (11)||
|Grub|그럽|`0x0C` (12)||
|Aduka|슈퍼2 ("Super 2")|`0x0D` (13)||
|Dragon|드래곤|`0x0E` (14)||
|Knight|나이트|`0x0F` (15)||
|Random|-|`0xFF` (-1)|Asset name is "rider"|

**Ranks** _Internally represented as a 16-bit WORD_

|Name|ID|
|-|-|
|20|ADMINISTRATOR|
|19|CHICK|
|18|WOODEN|
|17|DOUBLE WOODEN|
|16|STONE|
|15|DOUBLE STONE|
|14|AXE|
|13|DOUBLE AXE|
|12|SILVER AXE|
|11|DOUBLE SILVER AXE|
|10|GOLD AXE|
|9|DOUBLE GOLD AXE|
|8|BATTLE AXE|
|7|BATTLE AXE PLUS|
|6|SILVER BATTLE AXE|
|5|SILVER BATTLE AXE PLUS|
|4|GOLDEN BATTLE AXE|
|3|GOLDEN BATTLE AXE PLUS|
|2|VIOLET WAND|
|1|SAPPHIRE WAND|
|0|RUBY WAND|
|-1|DIAMOND WAND|
|-2|BLUE DRAGON|
|-3|RED DRAGON|
|-4|SILVER DRAGON|


**Game Mode** _Internal value used to track the client's state_

|ID|Name|
|-|-|
|1|Intro Splash? (never called)|
|2|World Select|
|3|Channel|
|5|Init3D/Evangelion failed|
|7|Avatar Shop|
|9|Room|
|11|In Game Session (Play)|
|15|Exit to Desktop|


