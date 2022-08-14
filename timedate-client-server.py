from select import select
import sys
import socket
import datetime

VALID_REQUESTS : tuple[int] = (
    0x0001,
    0x0002
)

# incase more need to be added in the future
VALID_MAGIC_NO : tuple[int] = (
    0x497E,
)

# incase more need to be added in the future
VALID_REQUEST_PACKET_TYPE : tuple[int] = (
    0x0001,
)

# incase more need to be added in the future
VALID_RESPONSE_PACKET_TYPE : tuple[int] = (
    0x0002,
)

VALID_RESPONSE_LANGUAGE_CODES : tuple[int] = (
    0x0001, # English
    0x0002, # Te reo Maori
    0x0003, # German
)

HELP_MESSAGE : str = """
    HELP MESSAGE FOR TIME/DATE CLIENT/SERVER

        --client ("time" || "day") (ip_address || hostname) port_number

            requests the time or the day for the server, will return
            requested format in either english, Te reo Maori or german

        --server english_port_number maori_port_number german_port_number

            starts a server scanning on the 3 differnt port number and when a request
            packet is sent to one of these ports it will return the response packet
            in the language corresponding to the port 

        --help || -h

            shows this message
"""

RESPONSE_PACKET_FEILDS : tuple[str] = (
    "magic number",
    "packet type",
    "language code",
    "year",
    "month",
    "day",
    "hour",
    "minute",
    "length",
    "textual representation"
)

LANGUAGES : tuple[str] = (
    "English",
    "Te reo Maori",
    "German"
)

ENGLISH_MONTHS : tuple[str] = (
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December"
)

MAORI_MONTHS : tuple[str] = (
    "Kohit ̄atea",       
    "Hui-tanguru",      
    "Pout ̄u-te-rangi",  
    "Paenga-wh ̄awh ̄a",  
    "Haratua",          
    "Pipiri",           
    "H ̄ongongoi",       
    "Here-turi-k ̄ok ̄a", 
    "Mahuru",           
    "Whiringa- ̄a-nuku", 
    "Whiringa- ̄a-rangi",
    "Hakihea"       
)

GERMAN_MONTHS : tuple[str] = (
    "Januar",
    "Februar",
    "M ̈arz",
    "April",
    "Mai",
    "Juni",
    "Juli",
    "August",
    "September",
    "Oktober",
    "November",
    "Dezember"
)

def b_arr(number : int, num_bytes : int = 2) -> bytearray:
    """shorting for int to bytearray conversion"""
    return bytearray(number.to_bytes(num_bytes, "big"))

def b_arr_to_int(byte_arr: bytearray) -> int:
    """to shorten the conversion of bytearray to int"""
    return int(byte_arr.hex(), 16)

#------------------------------------------request packet------------------------------------------

def make_request_packet(request_type : int, magic_no : int = 0x497E, packet_type : int = 0x0001) -> bytearray:
    """
    makes the request packet
    
    magic_no should be in VALID_MAGIC_NO or else it will be discarded by server

    packet_type should be in VALID_REQUEST_PACKET_TYPE or else it will be discarded by server
    
    request_type should be in VALID_REQUESTS or else it will be discarded by server
    """
    packet = (magic_no << 16)
    packet |= packet_type
    packet <<= 16
    packet |= request_type
    return b_arr(packet, 6)

def check_request_packet(request_packet : bytearray) -> tuple[int, str]:
    """ 
    checks the request packet    
    error codes:
        -------------------------------
        | -1 | magic_no not valid     | 
        | -2 | packet_type not valid  |
        | -3 | request_type not valid |
        -------------------------------
    returns 1 if no error
    """
    if b_arr_to_int(request_packet[0:2]) not in VALID_MAGIC_NO: 
        return (-1, "magic_no not valid")
    
    if b_arr_to_int(request_packet[2:4]) not in VALID_REQUEST_PACKET_TYPE:
        return (-2, "packet_type not valid")
    
    if b_arr_to_int(request_packet[4:6]) not in VALID_REQUESTS: 
        return (-3, "request_type not valid")

    return 1, ""

#------------------------------------------response packet------------------------------------------

def make_reponse_packet(language_code : int, format_request : int, magic_no : int = 0x497E, packet_type : int = 0x0001) -> bytearray: #pure
    """
        creates the response packet:
        will first get the time,
        then create the textual representation of the time in the given language
        then make the first part of the packet adding in the magic number, packet type and language code
        then adds the time bytearray, and the length of the packet
        finally the textual representation is added on and returned
    
    """
    time : tuple[int, int, int, int, int] = get_time() 
    text : bytes = make_text_rep(language_code, format_request, *time).encode("utf-8")
    text_int : int = int.from_bytes(text, "big")
    packet : int = make_response_admin_chunk(magic_no, packet_type, language_code)
    time_chunk : int = time_to_time_chunk(*time) #6 bytes
    length_chunk = (13 + len(text))
    packet <<= 48
    packet |= time_chunk
    packet <<= 8
    packet |= length_chunk
    packet <<= (length_chunk-13)*8
    packet |= text_int
    return b_arr(packet, length_chunk)

def make_response_admin_chunk(magic_no : int, packet_type : int, language_code : int) -> int:
    """creates the the response header i.e. the parts that dont require function calls"""
    admin_chunk = (magic_no << 16)
    admin_chunk |= packet_type
    admin_chunk <<= 16
    admin_chunk |= language_code
    return admin_chunk

def get_time() -> tuple[int, int, int, int, int]:
    """ 
        returns year, month, day, hour, minute in that order
        assumes a valid time always returns
    """
    time = datetime.datetime.now()
    return (time.year, 
            time.month,
            time.day,
            time.hour,
            time.minute
            )

def time_to_time_chunk(year : int, month : int, day : int, hour : int, minute : int) -> int:
    """ 
        converts the time given in to an int where each arg is 1 byte bsides year which is
        two bytes
    """    
    time_chunk = year
    time_chunk <<= 8
    time_chunk |= month
    time_chunk <<= 8
    time_chunk |= day
    time_chunk <<= 8
    time_chunk |= hour
    time_chunk <<= 8
    time_chunk |= minute
    return time_chunk

def make_text_rep(lang_code : int, format_request : int, year : int, month : int, day : int, hour : int, minute: int) -> str:
    """creates the text response in the required language"""    
    decoded_format_request : int = int(format_request.hex(), 16)
    
    if decoded_format_request == 0x0001:
        return [
                f"Today’s date is {ENGLISH_MONTHS[month-1]} {day}, {year}",
                f"Te reo Maori Ko te ra o tenei ra ko {MAORI_MONTHS[month-1]} {day}, {year}",
                f"Heute ist der {day}. {GERMAN_MONTHS[month-1]} {year}"
               ][lang_code-1]
    
    if decoded_format_request == 0x0002:
        return[f"The current time is {hour}:{minute}",
               f"Ko te wa o tenei wa {hour}:{minute}",
               f"Die Uhrzeit ist {hour}:{minute}"
              ][lang_code-1]

def check_reponse_packet(response_packet: bytearray) -> tuple[int, str]:
    """
    checks the reponse packet    
    error codes:
        ------------------------------------------------------
        | -1  | invalid magic number                         |
        | -2  | invalid request type                         |
        | -3  | invalid language code                        |
        | -5  | invalid year i.e. year > 2100                |
        | -6  | invalid month i.e. month > 12 or month < 0   |
        | -7  | invalid day i.e. day > 31 or day < 0         |
        | -8  | invalid hour i.e hour > 24 or hour < 0       |
        | -9  | invalid minute i.e minute > 59 or minute < 0 |
        | -10 | invalid length                               |
        ------------------------------------------------------
    returns 1 if no error
    """
    #---------------------header checks------------------------------------------------------
    if b_arr_to_int(response_packet[0:2])   not in VALID_MAGIC_NO                : return (-1, "invalid magic number")
    if b_arr_to_int(response_packet[2:4])   not in VALID_REQUEST_PACKET_TYPE     : return (-2, "invalid request type")
    if b_arr_to_int(response_packet[4:6])   not in VALID_RESPONSE_LANGUAGE_CODES : return (-3, "invalid language code")
    #---------------------time checks--------------------------------------------------------
    if b_arr_to_int(response_packet[6:8])   > 2100                               : return (-5, "invalid year i.e. year > 2100")
    if b_arr_to_int(response_packet[8:9])   not in range(1, 12+1)                : return (-6, "invalid month i.e. month > 12 or month < 0")
    if b_arr_to_int(response_packet[9:10])  not in range(1, 31+1)                : return (-7, "invalid day i.e. day > 31 or day < 0")
    if b_arr_to_int(response_packet[10:11]) not in range(0, 24)                  : return (-8, "invalid hour i.e hour > 24 or hour < 0")
    if b_arr_to_int(response_packet[11:12]) not in range(0, 60)                  : return (-9, "invalid minute i.e minute > 59 or minute < 0")
    #---------------------length check-------------------------------------------------------
    if b_arr_to_int(response_packet[12:13]) != len(response_packet)              : return (-10, "invalid packet length")
    if len(response_packet[13:].decode("utf-8")) > 255                           : return (-11, "invalid text length")

    return (1, "")

#------------------------------------------ debugging ------------------------------------------

def decompose_reponse_packet(packet : bytearray) -> tuple[int, int, int, int, int, int, int, int, int, str]:
    """decompses the response packet to a human readible format"""
    return (b_arr_to_int(packet[0:2]),
            b_arr_to_int(packet[2:4]),
            b_arr_to_int(packet[4:6]),
            b_arr_to_int(packet[6:8]),
            b_arr_to_int(packet[8:9]),
            b_arr_to_int(packet[9:10]),
            b_arr_to_int(packet[10:11]),
            b_arr_to_int(packet[11:12]),
            b_arr_to_int(packet[12:13]),
            packet[13:].decode("utf-8")
    )

def decompose_request_packet(packet: bytearray) -> tuple[int, int, int]:
    """decompses the request packet to a human readible format"""
    return (int(packet[0:2].hex(), 16),
            int(packet[2:4].hex(), 16),
            int(packet[4:6].hex(), 16))

#------------------------------------------ client ------------------------------------------

def send_request(option : str, addr : str, port : int):
    """
        sends the clients request to the specified ip and port
        will show error messages if args are not valid; packet
        times out due to incorrect server name, port, or 
        some other reason; if the response packet was wrong
        in any way and display the error code and error message    
    """
    if not check_port_range(port):
        print(f"[ERROR]: port not in range of (1000, 64000)")


    if option == "time":
        request_packet = make_request_packet(1)
    elif option == "day":
        request_packet = make_request_packet(2)
    else:
        print(f"[ERROR]: {option}: identifier is not valid please select between \"day\" and \"time\"")
        return

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(1)

    try:
        ip = socket.gethostbyname(addr)
        print(ip)
        client.sendto(request_packet, (ip, port))
        packet, addr = client.recvfrom(255)

        response_packet_check = check_reponse_packet(packet)

        if response_packet_check[0] == 1:
            decompoesed_packet = decompose_reponse_packet(packet)
            print(f"response form server address:{addr[0]}, port:{addr[1]}:") 
            for i in zip(decompoesed_packet, RESPONSE_PACKET_FEILDS):
                print(f"{i[1]} : {i[0]}")
        else:
            print(f"[ERROR] code:{response_packet_check[0]} error: {response_packet_check[1]}")
    except socket.timeout:
        print("[ERROR]: request timed out, check server ip and port")
    except socket.gaierror as e:
        print("[ERROR]: ip or domain name does not exist")
    finally:
        client.close()

#------------------------------------------ server ------------------------------------------

# gets the local machines ip address
SERVER_IP : str = socket.gethostbyname(socket.gethostname())
# creates 3 servers to be bound to 
servers : list[socket.socket] = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                ]
#initialized list of ports
ports : list[int] = []

def setup_server(port_en : int, port_tm : int, port_gm : int) -> None:
    """
        sets up all 3 language servers and checks the to see if the port numbers are valid
        then runs the server
    """
    if not (check_port_range(port_en) and check_port_range(port_tm) and check_port_range(port_gm)):
        print(f"[ERROR]: not all ports in range {port_en, port_tm, port_gm}")
        return 
    if (port_en == port_tm) or (port_tm == port_gm) or (port_en == port_gm):
        print(f"[ERROR]: duplicate port numbers {port_en, port_tm, port_gm}")
        return

    assignment_error = False
    for i in zip(servers, (port_en, port_tm, port_gm), LANGUAGES):
        try:
            i[0].bind((SERVER_IP, i[1]))
            time = get_time()
            print(f"[SERVER][{str(time[3]).rjust(2, '0')}:{str(time[4]).rjust(2, '0')}]: bound {i[2]} date-time response server to port : {i[1]}")
        except OSError as e:
            print(f"[SERVER][ERROR]: port:{i[1]} already in use please select a differnt port number")
            assignment_error = True

    if assignment_error: return

    global ports
    ports = [port_en, port_tm, port_gm]

    run_server()

def check_port_range(p : int) -> bool:
    """checks to see if port is valid"""
    if p in range(1024, 64001):
        return True
    return False

def get_lang_code_from_port(port : int) -> int:
    """will return the language code for a given port"""
    return ports.index(port) + 1

def run_server() -> None:
    """
        runs the server and handles any malformed packets
    """
    while True:
        lang_servers, *n = select(servers,[],[])
        for data in lang_servers:
            packet, ip = data.recvfrom(6)
            data_info = data.getsockname()
            request_packet_check = check_request_packet(packet) 
            time = get_time()
            
            print(f"[SERVER][{str(time[3]).rjust(2, '0')}:{str(time[4]).rjust(2, '0')}]: ", end="")
            print(f"request packet from address: {data_info[0]} on port: {data_info[1]}")
            
            
            if request_packet_check[0] != 1:
                print(f"[SERVER][ERROR]:request packet error CODE:{request_packet_check[0]}")
                print(f"\t\terror:{request_packet_check[1]}")

            else:
                lang_code = get_lang_code_from_port(data_info[1])
                response_packet = make_reponse_packet(lang_code, packet[4:6])
                response_packet_check = check_reponse_packet(response_packet) 

                if response_packet_check[0] != 1:
                    print(f"[SERVER][ERROR]: malformed response packet:")
                    print(f"\t\thex : {response_packet.hex()}")
                    print(f"\t\terror code{response_packet_check[0]}")
                    print(f"\t\terror:{response_packet_check[1]}")

                else:
                    time = get_time()
                    print(f"[SERVER][{str(time[3]).rjust(2, '0')}:{str(time[4]).rjust(2, '0')}]: ", end="")
                    print(f"sent response packet to address: {data_info[0]} on port: {data_info[1]}")
                    data.sendto(response_packet, ip)

#------------------------------------------ main ------------------------------------------

def main() -> None:
    try:
        args = sys.argv[1:]
        match args:
            case("--server", p1, p2, p3, *n):
                print(f"\n[WARN] discarded unnecessary args: {n}") if len(n) != 0 else None
                setup_server(int(p1), int(p2), int(p3))
            case("--client", x, ip, p, *n):
                print(f"\n[WARN] discarded unnecessary args: {n}") if len(n) != 0 else None
                send_request(x, ip, int(p))
            case("--help", *n):
                print(HELP_MESSAGE)
            case("-h", *n):
                print(HELP_MESSAGE)
            case("--client", *arg):
                print(f"[ERROR] not enough args please refer to the help section by using --help or -h")
            case("--server", *arg):
                print(f"[ERROR] not enough args please refer to the help section by using --help or -h")
            case(*n):
                print(HELP_MESSAGE)
    except Exception as e:
        print(f"[ERROR] something went horribly wrong, error:\n{e}")

if __name__ == "__main__":
    main()

    