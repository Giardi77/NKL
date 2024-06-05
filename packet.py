import socket

SEPARATOR = '\r\n'
ENDPACKET = '\n\r'

class Packet:
    def __init__(self, header, data):
        if isinstance(header,bytes):
            self.header = header + bytes(SEPARATOR,'utf-8')
        else:
            self.header = header + SEPARATOR
         
        if isinstance(data, bytes):
            self.data = data + bytes(ENDPACKET,'utf-8')

        elif isinstance(data, int): 
            self.data = str(data) + ENDPACKET

        else:
            self.data = data + ENDPACKET
        

    def get_header(self,as_str=True) -> str:
        if as_str:
            if isinstance(self.header, bytes):
                str_header = self.header.split(SEPARATOR.encode('utf-8'))
                header = str_header[0].decode('utf-8')
            elif isinstance(self.header, str):
                str_header = self.header.split(SEPARATOR)
                header = str_header[0] 
        else:
            if isinstance(self.header, bytes):
                str_header = self.header.split(SEPARATOR.encode('utf-8'))
                header = str_header[0]

        return header
    
    def get_data(self, as_str=True) -> str:
        if as_str:
            if isinstance(self.data, bytes):
                str_data = self.data.split(ENDPACKET.encode('utf-8'))
                data = str_data[0].decode('utf-8')
            elif isinstance(self.data, str):
                str_data = self.data.split(ENDPACKET)
                data = str_data[0] 
        else:
            str_data = self.data.split(ENDPACKET.encode('utf-8'))
            data = str_data[0]

        return data
    
    def raw_packet(self) -> bytes:
        if isinstance(self.header, bytes):
            packet = self.header
        else:
            packet = bytes(self.header,'utf-8')

        if isinstance(self.data, bytes):
            packet += self.data
        else:
            packet += bytes(self.data,'utf-8')

        return  packet

def send_packet(sock: socket.socket, packet: Packet):
    raw_data = packet.raw_packet()
    sock.sendall(raw_data)

def receive_packet(sock: socket.socket) -> Packet:
    buffer = b''
    while ENDPACKET.encode('utf-8') not in buffer:
        buffer += sock.recv(1)

    header , data= buffer.split(SEPARATOR.encode('utf-8'))

    return Packet(header, data)

