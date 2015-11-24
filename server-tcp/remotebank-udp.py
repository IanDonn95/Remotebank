import argparse
import socket
import hashlib

MAX_FAILED_TRIES = 3
TIME_OUT = 1.

#debug print
def dprint(x):
    if args.debug:
        print(x)

#Gets the next UDP message. Format taken from remotebank-tcp to increase code reuse
def pullNextMessage():
   return conn.recvfrom(BUFFER_SIZE)


#verifies a response was given and exits if it wasn't
def checkResp(s):
    if not s:
        dprint("Connection closed by server prematurely")
        print("Connection with the server has been terminated. Please try again.")
        exit()

#argparse use adapted from https://docs.python.org/2/library/argparse.html#module-argparse
parser = argparse.ArgumentParser(description = 'TCP server: port [-d]')
parser.add_argument('sa_arg', metavar = 'D', type = str, help = 'server address, example 127.0.0.1:8591')
parser.add_argument('user_arg', metavar = 'U', type = str, help = 'username')
parser.add_argument('pass_arg', metavar = 'P', type = str, help = 'password')
parser.add_argument('action_arg', metavar = 'A', type = str, help = 'action, choices are \'deposit\' and \'withdraw\'')
parser.add_argument('amount_arg', metavar = 'M', type = float, help = 'Transaction amount')
parser.add_argument('-d', dest = 'debug', help = 'enable debug messages', action = 'store_const', const = 1, default = 0)
args = parser.parse_args()

if args.action_arg != "deposit" and args.action_arg != "withdraw":#Who knows what the user wants? We don't!
    print("Please choose a valid action. Valid actions are are \'deposit\' and \'withdraw\'")
    exit()

#args.user_arg = args.user_arg[1:-1]#This would handle checking for quotes (by invalidating passwords without them),
#args.pass_arg = args.pass_arg[1:-1]#but the argument parser I am using treats "x" and x the same, and excludes the '"'

#UDP Client implementation
#basic setup from https://wiki.python.org/moin/UdpCommunication

try:
    UDP_IP = args.sa_arg.split(':')[0] #IP part
    dprint("IP: " + UDP_IP)
    UDP_PORT = int(args.sa_arg.split(':')[1]) #Port part
    dprint("Port: " + str(UDP_PORT))
except:
    print("Please use a valid server address and port and try again.")
    exit()
BUFFER_SIZE = 1024 #tunable value
conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #create the UDP socket
conn.settimeout(TIME_OUT) #set timeout
user = args.user_arg
args.user_arg = args.user_arg.encode('ASCII')
args.pass_arg = args.pass_arg.encode('ASCII')

try:

    #Authentication Sector
    sectorComplete = 0
    failedTries = 0
    while not sectorComplete and failedTries < MAX_FAILED_TRIES:
        try:
            dprint("Sending: $authreq*")
            conn.sendto(bytes("$authreq*", 'ASCII'), (UDP_IP, UDP_PORT))
            resp = pullNextMessage()
            if resp[1] != (UDP_IP, UDP_PORT): #receiving data from something other than the server
                dprint("Data from unknown source. Ignoring.")
            else:
                data = str(resp[0], 'ASCII')
                dprint("Response from server: " + data)
                if data[:11] == "$challenge:": #appropriate response
                    challenge_value = data[1:-1].split(':')[1]
                    dprint("Random string: " + challenge_value)
                    #MD5 usage from https://docs.python.org/2/library/hashlib.html#module-hashlib
                    m = hashlib.md5()
                    m.update(args.user_arg)
                    m.update(args.pass_arg)
                    m.update(challenge_value.encode('ASCII'))
                    hash = m.hexdigest()
                    dprint("hash: " + hash)
                    message = "$hashclient:" + hash + ":" + str(args.user_arg, 'ASCII') + "*"
                    dprint("Sending: " + message) #Second part of sector, timeouts here reset to the beginning to get the newest challenge value
                    conn.sendto(bytes(message, 'ASCII'), (UDP_IP, UDP_PORT))
                    resp = pullNextMessage()
                    if resp[1] != (UDP_IP, UDP_PORT): #receiving data from something other than the server
                        dprint("Data from unknown source. Ignoring.")
                    else:
                        data = str(resp[0], 'ASCII')
                        dprint("Response from server: " + data)
                        if data != "$authresp:true*":#authentication failed
                            dprint("Authentication error. Retrying in event of network issue being cause")
                            failedTries += 1
                        else: #Authenticated
                            print("Welcome " + user)
                            sectorComplete = 1
        except socket.timeout:
            dprint("Timed Out.")
            failedTries += 1
            if failedTries == MAX_FAILED_TRIES:
                print("Connection timed out. Please try again.")
                exit()
    if not sectorComplete: #transactions failed most likely bad user input
        print("Authentication failed. Please try again.")
        conn.close()
        exit()
    #Authentication Sector Complete

    #Transaction Alpha Sector
    sectorComplete = 0
    failedTries = 0
    while not sectorComplete and failedTries < MAX_FAILED_TRIES:
        try:
            message = "$reqID*"
            dprint("Sending: " + message)
            conn.sendto(bytes(message, 'ASCII'), (UDP_IP, UDP_PORT))
            resp = pullNextMessage()
            if resp[1] != (UDP_IP, UDP_PORT): #receiving data from something other than the server
                dprint("Data from unknown source. Ignoring.")
            else:
                data = str(resp[0], 'ASCII')
                dprint("Response: " + data)
                if data[:8] == "$idpass:": #appropriate response
                    id = data[1:-1].split(":")[1]
                    sectorComplete = 1
        except socket.timeout:
            dprint("Timed Out.")
            failedTries += 1
            if failedTries == MAX_FAILED_TRIES:
                print("Connection timed out. Please try again.")
                exit()
    if not sectorComplete: #transactions failed most likely bad user input
        print("Transaction failed. Please try again.")
        conn.close()
        exit()
    #Transaction Alpha Sector Complete

    #Transaction Beta Sector
    sectorComplete = 0
    failedTries = 0
    mostUpToDateAmount = -1
    while not sectorComplete and failedTries < MAX_FAILED_TRIES:
        try:
            message = "$transquery:" + id + ":" + args.action_arg + ":" + str(args.amount_arg) + "*"
            dprint("Sending: " + message)
            conn.sendto(bytes(message, 'ASCII'), (UDP_IP, UDP_PORT))
            resp = pullNextMessage()
            data = str(resp[0], 'ASCII')
            dprint("Response: " + data)
            if data[:13] == "$transresult:": #appropriate response
                d = data[1:-1].split(':')
                if id == d[3]: #correct id for this particular transaction
                    mostUpToDateAmount = d[2]
                    if d[1] == "true": #transaction completed
                        sectorComplete = 1
                        print("Transaction completed. Current balance: " + str(mostUpToDateAmount))
        except socket.timeout:
            dprint("Timed Out.")
            failedTries += 1
            if failedTries == MAX_FAILED_TRIES:
                print("Connection timed out. Please try again.")
                exit()
    if not sectorComplete: #transactions failed most likely bad user input
        if mostUpToDateAmount == -1:
            print("Transaction failed. Please try again.")
        else:
            print("Transaction completion unconfirmed. Best-known account balance is: " + str(mostUpToDateAmount))
        conn.close()
        exit()
    #Transaction Beta Sector Complete
   
    dprint("Client exiting normally")
    conn.close()

except socket.error as e:
    dprint("Error occurred: " + str(e.errno) + ": " + e.strerror)
    if e.errno == 11001:
        print("Please enter a valid server address and port number and try again.")
        exit()
    if e.errno == 10061:
        print("Connection rejected by server. Please check your server address and port number and try again.")
        exit()
    print("Connection with the server has been terminated. Please try again.")