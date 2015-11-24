import argparse
import socket
import hashlib

#debug print
def dprint(x):
    if args.debug:
        print(x)

#TCP stream to message converter
def pullNextMessage():
    resp = []
    completeMessage = 0
    pulledChars = 0
    for c in pullNextMessage.overflow:        
        pulledChars += 1
        if c != '*':
            resp += [c]
        else:
            resp += ['*']
            completeMessage = 1
        if completeMessage:
            pullNextMessage.overflow = pullNextMessage.overflow[pulledChars:]
            break
    if completeMessage: #full message contained in overflow
        return ''.join(resp)
    #overflow does not contain the full message
    #dprint("accessing network for more data")
    pullNextMessage.overflow = []
    while not completeMessage:
        d = conn.recv(BUFFER_SIZE) #pull data from the stream
        if not d: #connection closed
            return ""
        data = str(d, 'ASCII') #convert to string
        #dprint("data in pipeline: " + data)
        for c in list(data):
            if completeMessage:
                pullNextMessage.overflow += [c]
            else:
                resp += [c]
                if c == '*':
                    completeMessage = 1
    return ''.join(resp)
pullNextMessage.overflow = []

#Forces entire message onto the TCP Stream
def sendMessage(m):
    left = len(m)
    while left > 0:
        sent = conn.send(m)
        m = m[sent:]
        left = left - sent

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

#TCP Client implementation
#basic setup from https://wiki.python.org/moin/TcpCommunication
try:
    TCP_IP = args.sa_arg.split(':')[0] #IP part
    dprint("IP: " + TCP_IP)
    TCP_PORT = int(args.sa_arg.split(':')[1]) #Port part
    dprint("Port: " + str(TCP_PORT))
except:
    print("Please use a valid server address and port and try again.")
    exit()
BUFFER_SIZE = 1024 #tunable value
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create the TCP socket

try:
    conn.connect((TCP_IP, TCP_PORT)) #connect to the server

    #Single transaction interaction

    #Authentication Request
    request = "$authreq*"
    sendMessage(bytes(request, 'ASCII'))
    resp = pullNextMessage()
    checkResp(resp)
    challenge_value = resp[1:-1].split(':')[1]
    dprint("Random string: " + challenge_value)
    #MD5 usage from https://docs.python.org/2/library/hashlib.html#module-hashlib
    m = hashlib.md5()
    user = args.user_arg
    args.user_arg = args.user_arg.encode('ASCII')
    args.pass_arg = args.pass_arg.encode('ASCII')
    m.update(args.user_arg)
    m.update(args.pass_arg)
    m.update(challenge_value.encode('ASCII'))
    hash = m.hexdigest()
    dprint("hash: " + hash)
    message = "$hashclient:" + hash + ":" + str(args.user_arg, 'ASCII') + "*"
    sendMessage(bytes(message,'ASCII'))
    resp = pullNextMessage()
    checkResp(resp)
    dprint(resp)
    if resp != "$authresp:true*":#authentication failed
        print("Authentication failed. Please try again.")
        conn.close()
        exit()
    #Authenticated
    print("Welcome " + user)
    #Perform transaction
    message = "$reqID*" #get new transaction ID
    sendMessage(bytes(message, 'ASCII'))    
    dprint("Sending: " + message)
    resp = pullNextMessage()
    checkResp(resp)
    dprint("Response: " + resp)
    id = resp[1:-1].split(":")[1]
    message = "$transquery:" + id + ":" + args.action_arg + ":" + str(args.amount_arg) + "*"
    dprint("Sending: " + message)
    sendMessage(bytes(message, 'ASCII'))
    resp = pullNextMessage()
    checkResp(resp)
    dprint("Response: " + resp)
    data = resp[1:-1].split(":")
    if data[1] == "false" or data[1] == "error": #transaction failed
        print("Transaction rejected by server. Please try again. Current balance is " + data[2])
    else:#transaction successful
        print("Transaction completed. Current balance is now " + data[2])

    #Exit connection
    conn.close()
    dprint("Client exiting normally")

except socket.error as e:
    dprint("Error occurred: " + str(e.errno) + ": " + e.strerror)
    if e.errno == 11001:
        print("Please enter a valid server address and port number and try again.")
        exit()
    if e.errno == 10061:
        print("Connection rejected by server. Please check your server address and port number and try again.")
        exit()
    print("Connection with the server has been terminated. Please try again.")