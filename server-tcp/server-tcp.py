import argparse
import socket
import hashlib
import random
import string

#debug print
def dprint(x):
    if args.debug:
        print(x)

#random character string generator from http://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits-in-python
def id_generator(size = 64, chars = string.ascii_uppercase + string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

#Forces entire message onto the TCP Stream
def sendMessage(m):
    left = len(m)
    while left > 0:
        sent = conn.send(m)
        m = m[sent:]
        left = left - sent

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

#argparse use adapted from https://docs.python.org/2/library/argparse.html#module-argparse
parser = argparse.ArgumentParser(description = 'TCP server: port [-d]')
parser.add_argument('port_arg', metavar = 'P', type = int, help = 'port number, example 8591')
parser.add_argument('-d', dest = 'debug', help = 'enable debug messages', action = 'store_const', const = 1, default = 0)
args = parser.parse_args()

#account setup
accounts = {"archer" : ("kanshou", 3000.), "saber" : ("excalibur", 1000.), "gilgamesh" : ("ea", 9000.)}
dprint("Accounts:")
for x in accounts:
    dprint(x + " " + str(accounts[x][0]) + " " + str(accounts[x][1]))

#TCP Server implementation
#basic setup from https://wiki.python.org/moin/TcpCommunication
TCP_IP = '127.0.0.1' #self
TCP_PORT = args.port_arg #from command line
if TCP_PORT < 0 or TCP_PORT > 65535:
    print("Please enter a valid port number and try again.")
    exit()
BUFFER_SIZE = 512 #tunable value

serverBaseSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #TCP Socket
serverBaseSocket.bind((TCP_IP, TCP_PORT)) #bind to user-input port
serverBaseSocket.listen(1) #listen for client connections

transIDs= {} #dictionary of transaction ids. Pass in the id and get back whether it has been used
while 1:
    try:
        pullNextMessage.overflow = [] #clear internal application-level message buffer
        conn, addr = serverBaseSocket.accept() #connect to a user, pay sole attention to the current client and leave the others in queue to connect (no simultaneous multi-user support)
        dprint("Connection address: " + addr[0])
        authenticated = 0
        user = ""
        while(1):
            resp = pullNextMessage()
            if not resp: #connection closed
                dprint("Connection closed by client prematurely")
                break

            dprint("Data received: " + resp)

            #semi-stateless messaging responses

            if resp == "$authreq*":#handle Authentication Request
                current_rand = id_generator()
                message = "$challenge:" + current_rand + "*"
                dprint("Sending: " + message)
                sendMessage(bytes(message, 'ASCII'))

            if resp[:12] == "$hashclient:":#handle Hash Pass
                data = resp[1:-1].split(':')
                dprint("Hash from client:" + data[1])
                if len(data) != 3:
                    message = "$authresp:false*"#authentication failed by nature of a bad client response
                    dprint("Bad client response")
                    sendMessage(bytes(message, 'ASCII'))
                    current_rand = -1#invalidate challenge_value
                    continue
                #MD5 usage from https://docs.python.org/2/library/hashlib.html#module-hashlib
                m = hashlib.md5()
                if not (data[2] in accounts.keys()):
                    message = "$authresp:false*"#authentication failed by nature of a bad username
                    dprint("Bad username")
                    sendMessageMessage(bytes(message, 'ASCII'))
                    current_rand = -1#invalidate challenge_value
                    continue
                m.update(data[2].encode('ASCII'))#add username to hash
                m.update(accounts[data[2]][0].encode('ASCII'))#add password to hash
                m.update(current_rand.encode('ASCII'))#add challenge_value to hash
                hash = m.hexdigest()
                dprint("Correct Hash: " + hash)
                if hash != data[1]:#hashes do not match
                    message = "$authresp:false*"#authentication failed by nature of a bad hash (wrong password)
                    dprint("Bad hash/password")
                    sendMessage(bytes(message, 'ASCII'))
                    current_rand = -1#invalidate challenge_value
                    continue
                #hash is validated, client is authenticated
                authenticated = 1
                user = data[2]
                message = "$authresp:true*"#authentication failed by nature of a bad username
                dprint("Client Authenticated")
                sendMessage(bytes(message, 'ASCII'))
                current_rand = -1

            if resp == "$reqID*":#handle transaction ID request
                if not authenticated:
                    message = "$authresp:false*"#User is unauthenticated, so reject the request
                    dprint("Client attempted transaction before authentication")
                    sendMessage(bytes(message, 'ASCII'))
                    dprint("Sending: " + message)
                    continue
                id = id_generator()#generate new id; 2^64 combinations, so statistically unlikely to have collisions
                transIDs[id] = 0#save transaction id with unused state
                message = "$idpass:" + id + "*"
                sendMessage(bytes(message, 'ASCII'))
                dprint("Sending: " + message)
            
            if resp[:12] == "$transquery:":#Handle the actual transaction
                if not authenticated:
                    message = "$authresp:false*"#User is unauthenticated, so reject the transaction
                    dprint("Client attempted transaction before authentication")
                    dprint("Sending: " + message)
                    sendMessage(bytes(message, 'ASCII'))
                    continue
                data = resp[1:-1].split(":")
                if len(data) != 4:#Bad format response
                    message = "$transresult:error:" + str(accounts[user][1]) + + ":" + "0" + "*" #transID is 0 because the transquery is malformed
                    dprint("Sending: " + message)
                    sendMessage(bytes(message, 'ASCII'))
                    continue
                if not (data[1] in transIDs):#invalid ID, so reject the transaction
                    message = "$transresult:false:" + str(accounts[user][1]) + ":" + data[1] + "*"
                    dprint("Sending: " + message)
                    sendMessage(bytes(message, 'ASCII'))
                    continue
                if transIDs[data[1]]:#already-used ID, so transmit the results of the transaction
                    message = "$transresult:true:" + str(accounts[user][1]) + ":" + data[1] + "*"
                    dprint("Sending: " + message)
                    sendMessage(bytes(message, 'ASCII'))
                    continue
                try:
                    if data[2] == "withdraw":
                        accounts[user] = (accounts[user][0], accounts[user][1] - float(data[3]))#allow overdrafts so we can charge the user more later!
                    else:
                        if data[2] == "deposit":
                            accounts[user] = (accounts[user][0], accounts[user][1] + float(data[3]))#deposit
                        else:
                            message = "$transresult:error:" + str(accounts[user][1]) + + ":" + "0" + "*" #transID is 0 because the transquery is malformed
                            dprint("Sending: " + message)
                            sendMessage(bytes(message, 'ASCII'))
                            continue
                    transIDs[data[1]] = 1#switch transaction ID to used state
                    message = "$transresult:true:" + str(accounts[user][1]) + ":" + data[1] + "*"
                    dprint("Sending: " + message)
                    sendMessage(bytes(message, 'ASCII'))
                except ValueError:
                    #Client using unofficial code that doesn't do input checking, reject nonfloaty data!
                    message = "$transresult:error:" + str(accounts[user][1]) + + ":" + data[1] + "*"
                    dprint("Sending: " + message)
                    sendMessage(bytes(message, 'ASCII'))
                    continue
        conn.close()
    except socket.error as e:
        dprint("Error occurred: " + str(e.errno) + ": " + e.strerror)
        pass

#Unreachable code
dprint("ERROR. UNREACHABLE CODE REACHED")