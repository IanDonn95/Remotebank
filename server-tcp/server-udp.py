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

#Gets the next UDP message. Format taken from server-tcp to increase code reuse
def pullNextMessage():
   return conn.recvfrom(BUFFER_SIZE)

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

#UDP Server implementation
#basic setup from https://wiki.python.org/moin/UdpCommunication
UDP_IP = '127.0.0.1' #self
UDP_PORT = args.port_arg #from command line
if UDP_PORT < 0 or UDP_PORT > 65535:
    print("Please enter a valid port number and try again.")
    exit()
BUFFER_SIZE = 512 #tunable value

conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #UDP Socket
conn.bind((UDP_IP, UDP_PORT)) #bind to user-input port

connections = {} #active connection dictionary (mapped by src)
while 1:
    try:
        resp = pullNextMessage()
        data = str(resp[0], 'ASCII')
        dprint("Datagram Received: " + data)
        dprint("Source: " + str(resp[1][0]) + ":" + str(resp[1][1]))

        if (resp[1] not in connections.keys()): #new connection
            connections[resp[1]] = [0,"",{},-1]#unauthenticated, unset user, no transaction ids at start,no current challenge value
        
        authenticated = connections[resp[1]][0] #pull authentication status from connection list
        user = connections[resp[1]][1] #pull user account from connection list
        current_rand = connections[resp[1]][3] #pull most recent challenge value from connection list
        
        #semi-stateless messaging responses

        if data == "$authreq*": #handle Authentication Request
            current_rand = id_generator()
            connections[resp[1]][3] = current_rand #attach challenge_value to connection
            message = "$challenge:" + current_rand + "*"
            dprint("Sending: " + message)
            conn.sendto(bytes(message, 'ASCII'), resp[1])

        if data[:12] == "$hashclient:": #handle Hash Pass
            d = data[1:-1].split(':')
            dprint("Hash from client:" + d[1])
            if len(d) != 3:
                message = "$authresp:false*"#authentication failed by nature of a bad client response
                dprint("Bad client response")
                conn.sendto(bytes(message, 'ASCII'), resp[1])
                current_rand = -1#invalidate challenge_value
                continue
            #MD5 usage from https://docs.python.org/2/library/hashlib.html#module-hashlib
            m = hashlib.md5()
            if not (d[2] in accounts.keys()):
                message = "$authresp:false*"#authentication failed by nature of a bad username
                dprint("Bad username")
                conn.sendto(bytes(message, 'ASCII'), resp[1])
                current_rand = -1#invalidate challenge_value
                connections[resp[1]][3] = current_rand
                continue
            m.update(d[2].encode('ASCII'))#add username to hash
            m.update(accounts[d[2]][0].encode('ASCII'))#add password to hash
            m.update(current_rand.encode('ASCII'))#add challenge_value to hash
            hash = m.hexdigest()
            dprint("Correct Hash: " + hash)
            if hash != d[1]:#hashes do not match
                message = "$authresp:false*"#authentication failed by nature of a bad hash (wrong password)
                dprint("Bad hash/password")
                conn.sendto(bytes(message, 'ASCII'), resp[1])
                current_rand = -1#invalidate challenge_value
                connections[resp[1]][3] = current_rand
                continue
            #hash is validated, client is authenticated
            authenticated = 1
            connections[resp[1]][0] = 1 #authenticate connection
            user = d[2]
            connections[resp[1]][1] = user #attach user to connection
            message = "$authresp:true*"#authentication failed by nature of a bad username
            dprint("Client Authenticated")
            conn.sendto(bytes(message, 'ASCII'), resp[1])
            current_rand = -1
            connections[resp[1]][3] = current_rand

        if data == "$reqID*": #handle transaction ID request
            if not authenticated:
                message = "$authresp:false*" #User is unauthenticated, so reject the request
                dprint("Client attempted transaction before authentication")
                conn.sendto(bytes(message, 'ASCII'), resp[1])
                dprint("Sending: " + message)
                continue
            id = id_generator() #generate new id; 2^64 combinations, so statistically unlikely to have collisions
            connections[resp[1]][2][id] = 0 #save transaction id with unused state
            message = "$idpass:" + id + "*"
            dprint("Sending: " + message)
            conn.sendto(bytes(message, 'ASCII'), resp[1])
            
        if data[:12] == "$transquery:": #Handle the actual transaction
            if not authenticated:
                message = "$authresp:false*" #User is unauthenticated, so reject the transaction
                dprint("Client attempted transaction before authentication")
                dprint("Sending: " + message)
                conn.sendto(bytes(message, 'ASCII'), resp[1])
                continue
            d = data[1:-1].split(":")
            if len(d) != 4: #Bad format response
                message = "$transresult:error:" + str(accounts[user][1]) + ":" + "0" + "*" #transID is "0" because the response is bad
                dprint("Sending: " + message)
                conn.sendto(bytes(message, 'ASCII'), resp[1])
                continue
            if not (d[1] in connections[resp[1]][2]): #invalid ID, so reject the transaction
                message = "$transresult:false:" + str(accounts[user][1]) + ":" + d[1] + "*"
                dprint("Sending: " + message)
                conn.sendto(bytes(message, 'ASCII'), resp[1])
                continue
            if connections[resp[1]][2][d[1]]: #already-used ID, so transmitt the results of the transaction
                message = "$transresult:true:" + str(accounts[user][1]) + ":" + d[1] + "*"
                dprint("Sending: " + message)
                conn.sendto(bytes(message, 'ASCII'), resp[1])
                continue
            try:
                if d[2] == "withdraw":
                    accounts[user] = (accounts[user][0], accounts[user][1] - float(d[3]))#allow overdrafts so we can charge the user more later!
                else:
                    if d[2] == "deposit":
                        accounts[user] = (accounts[user][0], accounts[user][1] + float(d[3]))#deposit
                    else:
                        message = "$transresult:error:" + str(accounts[user][1]) + ":" + d[1] + "*"
                        dprint("Sending: " + message)
                        conn.sendto(bytes(message, 'ASCII'), resp[1])
                        continue
                connections[resp[1]][2][d[1]] = 1 #switch transaction ID to used state
                message = "$transresult:true:" + str(accounts[user][1]) + ":" + d[1] + "*"
                dprint("Sending: " + message)
                conn.sendto(bytes(message, 'ASCII'), resp[1])
            except ValueError:
                #Client using unofficial code that doesn't do input checking, reject nonfloaty data!
                message = "$transresult:error:" + str(accounts[user][1]) + ":" + d[1] + "*"
                dprint("Sending: " + message)
                conn.sendto(bytes(message, 'ASCII'), resp[1])
                continue
    except socket.error as e:
        dprint("Error occurred: " + str(e.errno) + ": " + e.strerror)
        pass

#Unreachable code
dprint("ERROR. UNREACHABLE CODE REACHED")