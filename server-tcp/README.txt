Ian Donn	IanDonn95@gatech.edu
CS 3251 B	9/25/2015
Sockets Programming Assignment 1

Files:
remotebank-tcp.py : tcp client
remotebank-udp.py : udp client
server-tcp.py : tcp server
server-udp.pu : udp server
README : this document
Sample.txt : debug output from server-tcp, remotebank-tcp, server-udp and remotebank-udp (in that order); nondebug output is absent on servers and just two messages on clients in optimal runs, so is not included

Compilation and running:
My code is in python and needs no compiling or makefiles
The environment I tested my code on was Windows with Python 3.4.2
I imagine my code may work with the most up to date versions of Python, but if there are troubles with later versions then it's possible something I used was changed in subsequent releases, and so my code would have to be run in legacy 3.4.2.

To run it, just call python <filename.py> <args>

Protocol:
This protocol starts a message with '$' and ends with '*'. For example, "$authreq*"
Fields inside the messsage are delineated with ':'. For example, "&hashclient:<hash>:<username>*"
The client begins by sending an "$authreq*" to the server. The server then creates a challenge value in the form of a random 64 character string, chosen from uppercase and lowercase letters and digits. It sends this value inside a "$challenge:<challenge value>*" message.
After the client receives this value, it computes an MD5 hash using it and the username and password inputs from the user. The client then sends a "$hashclient:<hash>:<username>*" message containing the calculated hash and the username in plain text.
The server takes the hash and username from this message and computes its own MD5 hash using the password on file for that username. If the username is not found or the hash does not match that provided by the client, an "$authresp:false*" message ia sent to the client. Otherwise, the client is authenticated, and an :$authresp:true*" message is sent.
Once the client is authenticated, it can send "$reqID*" messages to the server. If the client sends an "$reqID*" message before authentication, the server responds back with a "$authresp:false*" message reminding the client it needs to authenticate.
Otherwise, the server calculates a new 64-character string, chosen again from uppercase and lowercase letters and digits, and sends this "transaction id" through an "$idpass:<transID>:" message.
The client takes this id and attaches it to a "$transquery:<transID>:<action>:<amount>*" message and sends it to the server. <action> is either "deposit" or "withdraw", depending on what the user wants to do with it. <amount> is a float. If the client is still unathenticated, the server will send an "$authresp:false*" message reminding the client that authentication is actually a necessary step unless they want their money stolen.
If <action> is not valid or <amount> is not a float, a "$transresult:error:<current balance>:<transID>*" message is sent.
If <action> and <amount> are valid, and the (valid) id has not been used before in a valid way, the server will send the client a "$transresult:true:<new balance>:<transID>*" message.
If the id is not one that was provided by the server, the server will instead send a "$transresult:false:<current balance>:<transID>*" message.
If the id is one provided by the server, but the server has marked it as already being used (such as duplicate requests arriving), the server will send a "$transresult:true:<current balance>:<transID>*" message, because the transaction did go through with an earlier request.
The client is free to request additional transaction ids and peform extra transactions with the server during this session if desired, or the client can exit the connection then.

Limitations:
Foremost is the limititation that ':' and '*' cannot be part of the username because that would interfere with protocol's delineation. This is easily controlled by the bank by verifying usernames are acceptable during account creation.
Another possible issue is that the udp server never deletes information tied to old connections that have ended, though many thousands or millions of connections would be required before running out of memory became an issue.