'''
    ##  Implementation of peer
    ##  Each peer has a client and a server side that runs on different threads
    ##  150114822 - Eren Ulaş
'''
import hashlib
from socket import *
import threading
import time
import select
import logging
from colorama import Fore, Style

# Server side of peer
class PeerServer(threading.Thread):


    # Peer server initialization
    def __init__(self, username, peerServerPort):
        threading.Thread.__init__(self)
        # keeps the username of the peer
        self.username = username
        # tcp socket for peer server
        self.tcpServerSocket = socket(AF_INET, SOCK_STREAM)
        # port number of the peer server
        self.peerServerPort = peerServerPort
        # if 1, then user is already chatting with someone
        # if 0, then user is not chatting with anyone
        self.isChatRequested = 0
        # keeps the socket for the peer that is connected to this peer
        self.connectedPeerSocket = None
        # keeps the ip of the peer that is connected to this peer's server
        self.connectedPeerIP = None
        # keeps the port number of the peer that is connected to this peer's server
        self.connectedPeerPort = None
        # online status of the peer
        self.isOnline = True
        # keeps the username of the peer that this peer is chatting with
        self.chattingClientName = None
        #if requester waits a chat request response from peer server
        self.waitingResponse=0

        self.serverChattingClients = []

    def setServerChattingClients(self, arrayOfClients):
        self.serverChattingClients.append(arrayOfClients)


    # main method of the peer server thread
    def run(self):

        print(f"{Fore.GREEN}Peer server started...")

        # gets the ip address of this peer
        # first checks to get it for windows devices
        # if the device that runs this application is not windows
        # it checks to get it for macos devices
        hostname=gethostname()
        try:
            self.peerServerHostname=gethostbyname(hostname)
        except gaierror:
            import netifaces as ni
            self.peerServerHostname = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']

        # ip address of this peer
        #self.peerServerHostname = 'localhost'
        # socket initializations for the server of the peer

        self.tcpServerSocket.bind((self.peerServerHostname, self.peerServerPort))


        self.tcpServerSocket.listen(4)
        # inputs sockets that should be listened
        inputs = [self.tcpServerSocket]
        # server listens as long as there is a socket to listen in the inputs list and the user is online
        while inputs and self.isOnline:
            # monitors for the incoming connections
            try:
                readable, writable, exceptional = select.select(inputs, [], [])
                # If a server waits to be connected enters here
                for s in readable:
                    # if the socket that is receiving the connection is 
                    # the tcp socket of the peer's server, enters here
                    if s is self.tcpServerSocket:
                        # accepts the connection, and adds its connection socket to the inputs list
                        # so that we can monitor that socket as well
                        connected, addr = s.accept()
                        connected.setblocking(0)
                        inputs.append(connected)
                        # if the user is not chatting, then the ip and the socket of
                        # this peer is assigned to server variables
                        if self.isChatRequested == 0:     
                            print(self.username + " is connected from " + str(addr))
                            self.connectedPeerSocket = connected
                            self.connectedPeerIP = addr[0]
                    # if the socket that receives the data is the one that
                    # is used to communicate with a connected peer, then enters here
                    else:
                        # message is received from connected peer
                        messageReceived = s.recv(1024).decode()
                        # logs the received message
                        logging.info("Received from " + str(self.connectedPeerIP) + " -> " + str(messageReceived))
                        # if message is a request message it means that this is the receiver side peer server
                        # so evaluate the chat request
                        if len(messageReceived) > 11 and messageReceived[:12] == "CHAT-REQUEST":
                            # text for proper input choices is printed however OK or REJECT is taken as input in main process of the peer
                            # if the socket that we received the data belongs to the peer that we are chatting with,
                            # enters here
                            if s is self.connectedPeerSocket:
                                # parses the message
                                messageReceived = messageReceived.split()
                                # gets the port of the peer that sends the chat request message
                                self.connectedPeerPort = int(messageReceived[1])
                                # gets the username of the peer sends the chat request message
                                self.chattingClientName = messageReceived[2]
                                #indicates that there is a request is waiting to response
                                self.waitingResponse = 1
                                # prints prompt for the incoming chat request
                                print(Fore.YELLOW+"NOTIFICATION: Incoming chat request from " + self.chattingClientName + " >> ")
                                print(Fore.YELLOW+"Enter OK to accept or REJECT to reject:  ")

                                # makes isChatRequested = 1 which means that peer is chatting with someone
                                self.isChatRequested = 1
                            # if the socket that we received the data does not belong to the peer that we are chatting with
                            # and if the user is already chatting with someone else(isChatRequested = 1), then enters here
                            elif s is not self.connectedPeerSocket and self.isChatRequested == 1:
                                # sends a busy message to the peer that sends a chat request when this peer is 
                                # already chatting with someone else
                                message = "BUSY"
                                s.send(message.encode())
                                # remove the peer from the inputs list so that it will not monitor this socket
                                inputs.remove(s)

                        elif messageReceived.startswith("CHAT_IN_ROOM"):
                            self.isChatRequested = 1
                            messageReceived = messageReceived.split(" ")
                            self.serverChattingClients.append([messageReceived[1], int(messageReceived[2])])
                            print(
                                messageReceived[4] + f"{messageReceived[3]} joined the chat room" + Fore.LIGHTBLACK_EX)

                        elif messageReceived.startswith("LEAVE-CHATTING_IN-ROOM"):
                            messageReceived = messageReceived.split(" ")
                            for index, client in reversed(list(enumerate(self.serverChattingClients))):
                                if client[0] == messageReceived[1] and client[1] == int(messageReceived[2]):
                                    del self.serverChattingClients[index]
                            print(messageReceived[4] + f"{messageReceived[3]} left the chat room" + Fore.LIGHTBLACK_EX)
                        # if an OK message is received then ischatrequested is made 1 and then next messages will be
                        # shown to the peer of this server
                        # if an OK message is received then ischatrequested is made 1 and then next messages will be shown to the peer of this server

                        elif messageReceived == "OK":
                            self.isChatRequested = 1
                        # if an REJECT message is received then ischatrequested is made 0 so that it can receive any other chat requests
                        elif messageReceived == "REJECT":
                            self.isChatRequested = 0
                            inputs.remove(s)
                        # if a message is received, and if this is not a quit message ':q' and 
                        # if it is not an empty message, show this message to the user
                        elif messageReceived[:2] != ":q" and len(messageReceived) != 0:
                            if "#%#" in str(messageReceived):
                                messageReceived = messageReceived.split("#%#")
                                print(messageReceived[2] + messageReceived[0] + ": " + messageReceived[
                                    1] + Fore.CYAN)
                            else:
                                print(
                                    Fore.LIGHTGREEN_EX+Fore.CYAN + self.chattingClientName + ": " + messageReceived + Fore.LIGHTBLACK_EX)


                        elif messageReceived[:2] != ":q" and len(messageReceived)!= 0:
                            print(self.chattingClientName + ": " + messageReceived)
                        # if the message received is a quit message ':q',
                        # makes ischatrequested 1 to receive new incoming request messages
                        # removes the socket of the connected peer from the inputs list
                        elif messageReceived[:2] == ":q":
                            self.isChatRequested = 0
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                            # connected peer ended the chat
                            if len(messageReceived) == 2 :
                                print("User you're chatting with ended the chat")
                                print("Press enter to quit the chat: ")
                        # if the message is an empty one, then it means that the
                        # connected user suddenly ended the chat(an error occurred)
                        elif len(messageReceived) == 0 and self.chattingClientName != None:
                            self.isChatRequested = 0
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)

                            print("User you're chatting with suddenly ended the chat")
                            print("Press enter to quit the chat: ")
                        elif len(messageReceived) == 0:
                            self.isChatRequested = 0
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)

            # handles the exceptions, and logs them
            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))
            except ValueError as vErr:
                logging.error("ValueError: {0}".format(vErr))
            

# Client side of peer
class PeerClient(threading.Thread):
    # variable initializations for the client side of the peer
    def __init__(self, ipToConnect, portToConnect, username, peerServer, responseReceived):
        threading.Thread.__init__(self)
        # keeps the ip address of the peer that this will connect
        self.ipToConnect = ipToConnect
        # keeps the username of the peer
        self.username = username
        # keeps the port number that this client should connect
        self.portToConnect = portToConnect
        # client side tcp socket initialization
        self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
        # keeps the server of this client
        self.peerServer = peerServer
        # keeps the phrase that is used when creating the client
        # if the client is created with a phrase, it means this one received the request
        # this phrase should be none if this is the client of the requester peer
        self.responseReceived = responseReceived
        # keeps if this client is ending the chat or not
        self.isEndingChat = False
        self.clientChattingClients = []


    # main method of the peer client thread

    def setChattingClients(self, peerServers):
        self.clientChattingClients.append(peerServers)


    def updateClients(self, socketsArray):
        if len(self.clientChattingClients) == len(self.peerServer.serverChattingClients):
            for index in range(len(self.clientChattingClients)):
                if self.clientChattingClients[index] != self.peerServer.serverChattingClients[index]:
                    self.clientChattingClients.clear()
                    for chatting_client in self.peerServer.serverChattingClients:
                        self.setChattingClients(chatting_client)
                    socketsArray.clear()
                    for server in self.clientChattingClients:
                        if not(server[0] == self.peerServer.peerServerHostname and server[1] == self.peerServer.peerServerPort):
                            socketsArray.append(socket(AF_INET, SOCK_STREAM))
                            socketsArray[-1].connect((server[0], server[1]))
                            break
        else:
            self.clientChattingClients.clear()
            for chatting_client in self.peerServer.serverChattingClients:
                self.setChattingClients(chatting_client)
            socketsArray.clear()
            for server in self.clientChattingClients:
                if not(server[0] == self.peerServer.peerServerHostname and server[1] == self.peerServer.peerServerPort):
                    socketsArray.append(socket(AF_INET, SOCK_STREAM))
                    socketsArray[-1].connect((server[0], server[1]))

    def run(self):
        print(Fore.GREEN+"Peer client started...")
        # connects to the server of other peer
        self.tcpClientSocket.connect((self.ipToConnect, self.portToConnect))
        # if the server of this peer is not connected by someone else and if this is the requester side peer client then enters here
        if self.peerServer.isChatRequested == 0 and self.responseReceived is None:
            # composes a request message and this is sent to server and then this waits a response message from the server this client connects
            requestMessage = "CHAT-REQUEST " + str(self.peerServer.peerServerPort)+ " " + self.username
            # logs the chat request sent to other peer
            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + requestMessage)
            # sends the chat request
            self.tcpClientSocket.send(requestMessage.encode())
            print("Request message " + requestMessage + " is sent...")
            # received a response from the peer which the request message is sent to
            self.responseReceived = self.tcpClientSocket.recv(1024).decode()
            # logs the received message
            logging.info("Received from " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + self.responseReceived)
            print("Response is " + self.responseReceived)
            # parses the response for the chat request
            self.responseReceived = self.responseReceived.split()
            # if response is ok then incoming messages will be evaluated as client messages and will be sent to the connected server
            if self.responseReceived[0] == "OK":
                # changes the status of this client's server to chatting
                self.peerServer.isChatRequested = 1
                # sets the server variable with the username of the peer that this one is chatting
                self.peerServer.chattingClientName = self.responseReceived[1]
                # as long as the server status is chatting, this client can send messages
                while self.peerServer.isChatRequested == 1:
                    # message input prompt
                    messageSent = input("")
                    # sends the message to the connected peer, and logs it
                    self.tcpClientSocket.send(messageSent.encode())
                    logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + messageSent)
                    # if the quit message is sent, then the server status is changed to not chatting
                    # and this is the side that is ending the chat
                    if messageSent == ":q":
                        self.peerServer.isChatRequested = 0
                        self.isEndingChat = True
                        break
                # if peer is not chatting, checks if this is not the ending side
                if self.peerServer.isChatRequested == 0:
                    if not self.isEndingChat:
                        # tries to send a quit message to the connected peer
                        # logs the message and handles the exception
                        try:
                            self.tcpClientSocket.send(":q ending-side".encode())
                            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> :q")
                        except BrokenPipeError as bpErr:
                            logging.error("BrokenPipeError: {0}".format(bpErr))
                    # closes the socket
                    self.responseReceived = None
                    self.tcpClientSocket.close()
            # if the request is rejected, then changes the server status, sends a reject message to the connected peer's server
            # logs the message and then the socket is closed       
            elif self.responseReceived[0] == "REJECT":
                self.peerServer.isChatRequested = 0
                print(Fore.RED+"REJECT TO START CHAT, client of requester is closing...")
                self.tcpClientSocket.send("REJECT".encode())
                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> REJECT")
                self.tcpClientSocket.close()
            # if a busy response is received, closes the socket
            elif self.responseReceived[0] == "BUSY":
                print("Receiver peer is busy")
                self.tcpClientSocket.close()
            else:
                self.peerServer.isChatRequested = 0
                print(Fore.RED+"Unknown Response from the requester, client of requester is closing...")
                self.tcpClientSocket.send("REJECT".encode())
                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> REJECT")
                self.tcpClientSocket.close()
        # if the client is created with OK message it means that this is the client of receiver side peer
        # so it sends an OK message to the requesting side peer server that it connects and then waits for the user inputs.
        elif self.responseReceived == "OK":
            # server status is changed
            self.peerServer.isChatRequested = 1
            # ok response is sent to the requester side
            okMessage = "OK"
            self.tcpClientSocket.send(okMessage.encode())
            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + okMessage)
            print(Fore.GREEN+"Client with OK message is created... and sending messages")
            # client can send messsages as long as the server status is chatting
            while self.peerServer.isChatRequested == 1:
                # input prompt for user to enter message
                messageSent = input("")
                self.tcpClientSocket.send(messageSent.encode())
                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + messageSent)
                # if a quit message is sent, server status is changed
                if messageSent == ":q":
                    self.peerServer.isChatRequested = 0
                    self.isEndingChat = True
                    break
            # if server is not chatting, and if this is not the ending side
            # sends a quitting message to the server of the other peer
            # then closes the socket
            if self.peerServer.isChatRequested == 0:
                if not self.isEndingChat:
                    self.tcpClientSocket.send(":q ending-side".encode())
                    logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> :q")
                self.responseReceived = None
                self.tcpClientSocket.close()

        elif self.responseReceived == "CHAT-ROOM":
            self.peerServer.isChatRequested = True
            self.isEndingChat = False
            socketsArray = []

            self.updateClients(socketsArray)

            for server in self.clientChattingClients:
                if not(server[0] == self.peerServer.peerServerHostname and server[1] == self.peerServer.peerServerPort):
                    socketsArray.append(socket(AF_INET, SOCK_STREAM))
                    socketsArray[-1].connect((server[0], server[1]))
                    message = "CHAT_IN_ROOM " + self.peerServer.peerServerHostname + " " + str(
                        self.peerServer.peerServerPort) + " " + self.username + " "
                    socketsArray[-1].send(message.encode())

            while not self.isEndingChat:
                print(Fore.LIGHTBLACK_EX, end="")
                # message input prompt
                messageSent = input(Fore.LIGHTBLACK_EX)
                self.updateClients(socketsArray)

                if messageSent == ":q":
                    for socketElement in socketsArray:
                        try:
                            self.isEndingChat = True
                            self.peerServer.isChatRequested = 0
                            message = "LEAVE-CHATTING_IN-ROOM " + self.peerServer.peerServerHostname + " " + str(
                                self.peerServer.peerServerPort) + " " + self.username  + " "
                            socketElement.send(message.encode())
                            socketElement.close()
                            self.peerServer.serverChattingClients.clear()

                        except BrokenPipeError:
                            pass
                    socketsArray.clear()
                    registryName = gethostbyname(gethostname())
                    registryPort = 15600
                    tcpClientSocket1 = socket(AF_INET, SOCK_STREAM)
                    tcpClientSocket1.connect((registryName, registryPort))

                    message = "LEAVE-CHATTING_IN-ROOM " + self.username
                    tcpClientSocket1.send(message.encode())

                    tcpClientSocket1.close()
                    return
                else:
                    for socketElement in socketsArray:
                        try:
                            socketElement.send((self.username + "#%#" + messageSent + "#%#").encode())
                        except ConnectionError as e:
                            print(Fore.RED + f"Connection error: {e}")
                            print(Fore.LIGHTBLACK_EX, end="")
                        except Exception as ex:
                            print(Fore.RED + f"An error occurred: {ex}")
                            print(Fore.LIGHTBLACK_EX, end="")

                # if the quit message is sent, then the server status is changed to not chatting
                # and this is the side that is ending the chat
            # closes the socket
            for socketElement in socketsArray:
                socketElement.close()
                socketsArray.remove(socketElement)
            self.responseReceived = None
            self.tcpClientSocket.close()

# main process of the peer
class peerMain:

    # peer initializations
    def __init__(self):
        # ip address of the registry
        self.registryName = gethostbyname(gethostname())
        #self.registryName = 'localhost'
        # port number of the registry
        self.registryPort = 15600
        # tcp socket connection to registry
        self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
        self.tcpClientSocket.connect((self.registryName,self.registryPort))
        # initializes udp socket which is used to send hello messages
        self.udpClientSocket = socket(AF_INET, SOCK_DGRAM)
        # udp port of the registry
        self.registryUDPPort = 15500
        # login info of the peer
        self.loginCredentials = (None, None)
        # online status of the peer
        self.isOnline = False
        # server port number of this peer
        self.peerServerPort = None
        # server of this peer
        self.peerServer = None
        # client of this peer
        self.peerClient = None
        # timer initialization
        self.timer = None
        
        choice = "0"
        # log file initialization
     #   logging.basicConfig(filename="peer.log", level=logging.INFO)
        remainInregisterFlag=0
        remainInLoginFLag=0
        loginFlag=0
        # as long as the user is openning the program
        while True:

            if loginFlag == 0:
                if remainInregisterFlag == 0 and remainInLoginFLag == 0:
                    print(f'{Fore.GREEN}WELCOME TO OUR P2P CHATTING APPLICATION')
                    choice = input(F"{Fore.BLUE}Choose: \nCreate account: 1\nLogin: 2\n")


                # if choice is 1, creates an account with the username
                # and password entered by the user
                if choice == "1":
                    print(f'{Fore.GREEN} enter required data for regestering: ')
                    username = input(f"{Fore.YELLOW}username: ")
                    password = input(f"{Fore.YELLOW}password: ")
                    confirmpassword = input(f"{Fore.YELLOW}confirm password: ")
                    #check if the password is trong
                    if  not self.is_strong_password(password):
                        print(f"{Fore.RED}Error(password not strong): password should be at least 8 characters with at least one uppercase character , a number and a special charater ")
                        continue
                    #check password match the confirm password
                    if password != confirmpassword:
                        print(f"{Fore.RED}Error:  passwords are not matched ")
                        continue
                    hashed_password=self.hash_password(password)
                    response=self.createAccount(username, hashed_password)

                    if response == "join-exist":
                        remainInregisterFlag=1
                        continue
                    choice="0"
                    remainInregisterFlag = 0
                # if choice is 2 and user is not logged in, asks for the username
                # and the password to login
                elif choice == "2" and not self.isOnline:
                    username = input(f"{Fore.YELLOW}username: ")
                    password = input(f"{Fore.YELLOW}password: ")
                    # asks for the port number for server's tcp socket
                    while 1:
                        try:
                            peerServerPort = int(input(f"{Fore.YELLOW}Enter a port number for peer server: "))

                            if peerServerPort >= 0 and peerServerPort <= 65535:
                                break
                            else:
                                print(f"{Fore.RED}ERROR, port must be 0-65535.")
                        except ValueError:
                            print(f"{Fore.RED}Please enter a valid integer.")


                    hashed_password = self.hash_password(password)
                    status = self.login(username, hashed_password, peerServerPort)
                    # is user logs in successfully, peer variables are set
                    if status != 1:
                        remainInLoginFLag=1
                    if status == 1:
                        loginFlag = 1
                        remainInLoginFLag=0
                        self.isOnline = True
                        self.loginCredentials = (username, password)
                        self.peerServerPort = peerServerPort
                        # creates the server thread for this peer, and runs it
                        self.peerServer = PeerServer(self.loginCredentials[0], self.peerServerPort)
                        self.peerServer.start()
                        # hello message is sent to registry
                        self.sendHelloMessage()
                else:
                    print(f'{Fore.RED}invalid input pressed, please enter one from only options (1 or 2) ')
                    continue
            elif loginFlag == 1:
                print(f"{Fore.GREEN}WELCOME BACK{Style.BRIGHT}")
                # menu selection prompt
                choice = input(f"{Fore.BLUE}Choose: \nLogout: 3\nSearch: 4\nStart a chat: 5\nList online users: 6\nCreate chat Room:7\nJoin chat Room:8\nchat in chat Room:9\nList chat Rooms and Members:10\nEXIT CHAT ROOM:11\n")
                while (self.peerServer.waitingResponse == 1) and (not((choice == "OK") or (choice == "REJECT"))):
                    choice = input(Fore.RED+"Invalid response entered,please type \"OK\" to accept or \"REJECT\" to refuse:")

                # if choice is 3 and user is logged in, then user is logged out
                # and peer variables are set, and server and client sockets are closed
                if choice == "3" and self.isOnline:
                    self.logout(1)
                    choice = "0"
                    loginFlag = 0
                    self.isOnline = False
                    self.loginCredentials = (None, None)
                    self.peerServer.isOnline = False
                    self.peerServer.tcpServerSocket.close()

                    if self.peerClient is not None:
                        self.peerClient.tcpClientSocket.close()
                    print("Logged out successfully")
                    peerMain()
                    break
                # is peer is not logged in and exits the program
                elif choice == "3":
                    self.logout(2)
                # if choice is 4 and user is online, then user is asked
                # for a username that is wanted to be searched
                elif choice == "4" and self.isOnline:
                    username = input("Username to be searched: ")
                    if username == "":
                        print(f"{Fore.RED}ERROR: empty input!")
                        continue
                    searchStatus = self.searchUser(username)
                    # if user is found its ip address is shown to user
                    if searchStatus != None and searchStatus != 0:
                        print("IP address of " + username + " is " + searchStatus)
                # if choice is 5 and user is online, then user is asked
                # to enter the username of the user that is wanted to be chatted
                elif choice == "5" and self.isOnline:
                    username = input("Enter the username of user to start chat: ")
                    if username == "":
                        print(Fore.RED+"Empty input")
                        continue
                    if username == self.loginCredentials[0]:
                        print(Fore.RED+"Error: You can't chat with yourself, please enter a valid name")
                        continue
                    searchStatus = self.searchUser(username)
                    # if searched user is found, then its ip address and port number is retrieved
                    # and a client thread is created
                    # main process waits for the client thread to finish its chat
                    if searchStatus != None and searchStatus != 0:
                        searchStatus = searchStatus.split(":")
                        self.peerClient = PeerClient(searchStatus[0], int(searchStatus[1]) , self.loginCredentials[0], self.peerServer, None)
                        self.peerClient.start()
                        self.peerClient.join()
                elif choice == "6" and self.isOnline:
                    self.list_online_users()
                #creating a new chat room
                elif choice == "7" and self.isOnline:
                    groupFlag=1
                    while(groupFlag):
                        groupName=input(f"{Fore.YELLOW}Enter the Name of the group chat:")
                        if groupName == "":
                            print(f"{Fore.RED}empty input, you must enter a name")
                            continue
                        creatingGroupResponse=self.createChatGroup(groupName)
                        if creatingGroupResponse == "create-success":
                            groupFlag=0


                #join a chat room
                elif choice == "8" and self.isOnline:
                    joinFlag=1
                    while(joinFlag):
                        groupName=input(f"{Fore.BLUE}enter the chat room name you want to join: ")
                        if groupName == "":
                            print(f"{Fore.RED}empty input, you must enter a name")
                            continue
                        joinRespone=self.addToChatGroup(groupName)
                        joinFlag=0

                #start chatting in a chat room
                elif choice == "9" and self.isOnline:
                    response=self.getUserChatRooms()
                    if response != "USER-NOT-JOINING-GROUPS":
                        while 1 :
                            group=input(f"{Fore.BLUE}enter name of one of your joined chat Rooms:")
                            flagFound=0
                            for g in response:
                                if g == group:
                                    flagFound=1
                                    break
                            if flagFound == 1:
                                self.user_Chatting_in_chat_room(group)
                                break
                            else:
                                print(f"{Fore.RED} invalid group name entered, please choose only one of your group names")
                #list chat rooms and members
                elif choice == "10" and self.isOnline:
                    listresponse=self.listChatRooms()

                    while listresponse != "NO_CHAT_ROOMS":
                        chatRoom=input(f"{Fore.BLUE}Enter chat Room name you want to list it's members (or enter \":q\" to return to main menu):")
                        if chatRoom == ":q":
                            break
                        elif chatRoom == "":
                            print(Fore.RED+"no input entered, please enter name of chatRoom ")
                            continue
                        else:
                            membersResponse=self.listGroupMembers(chatRoom)


                elif choice == "11" and self.isOnline:
                    response=self.getUserChatRooms()
                    if response != "USER-NOT-JOINING-GROUPS":
                        while 1 :
                            group=input(f"{Fore.BLUE}enter name ofchat room you want to exit:")
                            flagFound=0
                            for g in response:
                                if g == group:
                                    flagFound=1
                                    break
                            if flagFound == 1:
                                self.ExitRoom(group)
                                break
                            else:
                                print(f"{Fore.RED} invalid group name entered, please choose only one of your group names")

                # if this is the receiver side then it will get the prompt to accept an incoming request during the main loop
                # that's why response is evaluated in main process not the server thread even though the prompt is printed by server
                # if the response is ok then a client is created for this peer with the OK message and that's why it will directly
                # sent an OK message to the requesting side peer server and waits for the user input
                # main process waits for the client thread to finish its chat
                elif choice == "OK" and self.isOnline and self.peerServer.waitingResponse == 1:
                    self.peerServer.waitingResponse = 0
                    okMessage = "OK " + self.loginCredentials[0]
                    logging.info("Send to " + self.peerServer.connectedPeerIP + " -> " + okMessage)
                    self.peerServer.connectedPeerSocket.send(okMessage.encode())
                    self.peerClient = PeerClient(self.peerServer.connectedPeerIP, self.peerServer.connectedPeerPort , self.loginCredentials[0], self.peerServer, "OK")
                    self.peerClient.start()
                    self.peerClient.join()
                # if user rejects the chat request then reject message is sent to the requester side
                elif choice == "REJECT" and self.isOnline and self.peerServer.waitingResponse == 1:
                    self.peerServer.waitingResponse = 0
                    self.peerServer.connectedPeerSocket.send("REJECT".encode())
                    self.peerServer.isChatRequested = 0
                    logging.info("Send to " + self.peerServer.connectedPeerIP + " -> REJECT")
                # if choice is cancel timer for hello message is cancelled
                elif choice == "CANCEL":
                    self.timer.cancel()
                    break
                else:
                    print(f'{Fore.RED}invalid input pressed, please enter one from only options (3 or 4 or 5 or 6) ')
                    continue
        # if main process is not ended with cancel selection
        # socket of the client is closed
        if choice != "CANCEL":
            self.tcpClientSocket.close()

    # account creation function
    def createAccount(self, username, password):
        # join message to create an account is composed and sent to registry
        # if response is success then informs the user for account creation
        # if response is exist then informs the user for account existence
        message = "JOIN " + username + " " + password
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "join-success":
            print(f"{Fore.GREEN}Account created...")
        elif response == "join-exist":
            print(f"{Fore.RED}user name used before, please choose another username ")
        return response

    # login function
    def login(self, username, password, peerServerPort):
        # a login message is composed and sent to registry
        # an integer is returned according to each response
        message = "LOGIN " + username + " " + password + " " + str(peerServerPort)
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "login-success":
            print(f"{Fore.GREEN}Logged in successfully...")
            return 1
        elif response == "login-account-not-exist":
            print(f"{Fore.RED}Account does not exist...")
            return 0
        elif response == "login-online":
            print(f"{Fore.RED}Account is already online...")
            return 2
        elif response == "login-wrong-password":
            print(f"{Fore.RED}Wrong password...")
            return 3
    
    # logout function
    def logout(self, option):
        # a logout message is composed and sent to registry
        # timer is stopped
        if option == 1:
            message = "LOGOUT " + self.loginCredentials[0]
            self.timer.cancel()
        else:
            message = "LOGOUT"
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        

    # function for searching an online user
    def searchUser(self, username,printFlag=1):
        # a search message is composed and sent to registry
        # custom value is returned according to each response
        # to this search message
        message = "SEARCH " + username
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        if response[0] == "search-success":
            if printFlag:
                print(Fore.GREEN+username + " is found successfully...")
            return response[1]
        elif response[0] == "search-user-not-online":
            if printFlag:
                print(Fore.YELLOW+username + " is not online...")
            return 0
        elif response[0] == "search-user-not-found":
            if printFlag:
                print(Fore.RED+username + " is not found")
            return None
    
    # function for sending hello message
    # a timer thread is used to send hello messages to udp socket of registry
    def sendHelloMessage(self):
        message = "HELLO " + self.loginCredentials[0]
        logging.info("Send to " + self.registryName + ":" + str(self.registryUDPPort) + " -> " + message)
        self.udpClientSocket.sendto(message.encode(), (self.registryName, self.registryUDPPort))
        self.timer = threading.Timer(1, self.sendHelloMessage)
        self.timer.start()

    def hash_password(self,password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return hashed_password
    def is_strong_password(self,password):
        if len(password) < 8:
            return False
        # Check for at least one uppercase letter
        has_uppercase = any(char.isupper() for char in password)

        # Check for at least one digit
        has_digit = any(char.isdigit() for char in password)

        # Check for at least one special character
        special_characters = set("!@#$%^&*(),.?\":{}|<>")
        has_special_char = any(char in special_characters for char in password)

        # Return True if all conditions are met
        return has_uppercase and has_digit and has_special_char
    def list_online_users(self):
        try:
            # Establish a TCP connection with the registry
            # registry_socket = socket(AF_INET, SOCK_STREAM)
            # registry_socket.connect((self.registryName,self.registryPort))
            # Send a request to the registry for online users
            request_message = "GET_ONLINE_USERS"
            self.tcpClientSocket.send(request_message.encode())
            # Receive the response from the registry
            response = self.tcpClientSocket.recv(1024).decode()
            if response.startswith("ONLINE_USERS"):
                # Extract the online users from the response and display them
                online_users = response.split()[1:]
                if len(online_users) >= 2:
                    print(Fore.LIGHTGREEN_EX + "Online Users:")
                    for user in online_users:
                        if user == self.loginCredentials[0]:
                            continue
                        print(user)
                else:
                    print(Fore.RED + "No online users found.")
            else:
                print(Fore.RED + "No online users found.")
            # # Close the socket
            #     self.tcpClientSocket.close()
        except ConnectionError as e:
            print(f"{Fore.RED}Connection error: {e}")
        except Exception as ex:
            print(f"{Fore.RED}An error occurred:{ex}")
    ########new########
    def createChatGroup(self,groupName):
        request_message = "CREATE_CHAT_ROOM "+groupName+" "+self.loginCredentials[0]
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + request_message)
        self.tcpClientSocket.send(request_message.encode())
        # Receive the response from the registry
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "create-success":
            print(f"{Fore.GREEN}Group created successfully...")
        elif response == "group-exist":
            print(f"{Fore.RED}chat room name used before, please choose another name ")
        return response
    def addToChatGroup(self,groupName):
        request_message = "JOIN_GROUP "+groupName+" "+self.loginCredentials[0]
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + request_message)
        self.tcpClientSocket.send(request_message.encode())
        # Receive the response from the registry
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "not-exist":
            print(f"{Fore.RED}chat room name doesn't exist, please choose existing group name ")
        elif response == "already-joined":
            print(f"{Fore.RED}you are already joining this group")
        elif response == "joined-successfully":
            print(f"{Fore.GREEN}joined successfully, you are now a member of group {groupName}")
        return response
    def listChatRooms(self):
        request_message = "LIST_CHAT_ROOMS"
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + request_message)
        self.tcpClientSocket.send(request_message.encode())
        # Receive the response from the registry
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "NO_CHAT_ROOMS":
            print(f"{Fore.RED}No chat rooms Created yet")
            return response
        else:
            chat_groups = response.split()[1:]

            print(Fore.LIGHTGREEN_EX + "Available chat Rooms R:")
            i=1
            for user in chat_groups:
                print(f"{Fore.GREEN}{i}-"+user)
                i+=1
    def listGroupMembers(self,groupName,printFlag=1):
        request_message = "LIST_MEMBERS "+groupName
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + request_message)
        self.tcpClientSocket.send(request_message.encode())
        # Receive the response from the registry
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "not-exist":
            if printFlag:
                print(f"{Fore.RED}chat room name doesn't exist, please choose existing group name ")

        else:
            room_members = response.split()[1:]
            if printFlag:
                print(Fore.LIGHTGREEN_EX + f"Room Admin:{room_members[0]}")
            i=1
            if printFlag:
                print(Fore.LIGHTGREEN_EX + f"Room Members:")
                for user in room_members:
                    if len(room_members) < 2:
                        print(f"{Fore.RED}no other members yet")
                        break
                    if i == 1:
                        i+=1
                        continue
                    print(f"{Fore.GREEN}{i-1}-"+user)
                    i+=1

            if printFlag==0:
                return room_members[1:]
    def getUserChatRooms(self):
        request_message = "GET_USER_CHATROOMS "+self.loginCredentials[0]
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + request_message)
        self.tcpClientSocket.send(request_message.encode())
        # Receive the response from the registry
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "USER-NOT-JOINING-GROUPS":
            print(f"{Fore.RED}you are not joining any chat rooms yet")
            return response
        else :
            room_members = response.split()[1:]
            i=1
            print(f'{Fore.GREEN}choose name of group, you want to start chatting in:')
            for groupName in room_members:
                print(f"{Fore.GREEN}{i}-" + groupName)
                i += 1
            return room_members


    def listGroupMembersChatting(self,groupName):
        request_message = "LIST_MEMBERS_CHATTING "+groupName
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + request_message)
        self.tcpClientSocket.send(request_message.encode())
        # Receive the response from the registry
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        room_members = response.split()[1:]
        print(room_members)
        return room_members

    def user_Chatting_in_chat_room(self, groupName):
        message = "CHAT_IN_ROOM " + self.loginCredentials[0] + " " + groupName
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        if response == "DONE":
            print(Fore.LIGHTGREEN_EX + "Chat room joined...")
            searchStatus = self.searchUser(self.loginCredentials[0], 0)
            # if searched user is found, then its ip address and port number is retrieved
            # and a client thread is created
            # main process waits for the client thread to finish its chat
            if searchStatus is not None and searchStatus != 0:
                searchStatus = searchStatus.split(":")
                self.peerClient = PeerClient(searchStatus[0], int(searchStatus[1]), self.loginCredentials[0],
                                             self.peerServer, "CHAT-ROOM")

                members = self.listGroupMembersChatting(groupName)
                print(members)
                for member in members:
                    searchStatus = self.searchUser(member, 0)
                    if searchStatus is not None and searchStatus != 0:
                        searchStatus = searchStatus.split(":")
                        self.peerClient.setChattingClients([searchStatus[0], int(searchStatus[1])])
                        self.peerClient.peerServer.setServerChattingClients([searchStatus[0], int(searchStatus[1])])

                self.peerClient.start()
                self.peerClient.join()

        elif response == "REJECT":
            print(Fore.RED + "Room doesn't exist...")
    def ExitRoom(self,groupName):
        request_message = "EXIT_GROUP "+groupName+" "+self.loginCredentials[0]
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + request_message)
        self.tcpClientSocket.send(request_message.encode())
        # Receive the response from the registry
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "done":
            print(f"{Fore.YELLOW}you exit group {groupName} successfully")
# peer is started
main = peerMain()