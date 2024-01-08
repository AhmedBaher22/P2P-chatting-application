from pymongo import MongoClient

# Includes database operations
class DB:
    # db initializations
    def __init__(self):
        self.client = MongoClient('mongodb://localhost:27017/')
        self.db = self.client['p2p-chat']
        self.accounts = self.db['accounts']
        self.online_peers = self.db['online_peers']
        self.chat_rooms = self.db['chat_rooms']

    # checks if an account with the username exists
    # the method return True if there is at least one document in the 'accounts' collection with the specified username,
    # indicating that the account already exists. Otherwise, it returns False, indicating that no such account exists.
    def is_account_exist(self, username):
        return self.accounts.count_documents({'username': username}) > 0

    # registers a user
    def register(self, username, password):
        account = {
            "username": username,
            "password": password,
            "currentRoomChatting":None
        }
        self.accounts.insert_one(account)

    # retrieves the password for a given username
    def get_password(self, username):
        user = self.accounts.find_one({"username": username})
        if user:
            return user["password"]
        else:
            return None

    # checks if an account with the username is online
    def is_account_online(self, username):
        return self.online_peers.count_documents({"username": username}) > 0

    # logs in the user
    def user_login(self, username, ip, port):
        online_peer = {
            "username": username,
            "ip": ip,
            "port": port
        }
        self.online_peers.insert_one(online_peer)

    # logs out the user
    def user_logout(self, username):
        self.online_peers.delete_many({"username": username})

    # retrieves the ip address and the port number of the username
    def get_peer_ip_port(self, username):
        user = self.online_peers.find_one({"username": username})
        if user:
            return user["ip"], user["port"]
        else:
            return None, None

    # retrieves a list of online peer usernames
    def get_online_usernames(self):
        online_usernames_list = [peer['username'] for peer in self.online_peers.find({}, {"_id": 0, "username": 1})]
        return online_usernames_list
 # create a new chat room
    def create_new_chat_room(self, chat_room_name, admin_username):
        admin_account = self.accounts.find_one({"username": admin_username})
        if admin_account:
            chat_room = {
                "chatRoomName": chat_room_name,
                "Members": [admin_account],
                "chatUserAdmin": admin_account
            }
            self.chat_rooms.insert_one(chat_room)

    # add a user to a chat room
    def add_user_to_chat_room(self, chat_room_name, username):
        chat_room = self.chat_rooms.find_one({"chatRoomName": chat_room_name})
        user_account = self.accounts.find_one({"username": username})
        if chat_room and user_account:
            if user_account not in chat_room["Members"]:
                chat_room["Members"].append(user_account)
                self.chat_rooms.update_one(
                    {"chatRoomName": chat_room_name},
                    {"$set": {"Members": chat_room["Members"]}}
                )

    # remove a user from a chat room
    def remove_user_from_chat_room(self, chat_room_name, username):
        chat_room = self.chat_rooms.find_one({"chatRoomName": chat_room_name})
        user_account = self.accounts.find_one({"username": username})
        if chat_room and user_account:
            if user_account in chat_room["Members"]:
                chat_room["Members"].remove(user_account)
                self.chat_rooms.update_one(
                    {"chatRoomName": chat_room_name},
                    {"$set": {"Members": chat_room["Members"]}}
                )

    # delete a chat room
    def delete_chat_room(self, chat_room_name):
        self.chat_rooms.delete_one({"chatRoomName": chat_room_name})

    # list all chat rooms
    def list_all_chat_rooms(self):
        return [chat_room["chatRoomName"] for chat_room in self.chat_rooms.find({}, {"_id": 0, "chatRoomName": 1})]

    # checks if a chat room with the given name exists
    def is_group_exist(self, chat_room_name):
        return self.chat_rooms.count_documents({"chatRoomName": chat_room_name}) > 0

    # checks if a user has joined a specific group
    def is_user_in_group(self, username, chat_room_name):
        user_account = self.accounts.find_one({"username": username})
        chat_room = self.chat_rooms.find_one({"chatRoomName": chat_room_name})

        if user_account and chat_room:
            return user_account in chat_room["Members"]
        else:
            return False

    # get a list of members for a specific group
    def get_group_members(self, chat_room_name):
        chat_room = self.chat_rooms.find_one({"chatRoomName": chat_room_name})

        if chat_room:
            return [member["username"] for member in chat_room["Members"]]
        else:
            return []



    # get a list of chat room names that the user has joined
    def get_user_chatrooms(self, username):
        user_account = self.accounts.find_one({"username": username})
        if user_account:
            user_chatrooms = self.chat_rooms.find({"Members": user_account}, {"_id": 0, "chatRoomName": 1})
            return [chatroom["chatRoomName"] for chatroom in user_chatrooms]
        else:
            return []

    def user_chat_in_room(self, username, new_group):
        # Find the document with the specified username
        user = self.accounts.find_one({"username": username})
        group_chat = self.chat_rooms.find_one({"chatRoomName": new_group})
        if user and group_chat:
            # Update the 'group' attribute in the document
            return self.accounts.update_one({"username": username}, {"$set": {"currentRoomChatting": new_group}})
        else:
            return None

    def user_leave_chatting_in_room(self, username):
        # Find the document with the specified username
        user = self.accounts.find_one({"username": username})
        if user:
            # Update the 'group' attribute in the document
            return self.accounts.update_one({"username": username}, {"$set": {"currentRoomChatting": None}})
        else:
            return None

    def get_current_chatting_members(self, chat_room_name):
        members = self.accounts.find({"currentRoomChatting": chat_room_name})
        return [member["username"] for member in members]

    def count_online_users(self):
        return self.online_peers.count_documents({})