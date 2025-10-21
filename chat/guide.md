Compile:
gcc -O2 -o server.exe server.c -lws2_32
gcc -O2 -o client.exe client.c -lws2_32

Run:
client.exe -a 127.0.0.1 -p 9000 -u *name*

_________________________________________

### Usage server script 
```bash
./server ## script will run on port 80 by default
./server 90 ## run the script on port 90
```
### Usage client script 
```bash
./client [-h] [-a] [-p] [-u]
 -h           show this help message and exit [optional]
 -a           IP address of the server [localhost if running on local machine] [required]
 -p           port number of the server [required]
 -u           username of the person [required]
```
### Chatroom functionality


| Command       | Parameter             | Desription                          |
| ------------- | --------------------- | ----------------------------------- |
| quit          |                       | Leave the chatroom                  |
| msg           |  "text"               | send the msg to all online users (use"")    |
| msg           |   "text" user         | Send the msg to a particular user              |
| online        |                       | get the username of all the users online                    |
| help          |                       | Show this help                      |


### Server
Each user is handled by a seperate thread in the server.The threads synchronise access to a global linked list 
storing the user information

### Client
When the client connects to the server, it executes a chatroom shell. Each client has 2 running threads one for sending commands and other for receiving msgs, both working in sync with each other.

### TO DO and Contributions
Feel free to contribute and collaborate 
1. Making a testing environment to check for subtle synchronisation bugs
2. Resolving same user-name conflicts
3. adding feature to change user name
4. BUG-: When a user is typing and at the same moment receives a msg in the chatroom