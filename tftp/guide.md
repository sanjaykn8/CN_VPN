To Compile : gcc -O2 -D_WIN32_WINNT=0x0600 -o ftp.exe ftp.c -lws2_32
-----------------------------
Usage
Modify the following variables in the code to fit your requirements:

DIR_OF_FILE: The default folder for TFTP files.
CLIENT_DEF_IP4: The default IP address of the TFTP client.
SERVER_DEF_IP4: The IP address of the TFTP server.
DEF_TIMEOUT: The timeout value for receiving requests.
Run the program.

Follow the interactive menu to start the TFTP server, print the configuration, change the configuration, or exit the program.
