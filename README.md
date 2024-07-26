# Fragmentation-Reassembly-of-IP-packets
A program made to Transfer files wirelessly in Software defined radios,Using the concepts of Fragmentation and Reassembly.Both Client and Server uses a custom file transfer protocol based on TCP connection.
##WORKS ONLY BETWEEN LINUX BASED SYSTEM.
For Linux G++:

-->g++ server.cpp -lpthread -o server

--> ./server

--> g++ client.cpp -o client

--> ./client

>run server and client in seperate terminals.
>change the *ip to the local ip of the machine you are running.
>To change file source change the "file_name" in struct config

MORE FUNCTIONS WILL BE IMPLEMENTED IN THE FUTURE.
