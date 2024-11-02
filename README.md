# Fragmentation-Reassembly-of-IP-packets
A program made to Transfer files wirelessly in Software defined radios,Using the concepts of Fragmentation and Reassembly.Both Client and Server uses a custom file transfer protocol based on TCP connection.
**##WORKS ONLY BETWEEN LINUX BASED SYSTEM.**

**Client (client.cpp)**
The client performs the following tasks:

1.File Reading: Reads the file from disk, converting it into hexadecimal format for transmission.

2.Fragmentation: Splits the file into fragments according to the MTU size.

3.Packet Creation: Adds metadata (like sequence ID, fragment length) to each fragment.

4.Transmission: Sends each fragment to the server and waits for confirmation of successful receipt.

5.Connection Handling: Establishes a TCP connection to the server and sends the file fragments.


**Server (server.cpp)**
The server performs the following tasks:

1. Packet Reception: Receives file fragments from the client.

2. Reassembly: Reconstructs the original file by ordering the fragments using sequence IDs.

3. Error Handling: Verifies that fragments are received in the correct sequence and that no corruption occurred during transmission.

4. File Writing: After all fragments are received and reassembled, the file is written to disk in its original format.



**Client Code (client.cpp):**

 - fragment(): Fragments the file into smaller parts for transmission.

 - send_fragment(): Sends each fragment and waits for confirmation.

 - fragment_creater(): Iterates through the file and splits it into smaller fragments.

 - packet_creater(): Reads the file, converts it to hexadecimal, and triggers the fragmentation and transmission process.



**Server Code (server.cpp):**

 - packet_check_reassembler(): Checks if the received packet is valid and reassembles the fragments.

 - recieve_packet(): Receives a fragment, verifies it, and calls the reassembly function.

 - hex2file(): Converts the reassembled hexadecimal data back into binary format and writes it to disk.


**Commands For Linux g++:**
```
g++ server.cpp -lpthread -o server

./server

g++ client.cpp -o client

./client

```
Run server and client in seperate terminals.
Change the *ip to the local ip of the machine you are running.
To change file source change the "file_name" in struct config

MORE FUNCTIONS WILL BE IMPLEMENTED IN THE FUTURE.
