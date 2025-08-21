#include "decrypt_server.cpp"

//g++ server_linuxv6.cpp -o serverv6 -lssl -lcrypto -lgmpxx -lgmp


// # Check firewall status
// sudo ufw status

// # Allow the ports
// sudo ufw allow 8080/tcp
// sudo ufw allow 8080/udp
// sudo ufw allow 8081/tcp

// # Reload firewall
// sudo ufw reload

#define PORT 8080
#define TCP_PORT 8081  // New TCP port for client registration and key exchange
#define BUFFER_SIZE 5000




//map<pair<string,int>,vector<char>> transmission_map;
//// normal diffy helman
//map<pair<string,int>,vector<vector<char>>> transmission_map;

map<pair<string,int>,pair<mpz_class,vector<vector<char>>>> transmission_map;

map<pair<string,int>, int>recv_count;  // keeps a count of receieved fragemetns of each connection ,and based on that if all recieved only then reassembles the file 
//ned to implement if  not all packets recieved the n requeust again for that packet dequence number

// Mutex for thread-safe access to transmission_map
mutex transmission_map_mutex;

struct packet { //----------------------------- HEADER SIZE 19 BYTES------------------------------------

    uint32_t sender_ip;     // 4 bytes (binary format)
    uint32_t receiver_ip;   // 4 bytes (binary format)
    uint16_t length;        // 2 bytes (supports larger files)
    uint16_t sequence_id;   // 2 bytes
    uint16_t total_frags;   // 2 bytes store number of total packets to be sent
    char extension[4];      // 4 bytes
    bool FIN;               // 0 for not finished ,1 for finished
    //uint16_t port;        //network byte port number
    //uint16_t rto;         // 2 bytes (retransmission timeout)
    //uint8_t flags;        // 1 byte (bitmask for fragmentation, payload type etc.)
    char data[BUFFER_SIZE];  // payload  RIGHTNOW 100000 bytes or 10 KB
    //make it outside so just need to store data in retransmission quueu instead of objects of struct
    // now may be object is good for multi threading when multiple servers
};

// Prints an error and exits
void die(const char* message) {
    perror(message);
    exit(EXIT_FAILURE);
}

// New function: TCP server for client registration and key exchange
void tcp_client_handler(int client_socket, struct sockaddr_in client_addr) {
    cout << "[+] TCP: New client connected from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << endl;
    
    // Get client IP and port for transmission_map key
    string client_ip = inet_ntoa(client_addr.sin_addr);
    int client_port = ntohs(client_addr.sin_port);
    auto client_key = make_pair(client_ip, client_port);
    
    // Perform Diffie-Hellman key exchange over TCP
    cout << "[+] TCP: Starting key exchange with client " << client_ip << ":" << client_port << endl;
    mpz_class session_key = server_key(client_socket); // New TCP version of key exchange
    
    // Store client info and session key in transmission_map
    {
        lock_guard<mutex> lock(transmission_map_mutex);
        transmission_map[client_key].first = session_key;
        transmission_map[client_key].second.clear(); // Initialize empty fragment vector
        recv_count[client_key] = 0;
    }
    
    cout << "[+] TCP: Client " << client_ip << ":" << client_port << " registered with session key. Ready for UDP data transmission." << endl;
    
    // TCP work is done, close the connection
    close(client_socket);
    cout << "[+] TCP: Connection closed for client " << client_ip << ":" << client_port << endl;
}

// New function: TCP listener thread
void tcp_listener_thread() {
    int tcp_server_fd;
    struct sockaddr_in tcp_address;
    int opt = 1;
    
    // Create TCP socket
    tcp_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_server_fd < 0) {
        die("TCP socket() failed");
    }
    
    // Set socket options
    if (setsockopt(tcp_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        die("TCP setsockopt() failed");
    }
    
    // Bind TCP socket
    tcp_address.sin_family = AF_INET;
    tcp_address.sin_addr.s_addr = INADDR_ANY;
    tcp_address.sin_port = htons(TCP_PORT);
    
    if (bind(tcp_server_fd, (struct sockaddr*)&tcp_address, sizeof(tcp_address)) < 0) {
        die("TCP bind() failed");
    }
    
    // Listen for connections
    if (listen(tcp_server_fd, 10) < 0) {
        die("TCP listen() failed");
    }
    
    cout << "[+] TCP server listening on port " << TCP_PORT << " for client registration..." << endl;
    
    // Accept clients in loop
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int client_socket = accept(tcp_server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_socket < 0) {
            perror("TCP accept() failed");
            continue;
        }
        
        // Handle each client in a separate thread (or handle synchronously)
        thread client_thread(tcp_client_handler, client_socket, client_addr);
        client_thread.detach(); // Let thread run independently
    }
    
    close(tcp_server_fd);
}

// Sets up the UDP server socket and binds it
int setup_socket() {
    int server_fd;
    int opt = 1;
    struct sockaddr_in address;

    // 1) Create UDP socket (IPv4, UDP)
    server_fd = socket(AF_INET, SOCK_DGRAM, 0);  // Changed to SOCK_DGRAM
    if (server_fd < 0) {
        die("socket() failed");
    }

    // 2) Set SO_REUSEADDR so we can rebind quickly after a crash/restart
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        die("setsockopt() failed");
    }

    // 3) Bind to all interfaces on PORT
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        die("bind() failed");
    }
    cout << "[+] UDP server listening on IP " << inet_ntoa(address.sin_addr) << "...\n";
    cout << "[+] UDP server listening on port " << PORT << "...\n";

    // No listen() needed for UDP - it's connectionless
    return server_fd;
}

// Sends a one‐byte confirmation ("1") back to the client
void send_confirmation(int server_fd, struct sockaddr_in& client_addr) {
    const char confirm = '1';
    socklen_t addr_len = sizeof(client_addr);
    char* ip_str = inet_ntoa(client_addr.sin_addr);
    ssize_t sent = sendto(server_fd, &confirm, 1, 0, 
                         (struct sockaddr*)&client_addr, addr_len);
    if (sent < 0) {
        perror("sendto() failed");
    }
    else{
        cout<<"[+] ACK SENT TO : "<<ip_str<<endl;
    }
}

bool fragment_processor(const char* buffer ,ssize_t bytes_received,int port,string& temp_name,string& temp_ext,bool& recv_flag,string client_ip){

    // if (bytes_received < sizeof(packet)) {
    //     cout << "[-] Received packet too small. Expected: " << sizeof(packet) 
    //          << " bytes, Got: " << bytes_received << " bytes\n";
    //     return false;
    // }
    
    // recast back to packet struct
    const packet* pkt = reinterpret_cast<const packet*>(buffer);

    // Convert network byte order back to host byte order
    uint32_t sender_ip = pkt->sender_ip;      // Already in network order
    uint32_t receiver_ip = pkt->receiver_ip;  // Already in network order
    
    int length = (int)ntohs(pkt->length); 
    uint16_t sequence_id = ntohs(pkt->sequence_id); // Convert from network to host order
    
    int totalfragments=ntohs(pkt->total_frags);
   
    char extension[5];
    strncpy(extension,pkt->extension,4);
    extension[4]='\0'; //eol 
    temp_ext=extension;

    bool fin_flag=pkt->FIN;
    struct in_addr addr;
    addr.s_addr = sender_ip;
    string sender_ip_str = inet_ntoa(addr);
    
    addr.s_addr = receiver_ip;
    string receiver_ip_str = inet_ntoa(addr);

    temp_name=to_string(port);
    // Print packet information
    // cout << "[+] Packet Details:\n";
    // cout << "    Sequence ID: " << sequence_id<<"/"<<totalfragments<< "\n";
    // cout << "    Sender IP: " << sender_ip_str << "\n";
    // cout << "    Receiver IP: " << receiver_ip_str << "\n";
    // cout << "    Data Length: " << length << "\n";
    // cout << "    Extension: " << extension << "\n";
    // cout << "    FIN Flag: " << (fin_flag ? "true" : "false") << "\n";

    if (length > (BUFFER_SIZE)) {//MTU - HEADER_SIZE)
        cout << "[-] Invalid data length: " << length << "\n";
        return false;
    }
    
    // if(length!=strlen(pkt->data))
    //     recv_flag=0;
    //     cout<<"[-] Packet rejected as length not same"<<strlen(pkt->data)<<"     "<<length <<endl;
    //     return false;

    auto key_pair=make_pair(client_ip,port);
    
    // Check if client is registered (key exchange completed via TCP)
    {
        lock_guard<mutex> lock(transmission_map_mutex);
        if (transmission_map.find(key_pair) == transmission_map.end()) {
            cout << "[-] Client " << client_ip << ":" << port << " not registered. Ignoring packet." << endl;
            return false;
        }
    }
    
    auto &vec = transmission_map[key_pair]; // making a auto variable ,to store data as value in it
    
    // vec is  pair mpz,vector<char>

    if (vec.second.empty()) {
        vec.second.resize(totalfragments); // the size of value forkey pair is totalfragemtns .and fragment go int o respective index of value veactor
        recv_count[key_pair] = 0;
    }

    // Extract and store the actual data
    if (length > 0) {
        // transmission_map[key_pair].insert(

        //     transmission_map[key_pair].end(),

        //     pkt->data,
        //     pkt->data + length
        // );
        // at index[sequence] in the transmission map vector
        
        // Key is already set during TCP phase, no need to set again
        if(vec.second[sequence_id-1].empty()){ // checking for duplicate packets 
            vec.second[sequence_id-1].assign(pkt->data,pkt->data + length);
            recv_count[key_pair]++;
        }
        
        //data_stream.insert(data_stream.end(), pkt->data, pkt->data + length);
        //cout << "[+] Added " << length << " bytes to data stream\n";
        recv_flag=1;
    }
    
    // Check if this is the final packet
    if (fin_flag) {
        cout << "[+] Received final packet (FIN=true)\n";
        return true;  // Signal end of transmission
    }
    
    return false;  // Continue receiving
}

// Writes the full byte stream into a file
void reassemble_fragments(const pair<mpz_class, vector<vector<char>>>& byteStream, string temp_name, string temp_ext){

    if (byteStream.second.empty()) {
        cout << "[-] No data received to reassemble.\n";
        return;
    }
    mpz_class session_key=byteStream.first;

    string filename=temp_name+"."+temp_ext;
    ofstream outfile(filename, ios::binary);
    if (!outfile) {
        cerr << "[-] Unable to open " << filename << " for writing.\n";
        return;
    }

    size_t total_size = 0;
    for (const auto& frag : byteStream.second) {
        total_size += frag.size();  // would be more than the actual size beacuase of encryption padding
    }

    vector<char> fulldata;
    fulldata.reserve(total_size);
    // Copy each fragment in order
    for (const auto& frag : byteStream.second) {
        
        //decrypt
        vector<char> temp_decryp;
        temp_decryp = decrypt(session_key,frag);

        fulldata.insert(fulldata.end(),temp_decryp.begin(),temp_decryp.end());
        
    }

    outfile.write(fulldata.data(), fulldata.size());
    outfile.close();
    cout << "[+] File reassembled and saved as \"" << filename << "\" (" 
         << fulldata.size() << " bytes)\n";
}

// Receives data from clients until no more data arrives
void receive_data(int server_fd) {
    char buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    // Set timeout for UDP socket to detect end of transmission
    struct timeval timeout;
    timeout.tv_sec = 1000;  // 10 second timeout
    timeout.tv_usec = 0;
    setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // No key exchange here anymore - keys are exchanged via TCP
    cout << "[+] Waiting for UDP packets...\n";
    
    while (true) {     
        ssize_t bytesReceived = recvfrom(server_fd, buffer, BUFFER_SIZE, 0,
                                        (struct sockaddr*)&client_addr, &addr_len);  // will this only accept one packet ot full 5000 bytes check <<<<<<<<<<<<<<<<<<
        
        if (bytesReceived < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                // Timeout occurred - assume no more data
                cout << "[+] Timeout reached. No more data expected.\n";
                break;
            } else {
                perror("recvfrom() failed");
                break;
            }
        }
        
        if (bytesReceived == 0) {
            // This shouldn't happen with UDP, but handle it just in case
            cout << "[+] No data received.\n";
            break;
        }
        string ip_str = inet_ntoa(client_addr.sin_addr);
        int port = ntohs(client_addr.sin_port);

        // Log received packet
        cout << "[+] Received " << bytesReceived << " bytes from "
             << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "\n";

        string temp_name;
        string temp_ext;
        bool recv_flag=0;
        bool is_final_packet = fragment_processor(buffer, bytesReceived,port,temp_name,temp_ext,recv_flag,ip_str);

        // Append received bytes to data_stream
        //data_stream.insert(data_stream.end(), buffer, buffer + bytesReceived);

        // Send back a single‐byte confirmation to the specific client
        send_confirmation(server_fd, client_addr);
        if(is_final_packet){
            cout << "[+] All packets received from " <<ip_str<<":"<<port <<endl ;

            auto key_pair = make_pair(ip_str, port);
            {
                lock_guard<mutex> lock(transmission_map_mutex);
                reassemble_fragments(transmission_map[key_pair], temp_name,temp_ext);
                
                // Clean up the buffer for this client
                transmission_map.erase(key_pair);
                recv_count.erase(key_pair);
            }

            //data_stream.clear(); // clearing the vect
            // for the vector to mitigate out of order packet ,push in data_stream[sequence_id]
            // implement a map instead of one vecgtor ,the ip address and port as key and vector data_stream  as the value then after reassembly delete the key and value pair from map
            // not breaking but asembling the full reciev packet but continueing to recieve
            //break;
        }
        
        // Clear buffer for next recvfrom
        memset(buffer, 0, BUFFER_SIZE);
    }
}

int main() {
    // 1) Start TCP listener thread for client registration and key exchange
    thread tcp_thread(tcp_listener_thread);
    tcp_thread.detach(); // Let it run independently
    
    cout << "[+] TCP listener thread started for client registration" << endl;
    
    // 2) Create UDP socket and bind
    int server_fd = setup_socket();

    // 3) Receive all fragments into a single byte stream
    receive_data(server_fd);

    // 4) Reassemble into a file (e.g. output.jpg)
    //reassemble_fragments(data_stream, "output.jpg");

    // 5) Clean up
    close(server_fd);
    cout << "[+] UDP server shut down.\n";
    return 0;
}
