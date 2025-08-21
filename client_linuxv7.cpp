
//g++ client.cpp -o client -lssl -lcrypto -lgmpxx -lgmp

#include "encrypt_client.cpp"
#include <queue>
using namespace std;

#define HEADER_SIZE 19          // 19+ 28 for encryption padding
#define TCP_PORT 8081           // TCP port for client registration and key exchange
int client_tcp_port = 0;        // Stores the common port 

char const* ip;                 // IP Address 
int port;                       // UDP port of server
string input_name, extension;   // File name and extension
queue<pair<int,char*>> rt_q;   // Retransmission queue
int sockfd;                     // Socket descriptor
int total_length = 0;
const int MTU = 1200;


struct packet { //----------------------------- HEADER SIZE 19 BYTES------------------------------------
    uint32_t sender_ip;         // 4 bytes (binary format)
    uint32_t receiver_ip;       // 4 bytes (binary format)
    uint16_t length;            // 2 bytes (supports larger files)
    uint16_t sequence_id;       // 2 bytes
    uint16_t total_frags;       // 2 bytes store number of total packets to be sent
    char extension[4];          // 4 bytes
    bool FIN;                   // 0 for not finished ,1 for finished
    //uint16_t rto;             // 2 bytes (retransmission timeout)
    //uint8_t flags;            // 1 byte (bitmask for fragmentation, payload type etc.)
    char data[MTU-HEADER_SIZE]; // Payload
   
};


                
mpz_class tcp_connect() {       // TCP connection for client registration and key exchange
    int tcp_sockfd;
    struct sockaddr_in tcp_server_addr;
    
    // Create TCP socket
    tcp_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sockfd < 0) {
        perror("[-] Error in TCP socket creation");
        exit(1);
    }
    cout << "[+] TCP socket created for registration." << "\n";
    
    // Setup TCP server address
    memset(&tcp_server_addr, 0, sizeof(tcp_server_addr));
    tcp_server_addr.sin_family = AF_INET;
    tcp_server_addr.sin_port = htons(TCP_PORT);
    
    if (inet_pton(AF_INET, ip, &tcp_server_addr.sin_addr) <= 0) {
        cerr << "[-] Invalid IP address for TCP: " << ip << "\n";
        close(tcp_sockfd);
        exit(1);
    }
    
    // Connect to TCP server
    cout << "[+] Connecting to TCP server for registration..." << endl;
    if (connect(tcp_sockfd, (struct sockaddr*)&tcp_server_addr, sizeof(tcp_server_addr)) < 0) {
        perror("[-] Error in TCP connection");
        close(tcp_sockfd);
        exit(1);
    }
    cout << "[+] Connected to TCP server for registration" << endl;
    
    // Retain the port of tcp for udp
    struct sockaddr_in tcp_local_addr;
    socklen_t addr_len = sizeof(tcp_local_addr);
    if (getsockname(tcp_sockfd, (struct sockaddr*)&tcp_local_addr, &addr_len) < 0) {
        perror("getsockname on TCP socket");
        exit(1);
    }
    
    client_tcp_port = ntohs(tcp_local_addr.sin_port);
    cout << "[+] TCP client port: " << client_tcp_port << endl;


    // Perform key exchange over TCP
    cout << "[+] Starting key exchange over TCP..." << endl;
    mpz_class session_key = client_key(tcp_sockfd); // New TCP version of key exchange
    cout << "[+] Key exchange completed over TCP" << endl;
    
    // Close TCP connection - registration and key exchange done
    close(tcp_sockfd);
    
    cout << "[+] TCP registration completed. Session key obtained." << endl;
    
    return session_key;
}

//----------------------------------------------------FRAGEMENTATION BLOCK----------------------------------------
void send_fragment(const char arr[], int sockfd1, int size, int counter_sequence, struct sockaddr_in server_addr)
{
    char confirm;
    socklen_t addr_len = sizeof(server_addr);
    
    // Send data using sendto() for UDP
    ssize_t sendResult = sendto(sockfd1, arr, size, 0, 
                               (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (sendResult < 0) {
        perror("[-] Error in sending data");
        exit(1);
    }

    // Receive confirmation using recvfrom() for UDP
    struct sockaddr_in recv_addr;
    socklen_t recv_addr_len = sizeof(recv_addr);
    ssize_t recvResult = recvfrom(sockfd1, &confirm, 1, 0, 
                                 (struct sockaddr*)&recv_addr, &recv_addr_len);
    if (recvResult < 0) {
        perror("[-] Error in receiving data");
        //rt_q.push({counter_sequence,arr});
     
    }

    if (confirm == '1') {
        cout << "[+] Fragment F" << counter_sequence << " of " << size << " bytes sent." << "\n";
    }
    else {
        cout << "[-] Packet not sent: " << counter_sequence << "\n";
        //rt_q.push({counter_sequence,arr});
        
    }
}



void fragment(int size, const char* arr, int& counter_sequence,struct sockaddr_in server_addr,int times_frag,uint32_t sender_ip,uint32_t receiver_ip)
{
    // Creating object of packet structure    
    packet pkt;
    memset(&pkt, 0, sizeof(pkt));               // Initialize all bytes to 0
    
    pkt.sequence_id = htons(counter_sequence);
    
    pkt.length = htons(size);
    
    
    pkt.sender_ip   = sender_ip;
    pkt.receiver_ip = receiver_ip;
    pkt.total_frags = htons(times_frag);
    strncpy(pkt.extension,extension.c_str(), sizeof(pkt.extension) - 1);
    
    if(times_frag==counter_sequence)
        pkt.FIN=1;
    else
        pkt.FIN=0;
    
    
    memcpy(pkt.data, arr, size);
    int total_bytes_to_send = HEADER_SIZE + size;
    // Check struct size
    cout << "Packet size is : " << total_bytes_to_send << "\n";
    
    if (sizeof(pkt) > MTU) {
        cout << "[-] Error: Fragment size exceeds MTU size." << "\n";
        exit(1);
    }
    
    send_fragment(reinterpret_cast<const char*>(&pkt), sockfd, total_bytes_to_send, counter_sequence, server_addr);
    counter_sequence++;
}

void retransmission(struct sockaddr_in server_addr,int times_frag,uint32_t sender_ip,uint32_t receiver_ip){
    
    while(!rt_q.empty()){
        auto pack=rt_q.front();
        const char* arr= pack.second;
        int seq=pack.first;
        rt_q.pop();
        fragment(sizeof(arr),arr,seq,server_addr,times_frag,sender_ip,receiver_ip);
        send_fragment(arr,sockfd,sizeof(arr),seq,server_addr);
        
    }
}

void fragment_creator(vector<char> byteString,struct sockaddr_in server_addr,int sockfd,uint32_t sender_ip,uint32_t receiver_ip,mpz_class session_key)
{
    
    
    const int ENC_OVERHEAD     = 28;                       // worst-case padding/info
    const int packet_length    = byteString.size();
    const int fragment_payload_size = MTU - HEADER_SIZE - ENC_OVERHEAD;                  // reserve space
    int start  = 0;
    int ending = fragment_payload_size;
    int counter_sequence = 1;
    int times_frag = (packet_length + fragment_payload_size - 1) / fragment_payload_size;
    
    if (packet_length < MTU)
        fragment(packet_length, byteString.data(), counter_sequence,server_addr,times_frag,sender_ip,receiver_ip);

    else {
        
        for (int i = 1; i <= times_frag; i++){

            if(!rt_q.empty()){
                retransmission(server_addr, times_frag, sender_ip, receiver_ip);
            }

            int fragment_size =min(fragment_payload_size, packet_length - start);
            vector<char> plaintext_fragment(byteString.begin() + start, byteString.begin() + start + fragment_size);

            //cout << "Encrypting fragment " << i << "/" << times_frag << " (size: " << plaintext_fragment.size() << " bytes)" << endl;

            //cout<<"Original file size  "<<plaintext_fragment.size()<<endl;
            
            vector<char> encrypted_fragment = encrypt(session_key, plaintext_fragment);

            // temp_frag = encrypt(session_key,temp_frag);

            //cout<<"Size of encryption string is  "<<encrypted_fragment.size()<<endl;

            fragment(encrypted_fragment.size(), encrypted_fragment.data(), counter_sequence,server_addr,times_frag,sender_ip,receiver_ip);
            start += fragment_size;

        }
    }
}

void packet_creator(struct sockaddr_in server_addr,int sockfd,uint32_t sender_ip,uint32_t receiver_ip,mpz_class session_key)
{
    string file_name = input_name + "." + extension; // change to get from cmd parameter 
    ifstream file(file_name, ios::binary);

    // Check if the file is successfully opened
    if (!file.is_open()) {
        cerr << "[-] Failed to open file: " << file_name << "\n";
        exit(1);
    }

    // Read the file into a vector
    vector<char> byteStream(
        (istreambuf_iterator<char>(file)),
        (istreambuf_iterator<char>())
    );
    total_length = byteStream.size();
    cout << "[+] Total length of file"<<file_name<< "is : " << total_length << "\n";
    cout<<"[+] Starting sending....."<<endl;
    fragment_creator(byteStream,server_addr,sockfd,sender_ip,receiver_ip,session_key);
}

//----------------------------------------------------FRAGEMENTATION BLOCK---------------------------------------------------

int main(int argc, char* argv[])
{
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <server-IP> <server-port> <filename>" << endl;
        return 1;
    }

    ip = argv[1]; // assigning ip
    port = stoi(argv[2]);  // assigning port no.
    string filename = argv[3];

    size_t dotPos = filename.find_last_of('.');

    if (dotPos != string::npos) {
        input_name = filename.substr(0, dotPos);       // Before the last '.'
        extension = filename.substr(dotPos + 1); // After the last '.'
    } else {
        input_name = filename;     // No extension found
        extension = "";      // Empty extension
    }
    
    // Step 1: TCP Registration and Key Exchange
    cout << "[+] Starting TCP registration and key exchange..." << endl;
    mpz_class session_key = tcp_connect();
    cout << "[+] Registration completed. Proceeding with UDP file transfer..." << endl;
    
    // Step 2: Create UDP socket for file transfer
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("[-] Error in UDP socket creation");
        exit(1);
    }
    cout << "[+] UDP socket created." << "\n";

    // ✅ BIND UDP SOCKET TO THE SAME PORT USED DURING TCP KEY EXCHANGE
    struct sockaddr_in udp_local_addr;
    memset(&udp_local_addr, 0, sizeof(udp_local_addr));
    udp_local_addr.sin_family = AF_INET;
    udp_local_addr.sin_addr.s_addr = INADDR_ANY;
    udp_local_addr.sin_port = htons(client_tcp_port);  // ✅ Use same port as TCP

    if (bind(sockfd, (struct sockaddr*)&udp_local_addr, sizeof(udp_local_addr)) < 0) {
        perror("[-] Error binding UDP socket to specific port");
        close(sockfd);
        exit(1);
    }
    cout << "[+] UDP socket bound to port " << client_tcp_port << endl;

    struct sockaddr_in server_addr; // sock struct creation
    memset(&server_addr, 0, sizeof(server_addr)); // setting to 0 just in case
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);  // UDP server port (8080)

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        cerr << "[-] Invalid IP address: " << ip << "\n";
        close(sockfd);
        exit(1);
    }

    cout << "[+] Ready to send UDP packets to " << ip << ":" << port << endl;

    // —— DISCOVER local (sender) IP ——
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(sockfd, (struct sockaddr*)&local_addr, &addr_len) < 0) {
        perror("getsockname");
        close(sockfd);
        exit(1);
    }

    cout << "[+] Detected sender IP: ";
    {
      char buf[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &local_addr.sin_addr, buf, sizeof(buf));
      cout << buf << "\n";
    }
    cout << "[+] Using client port: " << ntohs(local_addr.sin_port) << endl;  // Should match client_tcp_port
    
    uint32_t sender_ip   = local_addr.sin_addr.s_addr;
    uint32_t receiver_ip = server_addr.sin_addr.s_addr;
    cout << "[+] Sending packets to server " << ip << ":" << port << "\n";

    // Pass the session key obtained from TCP registration
    packet_creator(server_addr,
                   sockfd,
                   sender_ip,
                   receiver_ip,
                   session_key);

    close(sockfd);
    cout << "[+] Socket closed." << "\n";
    return 0;
}

