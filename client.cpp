#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <fstream>
#include <cstdio>
#include <math.h>
#include <iomanip>

using namespace std;
#define SIZE 1024
#define MAXBUFLEN 65536
int sockfd;
int start=0;
int ending=0;
int counter_sequence=0;
int total_length=0;
int packet_size=4000;
int pkt_start = 0;
int pkt_ending = MAXBUFLEN;
int MTU=500;

struct config{
	
	string file_name="test.jpg";
	int x=0; //change to 0 for file transfer and change to 1 for packet transfer
};
struct packet {

	//char sender_ip=inet(ip) for later on
	//char *d_ipaddress;
	string extension;
    int length=0;
	int sequence_id=0;
	  
};
//queue <vector> char fragment_queue;

string ToHex(const string& s, bool upper_case)
{
    ostringstream ret;

    for (string::size_type i = 0; i < s.length(); ++i)
    {
        int z = s[i]&0xff;
        ret << std::hex << std::setfill('0') << std::setw(2) << (upper_case ? std::uppercase : std::nouppercase) << z;
    }

    return ret.str();
}

void send_fragment(char arr[], int sockfd1,int size)
{		
		char confirm[1];
        if(send(sockfd1,arr,strlen(arr), 0)== -1)
        {
            perror("[-] Error in sending data");
            exit(1);
		   //confirmation function

        }
        
		recv(sockfd1,confirm,1,0);
		if (confirm[0] =='1'){
            cout<<"[+]Fragment "<<" F"<<counter_sequence <<" of "<<size<<" bytes sent."<<endl;
		}
		else{
			perror("Packet not sent :");
			cout<<counter_sequence<<endl;
			exit(1);
		}
		
    
}

void fragment(int size,char arr[]){
	packet pkt;
	char data[MTU+10];
	pkt.sequence_id=counter_sequence;
	counter_sequence++;
    pkt.length=size;
	string total=to_string(total_length);
 	string num_char=to_string(size);
    string seq_char=to_string(pkt.sequence_id);
    string temp=num_char+'S'+seq_char+ 'T'+total+'P'+arr;
	strcpy(data,temp.c_str());
	send_fragment(data,sockfd,size);
		
}


void fragment_creater(char pack[]){
														
	ending=MTU-20;		
	int packet_length=strlen(pack);
    config conf;
	int times_frag =ceil(packet_length/(MTU-20));      
    char packet_data[MTU-20];
	int k=0;
	
	if (packet_length < MTU )
    {
			fragment(packet_length,pack);
	}
	else{
		for (int i=0;i<=times_frag;i++)
		{
		
			for(int j=start;j<ending;j++)
			{
				packet_data[k]=pack[j];
				k++;

			}
			start=ending;
			ending=ending+MTU-20; 																					
			k=0;
			fragment(strlen(packet_data),packet_data);
			bzero(packet_data, MTU-20);
			memset(packet_data, 0, sizeof(packet_data));

	}
		

	}
}

void packet_creater(){

	 ifstream::pos_type size;
    char * memblock;
	config cg;
    ifstream file (cg.file_name, ios::in|ios::binary|ios::ate);
    if (file.is_open())
    {
        size = file.tellg();
        memblock = new char [size];
        file.seekg (0, ios::beg);
        file.read (memblock, size);
        file.close();
        std::string hex_file = ToHex(std::string(memblock, size), true);
		total_length=hex_file.length();
		fragment_creater(const_cast<char*>(hex_file.c_str()));

    }
	
	
}

void packet_maker(){

}

void packet_reciever(){
	int n;
    char *buffer;

      n = recv(sockfd, buffer, sizeof(buffer), 0);
        if(n<=0)
        {
            std::cout<<"packet failed";
            exit(1);
            

        }
		buffer = new char [sizeof(buffer)];
		fragment_creater(buffer);
        

}
int main()
{
    char const *ip = "127.0.0.1";
    int port = 8080;
    int e;

    
    struct sockaddr_in server_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd<0)
    {
        perror("[-]Error in socket");
        exit(1);
    }
     printf("[+]Server socket created. \n");

     server_addr.sin_family = AF_INET;
     server_addr.sin_port = port;
     server_addr.sin_addr.s_addr = inet_addr(ip);

     e = connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
     if(e == -1)
     {
         perror("[-]Error in Connecting");
         exit(1);
     }
     printf("[+]Connected to server.\n");

	  
	packet_creater();
     
    close(sockfd);
    printf("[+]Disconnected from the server. \n");
    return 0;

}


	
