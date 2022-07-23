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


using namespace std;
#define SIZE 1024
#define MAXBUFLEN 65536
int sockfd;
int start=0;
int ending=0;
int MTU=1000;
int counter_sequence=0;
int total_length=0;
int packet_size=4000;
int pkt_start = 0;
int pkt_ending = MAXBUFLEN;
char *file_name="web.txt";
struct packet {

	//char sender_ip=inet(ip) for later on
	//char *s_ipaddress;
	//char *d_ipaddress;
	string extension;
    int length=0;
	int sequence_id=0;
	  
};
//queue <vector> char fragment_queue;

void confirmation(){

}
void send_fragment(char arr[], int sockfd1)
{		
		char confirm[1];
		//cout<<arr<<flush<<endl<<endl<<endl<<endl<<endl<<endl<<endl<<endl<<endl;
        if(send(sockfd1,arr,strlen(arr), 0)== -1)
        {
            perror("[-] Error in sending data");
           // exit(1);
		   //confirmation function

        }
		recv(sockfd1,confirm,1,0);
		if (confirm[0] =='1'){
			cout<<"data sent"<< counter_sequence <<endl;
		}
		else{
			perror("Packet not sent :");
			cout<<counter_sequence<<endl;
			exit(1);
		}
		
        //
    
}

void fragment(int size,char arr[]){
	packet pkt;
	char data[MTU];
	pkt.sequence_id=counter_sequence;
	counter_sequence++;
    pkt.length=size;
	string total=to_string(total_length);
 	string num_char=to_string(size);
    string seq_char=to_string(pkt.sequence_id);
    string temp=num_char+'S'+seq_char+ 'T'+total+'P'+arr;
	strcpy(data,temp.c_str());

	send_fragment(data,sockfd);
	
	
}

void fragment_creater(char pack[]){
														
	ending=MTU-20;		
	int packet_length=strlen(pack);

	cout<<packet_length<<flush;
	int times_frag =ceil(packet_length/(MTU-20));
    char packet_data[MTU-20];
	int k=0;
	
	if (packet_length < MTU )
    {
	
			send_fragment(pack,sockfd);
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
			ending=ending+MTU-20; 																					//change this for different mtu

			k=0;
			//cout<<packet_data;
			fragment(sizeof(packet_data),packet_data);
			
			//delete[] tempBuffer;
			bzero(packet_data, MTU-20);
			memset(packet_data, 0, sizeof(packet_data));

	}
		

	}
}

void packet_creater(){

	FILE *fp = fopen(file_name, "r");
	int k=0;
	ifstream stream(file_name, ios_base::binary);
	stream.seekg(0, ios::end);
	int file_size = stream.tellg();
	char source[MAXBUFLEN];
	total_length=file_size;
	cout<<file_size;
	size_t newLen;
	int number_of_packets=ceil(total_length/MAXBUFLEN);
	if (fp != NULL) {
		for(int i =0;i<=number_of_packets;i++)
		{
			fseek(fp,pkt_start,SEEK_SET);
			newLen = fread(source, 1, MAXBUFLEN, fp);
			pkt_start=pkt_ending;


			fragment_creater(source);
			memset(source, 0, sizeof(source));

		}
		if ( ferror( fp ) != 0 ) {
			fputs("Error reading file", stderr);
		} else {
			source[newLen++] = '\0'; /* Just to be safe. */
		}

	}
	
	/*int number_of_packets=ceil(total_length/packet_size);
	char packet_data[packet_size];

	for (int i=0;i<=number_of_packets;i++)
		{
			for(int j=pkt_start;j<pkt_ending;j++)
			{
				packet_data[k]=source[j];
				k++;

			}
			pkt_start=pkt_ending;
			pkt_ending=pkt_ending+packet_size; 
			k=0;
			//cout<<packet_data;
			//fragmentation(packet_data);
			bzero(packet_data, packet_size);
			memset(packet_data, 0, sizeof(packet_data));

	}
	*/
	

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
         //exit(1);
     }
     printf("[+]Connected to server.\n");

	  //if(send(sockfd,file_name,strlen(file_name), 0)== -1)
        {
            //perror("[-] Error in sending name");
          // exit(1);

        }

	packet_creater();
     
    

    close(sockfd);
    printf("[+]Disconnected from the server. \n");
     return 0;

}


	
