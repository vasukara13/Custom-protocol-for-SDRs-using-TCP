/*
    C socket server example, handles multiple clients using threads
    Compile
    gcc server.c -lpthread -o server
*/
#include<stdio.h>
#include<string.h>   
#include<stdlib.h>    
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include<unistd.h>   
#include<pthread.h> //for threading , link with lpthread
#include <iostream>

using namespace std;
void *connection_handler(void *);
#include <stdlib.h>
#include <fstream>
#include <algorithm>
#define SIZE 2000
int sequence_id=0;
int total_length=0;
int sockfd;
int counter=0;
#pragma warning (disable : 4101)
char *filename = "file2.jpg";            //change the destination file name and extension
int endpointer=0;
string reassembled;
/** Flag set by `--verbose'. */
static int verbose_flag;

char fin[255]; 			///< input filename
char fout[255]; 		///< output filename
char strtmp[255]; 		///< temporary string
char separator[255]; 	///< separator for output strings
int bytes_per_string; 	///< how many bytes convert to string? (byte/word/quad/... data)
unsigned int wrap_line;	///< wrap line after about N chars

struct reas{

    //queue to store packets
};

int hex2val(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

int hex2file (string input)
{
    int c;
    int lsize;
    lsize=input.length();
    char buffer[lsize];		///< pointer to buffer for input file
    int option_count=0; ///< command-line options counter
    FILE *fileOut; ///< input and output file

    // open output file
    fileOut = fopen(filename, "wb");
    if (fileOut==NULL)
    {
        puts("Error opening output file for write");
        exit (1);
    }
    strcpy(buffer,input.c_str());
    if (buffer == NULL)
    {
    	puts("malloc for input file buffer failed (not enough memory?)");
        exit (2);
    }

    
    int c1, c2;
    enum State {
        Idle,
        Odd
    } state = Idle;
    for (int i=0; i<lsize;)
    {
        char c = buffer[i];

        switch (state)
        {
        case Idle:
            if (c == '0') {
                if (i < lsize -1) {
                    if (buffer[i+1] == 'x' || buffer[i+1] == 'X') {
                        i += 2;
                        continue;
                    }
                }
            }
            c1 = hex2val(c);
            if (c1 < 0) {
                break;
            } else {
                state = Odd;
                break;
            }
        case Odd:
            c2 = hex2val(c);
            if (c2 < 0) {
                break;
            } else {
                unsigned char value = c1*16 + c2;
                fwrite(&value, 1, 1, fileOut);
                state = Idle;
                break;
            }
        }
        i++;
    }

	if(fileOut) fclose (fileOut);
	if (state == Odd)
    {
    	puts("[-] Warning: uneven number of hex characters, last character ignored");
        exit (3);
    }

}

void packet_check_reassembler(char packet[]){
    int i=0;
    int length=0;
    char *arr;  
    int sequence=0;
    while(packet[i]!='S'){
        length=length*10+((int)packet[i]-48) ;     //checks the length
        i++;
    }
    i+=1;
    while(packet[i]!='T'){
        sequence=sequence*10+((int)packet[i]-48);
        i++;
    }
    i++;
    while(packet[i]!='P'){
        total_length=total_length*10+((int)packet[i]-48) ;     //to get the total length of the packet
        i++;
    }
    counter=sequence;
    i++;
    cout<<"[+]Fragment "<<" F"<<sequence<<" of "<<length<<" bytes received."<<endl;
   
    arr = (char*)malloc(length-1); 
    int payload_length=strlen(packet)-i;

    if (sequence==sequence_id)
    {   
        for (int j=i;j<strlen(packet)-1;j++)
                {
                    arr[endpointer]=packet[j];
                    endpointer++;

                }
    
                endpointer=0;
                string local=string(arr,strlen(arr));
                reassembled.append(local);
                sequence_id++;
                return;
                        
        }


    else{
        if (length==payload_length)
        {
            //queue_store(temp);

        }
        
        else{
            cout<<"[-]Corrupted Fragment no"<<" F"<<sequence<<endl;
        }
            
    }

}

void queue_store(char arr){


}

void search_queue(){
    //for i=o to end 
    //if queue[i] sqeuence == sequencer 
    //then run reassembler
    //reassembly(queue[i]);

}
void write_file()
{
    perror("writing data.....");
    int n; 
    FILE *fp;
    ofstream file(filename);
    file << reassembled;

    
    return;
  }  


void recieve_packet(int sock){
    int n;

   char buffer[SIZE];

      n = recv(sock, buffer, SIZE, 0);
        if(n<=0)
        {
            cout<<"[+] Writing File..."<<endl;
            hex2file(reassembled);
            
        }
        char confirm[1];
        confirm[0]='1';
        packet_check_reassembler(buffer);        
        send(sock,confirm,1,0);
        bzero(buffer, SIZE);
  
}

int main(int argc , char *argv[])
{
    int client_sock , c;
    struct sockaddr_in server , client;
    char *ip = "127.0.0.1";
    //Create socket
     sockfd = socket(AF_INET , SOCK_STREAM , 0);
    if ( sockfd == -1)
    {
        printf("[-] Could not create socket");
    }
    puts("[+] Socket created");
     
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_port =8080;
     
    //Bind
    if( bind( sockfd,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        perror("[-] bind failed. Error");
        return 1;
    }
    puts("[+] bind done");
     
    //Listen
    listen( sockfd , 3);
     
    //Accept and incoming connection
    puts("[+] Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);
     
     
    //Accept and incoming connection

    c = sizeof(struct sockaddr_in);
	pthread_t thread_id;
	
    while( (client_sock = accept( sockfd, (struct sockaddr *)&client, (socklen_t*)&c)) )
    {
        puts("[++] Connection accepted");
         
        if( pthread_create( &thread_id , NULL ,  connection_handler , (void*) &client_sock) < 0)
        {
            perror("[-] could not create thread");
            return 1;
        }
         
        //Now join the thread , so that we dont terminate before the thread
        //pthread_join( thread_id , NULL);
        puts("[+] Handler assigned");
    }
     
    if (client_sock < 0)
    {
        perror("[-] accept failed");
        return 1;
    }
     
    return 0;
}
 
/*
 * This will handle connection for each client
 * */
void *connection_handler(void * sockfd)
{
    //Get the socket descriptor
    int sock = *(int*) sockfd;
    int read_size;

    //Receive a message from client
    cout<<"waiting..."<<endl;
    while(1){

         recieve_packet(sock); //this will only accept one packet
    }
    /*
    while( (read_size = recv(sock , client_message , 2000 , 0)) > 0 )
    {   

        //end of string marker
		client_message[read_size] = '\0';
		
		//Send the message back to client
        write(sock , client_message , strlen(client_message));
		
		//clear the message buffer
		memset(client_message, 0, 2000);
    }
     
    if(read_size == 0)
    {
        puts("Client disconnected");
        fflush(stdout);
    }
    else if(read_size == -1)
    {
        perror("recv failed");
    }
         */
    return 0;
} 
