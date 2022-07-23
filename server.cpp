#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <iostream>
#include <vector>
using namespace std;
#define SIZE 2000
int sequence_id=0;
int total_length=0;
char *reassembled;
int counter=0;
#pragma warning (disable : 4101)
char *file_name;              //change the destination file name and extension
int endpointer=0;
struct reas{

    //queue to store packets
};

void packet_check_reassembler(char packet[]){//problem in this function
   // cout<<packet<<endl<<endl;
    int i=0;
    int length=0;
    //char temp[strlen(packet)];
    perror("pcr started");
    //strcpy(temp,packet);//solved

    int sequence=0;
    while(packet[i]!='S'){
        length=length*10+((int)packet[i]-48) ;     //checks the length
        i++;
    }
    i+=1;
   // perror("length");
    while(packet[i]!='T'){
        sequence=sequence*10+((int)packet[i]-48);
        i++;
    }
    i++;
    while(packet[i]!='P'){
        total_length=total_length*10+((int)packet[i]-48) ;     //to get the total length of the packet
        i++;
    }
    perror("sequence");
    i++;

    if(counter==0){
       reassembled = (char*)malloc(total_length); 
       counter+=1;
       total_length=0;
    }

    
    int payload_length=strlen(packet)-i;

    if (sequence==sequence_id)
    {
        if (length==payload_length)//maybe
        {    
            for (int j=i;j<payload_length-1;j++)
            {
                reassembled[endpointer]=packet[j];
                endpointer++;
                

            }perror("packet insrted:");
            //strncpy(reassembled, packet.c_str(), sizeof(tab2));  //check if for the dynamic array   
            //whis will replace data
            // sprintf(temp, packet.c_str()); //will not replace maybe
            //memcpy( reassembled, packet + i+1, strlen(packet) );
            
        }
        else{
            for (int j=i;j<strlen(packet)-1;j++)
            {
                reassembled[endpointer]=packet[j];
                endpointer++;
                
                //cout<<endpointer<<flush<<endl;

            }
            sequence_id++;
            

            perror("packet insrted:");
            //perror("Corrupted packet");// or retransmit the packet call the retransmit function also store the sequence
                    
                
        }
    }
    else{
        if (length==payload_length)
        {
            //queue_store(temp);

        }
        
        else{
            //corrupted packet
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
    char *filename = "file2.txt";
   // string buffer;

    //char buffer[SIZE];

    fp = fopen(filename, "w");
    if(fp==NULL)
    {
        perror("[-]Error in creating file.");
        exit(1);
    }
       
    fprintf(fp, "%s", reassembled);
    //bzero(buffer, SIZE);
    
    return;
  }  


void recieve_packet(int sockfd){
    int n;

   char buffer[SIZE];

      n = recv(sockfd, buffer, SIZE, 0);
        if(n<=0)
        {
            //std::cout<<"packet failed";
            //send(sockfd,'0',1,0);
            write_file();
            exit(1);
            

        }
        char confirm[1];
        confirm[0]='1';
        
        //cout<<buffer<<flush<<endl<<endl;
        packet_check_reassembler(buffer);
        send(sockfd,confirm,1,0);
        bzero(buffer, SIZE);
  
}






int main ()
{
    char *ip = "127.0.0.1";
    int port = 8080;
    int e;

    int sockfd, new_sock;
    struct sockaddr_in server_addr, new_addr;
    socklen_t addr_size;
    char buffer[SIZE];

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

     e = bind(sockfd,(struct sockaddr*)&server_addr, sizeof(server_addr));
     if(e<0)
     {
         perror("[-]Error in Binding");
         exit(1);
     }
     printf("[+]Binding Successfull.\n");

     e = listen(sockfd, 10);
     if(e==0)
     {
         printf("[+]Listening...\n");
     }
     else 
     {
         perror("[-]Error in Binding");
         exit(1);
     }
     addr_size = sizeof(new_addr);
     new_sock = accept(sockfd,(struct sockaddr*)&new_addr, &addr_size);
    // recv(sockfd, file_name, strlen(file_name), 0); //recieves name and ext
     cout<<"recieveing started";
    while(1){

         recieve_packet(new_sock); //this will only accept one packet
    }
    cout<<reassembled<<flush;

   //write_file();

     
     printf("[+]Data written in the text file ");
}


//data structure to store array conveninately