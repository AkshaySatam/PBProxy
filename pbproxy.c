#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <signal.h>
#include<netdb.h>
int readInput(char* input);
void printInput(char* input,int count);
int createClientSocket(char* destIP, char* destPort);
void getDestIPandPort(char* dest_host_port,char* host,char* port);
void splitString(char* buffer [2],const char* input,char delimiter);
void copyString(char* dest,const char* src, int start, int end);
int createServerSocket(char* sourcePort);
void readFile(char* fileName,char* key);
void* readClientInput();
void* writeClientOutput();
void decryptionSetup(int fd, const unsigned char* enc_key);
void decryptionSetupRet(int fd, const unsigned char* enc_key);
void* clientRThread();
void* clientWThread();
void encryptionSetup(int fd, const unsigned char* enc_key);
void encryptionSetupRet(int fd, const unsigned char* enc_key);

struct ctr_state
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

int SIZE=5000;


AES_KEY aes_key_ret;
unsigned char iv_ret[AES_BLOCK_SIZE];
struct ctr_state state_ret;


AES_KEY aes_key;
unsigned char iv[AES_BLOCK_SIZE];
struct ctr_state state;

char ip[20];
char sLisPort[10];
int bytes_read, bytes_written;
char input[5000];
char serverReply[5000];
char encInput[5000];
char encOutput[5000];
int fd=0,clFd=0,fd1=0;
char key [129];
int bytesRead=0,bytesRead_Server=0;
char host [20];
char port [10];
pthread_t rTId;
pthread_t wTId;

void* clientWThread(){

	while(1){

		memset(&serverReply,0,sizeof(serverReply)/sizeof (char));
		memset(&encOutput,0,sizeof(encOutput)/sizeof (char));

		//Read from server
		bytesRead_Server = read(fd,serverReply,SIZE);
		if(bytesRead_Server>0){
			//fprintf(stderr,"Read from PBProxy Server  %s\n",serverReply);
			AES_ctr128_encrypt(serverReply,encOutput,bytesRead_Server, &aes_key_ret, state_ret.ivec, state_ret.ecount, &state_ret.num);
			write(1,encOutput,bytesRead_Server);
	//		write(1,serverReply,bytesRead_Server);

		}

	}
}

void* clientRThread(){
	while(1)
	{
		memset(&input,0,sizeof(input)/sizeof (char));		
		memset(&encInput,0,sizeof(encInput)/sizeof (char));
		bytesRead = read(0,input,SIZE);
		if(bytesRead>0){
			AES_ctr128_encrypt(input,encInput,bytesRead, &aes_key, state.ivec, state.ecount, &state.num);
			send(fd,encInput,bytesRead,0);
			//fprintf(stderr,"Client wrote the message \n %s",input);
		}	
	}	

}

void* writeClientOutput(){
	//ffprintf(stderr,strerr,"Encryption setup done from server side\n");
	while(1){

		memset(&serverReply,0,sizeof(serverReply)/sizeof (char));
		memset(&encOutput,0,sizeof(encOutput)/sizeof (char));

		//Read from server
		bytesRead_Server = read(clFd,serverReply,SIZE);
		if(bytesRead_Server>0){
		//	fprintf(stderr,"Read from Server 2 %s\n",serverReply);

			AES_ctr128_encrypt(serverReply,encOutput,bytesRead_Server, &aes_key_ret, state_ret.ivec, state_ret.ecount, &state_ret.num);
		//	fprintf(stderr,"Wrote to Client %s\n",encOutput);
			
			//write back to client
			write(fd,encOutput,bytesRead_Server);
			//write(fd,serverReply,bytesRead_Server);
		}

	}	
}

void* readClientInput(){
	//	fprintf(stderr,"creating sockets for server\n");
	while(1){
		memset(&input,0,sizeof(input)/sizeof (char));
		memset(&encInput,0,sizeof(encInput)/sizeof (char));
		bytesRead = recv(fd,input,SIZE,0);
		if(bytesRead>0){
		//	fprintf(stderr,"Read: %s\n ",input);
			AES_ctr128_encrypt(input, encInput, bytesRead, &aes_key, state.ivec, state.ecount, &state.num);
		//	fprintf(stderr,"Read after decryption: %s\n ",encInput);
			send(clFd,encInput,bytesRead,0);
		}

		else if (bytesRead<0){
			break;
		}else{	break;
			fprintf(stderr,"Error while reading\n");

		}

	}	
}

int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{                
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
	 * first call. */
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);

	/* Initialise counter in 'ivec' to 0 */
	memset(state->ivec + 8, 0, 8);

	/* Copy IV into 'ivec' */
	memcpy(state->ivec, iv, 8);
}

void encryptionSetupRet(int fd, const unsigned char* enc_key)
{
	char newIV[16];

	if(!RAND_bytes(iv_ret, AES_BLOCK_SIZE))
	{
		fprintf(stderr, "Could not create random bytes.");
		exit(1);
	}

	for(int i=0;i<8;i++){
		newIV[i]=iv_ret[i];
	}
	for(int i=8;i<16;i++){
		newIV[i]='\0';
	}

	write(fd,newIV,AES_BLOCK_SIZE);
//	fprintf(stderr,"Initialization vector 2 : Sent - %s\n",newIV);	

	//Initializing the encryption KEY
	if (AES_set_encrypt_key(enc_key, 128, &aes_key_ret) < 0)
	{
	//	ffprintf(stderr,stderr, "Could not set encryption key.");
		exit(1);
	}

	init_ctr(&state_ret, newIV); //Counter call
}

void decryptionSetupRet(int fd, const unsigned char* enc_key)
{
	read(fd,iv_ret,AES_BLOCK_SIZE);
//	fprintf(stderr,"Initialization vector 2: Recived - %s\n",iv);	
	//Initializing the encryption KEY
	if (AES_set_encrypt_key(enc_key, 128, &aes_key_ret) < 0)
	{
		fprintf(stderr, "Could not set decryption key.");
		exit(1);
	}

	init_ctr(&state_ret, iv_ret);//Counter call

}

void encryptionSetup(int fd, const unsigned char* enc_key)
{
	char newIV[16];

	if(!RAND_bytes(iv, AES_BLOCK_SIZE))
	{
	//	ffprintf(stderr,stderr, "Could not create random bytes.");
		exit(1);
	}

	for(int i=0;i<8;i++){
		newIV[i]=iv[i];
	}
	for(int i=8;i<16;i++){
		newIV[i]='\0';
	}

	write(fd,newIV,AES_BLOCK_SIZE);
	//	fprintf(stderr,"Initialization vector: Sent - %s\n",newIV);	

	//Initializing the encryption KEY
	if (AES_set_encrypt_key(enc_key, 128, &aes_key) < 0)
	{
	//	ffprintf(stderr,stderr, "Could not set encryption key.");
		exit(1);
	}

	init_ctr(&state, newIV); //Counter call
}

void decryptionSetup(int fd, const unsigned char* enc_key)
{
	read(fd,iv,AES_BLOCK_SIZE);
	//	fprintf(stderr,"Initialization vector: Recived - %s\n",iv);	
	//Initializing the encryption KEY
	if (AES_set_encrypt_key(enc_key, 128, &aes_key) < 0)
	{
		//      ffprintf(stderr,stderr, "Could not set decryption key.");
		exit(1);
	}

	init_ctr(&state, iv);//Counter call

}

int hostname_to_ip(char * hostname , char* ip)
{
	struct hostent *he;
	struct in_addr **addr_list;
	int i;

	if ( (he = gethostbyname( hostname ) ) == NULL) 
	{
		// get the host info
		herror("gethostbyname");
		return 1;
	}

	addr_list = (struct in_addr **) he->h_addr_list;

	for(i = 0; addr_list[i] != NULL; i++) 
	{
		//Return the first one;
		strcpy(ip , inet_ntoa(*addr_list[i]) );
		return 0;
	}
	fprintf(stderr,"IP %s",ip);

	return 1;
}

int main(int argc, char *argv[])
{
	int isServer=0;
	char fileName [20];
	int j=0;
	char dest_host_port[25];
	for(int i=1;i<argc;i++){
		if(strcmp("-l",argv[i])==0){
			i++;
			isServer = 1;
			copyString(sLisPort,argv[i],0,strlen(argv[i]));
			//			fprintf(stderr,"Server port set to : %s \n", sLisPort);
		}else 
			if(strcmp("-k",argv[i])==0){
				i++;
				copyString(fileName,argv[i],0,strlen(argv[i]));
				//				fprintf(stderr,"fileName : %s\n",fileName);
				readFile(fileName,key);
			}else 
			{

				int k =0;
				if(j!=0){
					*(dest_host_port+j)= ' ';
					j++;
				}
				//				fprintf(stderr,"Received host/port : %s \n",(argv[i]+k));
				//				fprintf(stderr,"First char of received exp: %c \n",*(argv[i]+k));
				while(*(argv[i]+k)!='\0'){
					*(dest_host_port+j)= *(argv[i]+k);
					j++;k++;
				}
			}
	}

	*(dest_host_port+j)='\0';
	//	fprintf(stderr,"Host/Port: %s\n",dest_host_port);	

	getDestIPandPort(dest_host_port,host,port);
	//	fprintf(stderr,"Host: %s\n",host);
	//	fprintf(stderr,"Port: %s\n",port);

	//if it is a client
	if(isServer==0){
		hostname_to_ip(host,ip);	
		fd = createClientSocket(ip,port);
		encryptionSetup(fd,key);
		decryptionSetupRet(fd,key);
		pthread_create(&rTId,NULL,clientRThread,NULL);
		pthread_create(&wTId,NULL,clientWThread,NULL);
		pthread_join(rTId,NULL);
		pthread_join(wTId,NULL);
//		fprintf(stderr,"Threads exited\n");
	}
	//if it is a server
	else{
		fd1 = createServerSocket(sLisPort);
		while(1){
		//	fprintf(stderr,"Creating new file descriptors\n");
			fd = accept(fd1, (struct sockaddr*) NULL, NULL);
			clFd = createClientSocket(host,port);
			decryptionSetup(fd,key);
			encryptionSetupRet(fd,key);
			pthread_create(&rTId,NULL,readClientInput,NULL);
			pthread_create(&wTId,NULL,writeClientOutput,NULL);
			pthread_join(rTId,NULL);
			//	pthread_join(wTId,NULL);
			pthread_kill(wTId,0);
		//	fprintf(stderr,"Closing file descriptor\n");
			close(fd);
			close(clFd);
		//	fprintf(stderr,"Killed thread 2\n");
			//		fprintf(stderr,"Exited");
		}
	}

}

 
void readFile(char* filename,char* key){
	FILE *fptr;
	char ch;
	int i =0;

	/*  open the file for reading */
	fptr = fopen(filename, "r");

	if (fptr == NULL)
	{
		//		fprintf(stderr,"Cannot open file \n");
		exit(0);
	}

	ch = fgetc(fptr);
	while (ch != EOF)
	{
		//		printf ("%c", ch);
		key[i++]=ch;
		ch = fgetc(fptr);
	}
	key[i]='\0';
	//	fprintf(stderr,"Key %s\n",key);
	fclose(fptr);
}

int createServerSocket(char* sourcePort){
	int port = atoi(sourcePort);
	int listen_fd, comm_fd;
	struct sockaddr_in servaddr;

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	//	fprintf(stderr,"Server socket created\n");

	bzero( &servaddr, sizeof(servaddr));
	//	fprintf(stderr,"Memory zeroed for server address\n");
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htons(INADDR_ANY);
	servaddr.sin_port = htons(port);

	bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	//	fprintf(stderr,"socket binded to host:port\n");
	listen(listen_fd, 10);
	return listen_fd;
	//	fprintf(stderr,"Listening to port\n");
	//	fprintf(stderr,"Input message accepted\n");
}


int createClientSocket(char* destIP, char* destPort){
	int sockfd,n;
	struct sockaddr_in servaddr;
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	//	fprintf(stderr,"Client Socket created\n");

	bzero(&servaddr,sizeof servaddr);
	//	fprintf(stderr,"Client struct memory zeroed\n");
	servaddr.sin_family=AF_INET;
	servaddr.sin_port=htons(atoi(destPort));
	//	fprintf(stderr,"Client dest host:port set\n");
	inet_pton(AF_INET,destIP,&(servaddr.sin_addr));
	//	fprintf(stderr,"Client dest IP address set\n");
	connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
	//	fprintf(stderr,"Client socket attached to IP address\n");
	return sockfd;
}

void getDestIPandPort(char* dest_host_port,char* host,char* port){

	char *token;
	char *delimiter = " ";
	char dup[25];
	int i =0;
	while(*(dest_host_port+i)!=0){
		dup[i]=*(dest_host_port+i);
		i++;
	}
	dup[i]='\0';
	//	fprintf(stderr,"New array: %s \n",dup);
	token = strtok(dup, delimiter);
	//	fprintf(stderr,"First word: %s\n",token);
	copyString(host,token,0,strlen(token));
	token = strtok(NULL, delimiter);
	//	fprintf(stderr,"Second word: %s\n",token);
	copyString(port,token,0,strlen(token));
}

void copyString(char* dest,const char* src, int start, int end){
	while(start < end){
		*dest = *(src+start);
		dest++;
		start++;
	}

	*dest='\0';
}
void printInput (char* input,int count){
	int i=0;
	while((*input!= 0)&&(i<count)){
		//		fprintf(stderr,"%c",*input);
		input++;
		i++;
	}
	//	fprintf(stderr,"\n");
}

int readInput(char* input){
	char c;
	int i =0;
	while(1){
		if(i==AES_BLOCK_SIZE){
			break;	
		}
		c = getchar();
		if(c == '\n'){
			input[i]=0; 
			break;
		}
		input[i++]=c;
	}
	return i;


}
