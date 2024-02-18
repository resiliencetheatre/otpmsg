/*
 *  otpmsg - otp message pipe
 *  Copyright (C) 2024 Resilience Theatre
 * 
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * 
 * Includes:
 * 
 * - base64 from Jouni Malinen, see base64.c for licensing details.
 * - https://github.com/liteserver/binn
 * - https://github.com/rxi/log.c
 * 
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "log.h"
#include "ini.h"
#include "binn.h"
#include "base64.h"


#define PLAINTEXT_BUF_LEN 100
#define TRANSPORT_BUF_LEN 200
#define KEY_INDEX_FILENAME_LEN	100
#define ENCRYPT_MODE 0
#define DECRYPT_MODE 1

void safe_fclose(FILE *fp);
long int get_key_index(char *filename);
void set_key_index(char *filename, long int index);

void safe_fclose(FILE *fp)
{
	if (fp && fp != stdout && fp != stderr) {
		if (fclose(fp) == EOF) {
			perror("fclose()");
		}
		fp = NULL;
	}
}

long int get_key_index(char *filename) {
	long int index=0;
	FILE *keyindex_file;
	keyindex_file = fopen(filename, "rb");
	fread(&index, sizeof(long int),1,keyindex_file);
	safe_fclose(keyindex_file);
	return index;
}

void set_key_index(char *filename, long int index) {
	FILE *keyindex_file;
	keyindex_file = fopen(filename, "wb");
	fwrite(&index, sizeof(long int), 1, keyindex_file);
	safe_fclose(keyindex_file);
}

void getkey(char *filename, char* keybuf, long int start_index, int len, bool overwrite)
{	
	FILE *keyfile;
	size_t freadlen=0;
	keyfile = fopen(filename, "rb");
	if (fseek(keyfile, start_index, SEEK_SET)) {
			printf("Seek error!\n");
	}
	freadlen = fread(keybuf, sizeof(char),len,keyfile);
	if ( freadlen == 0 ) {
		log_error("[%d] %s fread return: %d ", getpid(),filename,freadlen);	
		log_error("[%d] You run out of key material! Exiting. ", getpid());	
		exit(0);
	}
	safe_fclose(keyfile);
	if ( overwrite == TRUE )
	{
		log_debug("[%d] Key %s overwrite at: %ld len: %d", getpid(),filename,start_index,len);
		char *zerobuf = malloc(len);
		memset(zerobuf,0xFF,len);
		int f_read = open(filename, O_WRONLY);
		lseek (f_read, start_index, SEEK_CUR);
		write(f_read, zerobuf, len);
		close(f_read);
		free(zerobuf);
		log_debug("[%d] Key overwrite complete and buffers free'd", getpid() );
	}
}
long int get_file_size (char *filename) {
	struct stat st;
	long int size=0;
	stat(filename, &st);
	size = st.st_size;
	return size;
}

int encryptpacket(char *buf, unsigned int buflen, char *serializedbuf, char *keyfile,char* outbound_counter_file)
{	
	static long int tx_key_ref;
	int packet_size;
	unsigned char *xorbytes = malloc(buflen);
	memset(xorbytes, 0, buflen);
	char *key = malloc(buflen);
	memset(key, 0, buflen);
	long int tx_key_used = get_key_index(outbound_counter_file);
	
		getkey(keyfile,key,tx_key_used-buflen,buflen,TRUE);
		for(int i = 0; i < buflen; ++i)
		{
			xorbytes[i] = buf[i] ^ key[i];
		}

        tx_key_used = tx_key_used + buflen;
        set_key_index(outbound_counter_file, tx_key_used);
		
		binn *obj;
		obj = binn_object();
		binn_object_set_blob(obj, "packet", xorbytes,buflen);
		binn_object_set_int64(obj, "keyindex", tx_key_used-buflen);
		binn_object_set_int32(obj, "buflen", buflen);	
		memcpy(serializedbuf,binn_ptr(obj), binn_size(obj));
		packet_size = binn_size(obj);
		binn_free(obj);
		free(xorbytes);
		
		if (tx_key_used > tx_key_ref ) {
			long int key_file_size = get_file_size(keyfile);
			float key_presentage = (100.0*tx_key_used)/key_file_size;
			tx_key_ref = tx_key_used;
			log_debug("[%d] TX key used: %ld (of %ld) %.2f %%",getpid(),tx_key_used,key_file_size,key_presentage );
		}
	 return packet_size;
}

int decryptpacket(char *buf,char *rxbuffer,int readbytes,char* keyfile, char* inbound_counter_file)
{	
	static long int rx_key_ref;
	unsigned char *serializedbuf; 
	long int keyindex;
	int buflen;
	char *key;
	binn *obj;
    if ( readbytes < 4 ) 
    {
        log_error("[%d] de-serialization sanity check detected shorted than 4 bytes packet, discarding.",getpid());
        return 0;
    }
    if (binn_is_valid_ex(rxbuffer, NULL, NULL, &readbytes) == FALSE) 
    {
        log_error("[%d] de-serialization sanity check detected non valid packet, discarding.",getpid());
        return 0;
    }
	obj = binn_open(rxbuffer);
	keyindex = binn_object_int64(obj, "keyindex");
	buflen = binn_object_int32(obj, "buflen");
	serializedbuf = binn_object_blob(obj, "packet",&buflen);
	binn_free(obj);
	key = malloc(buflen);
	memset(key, 0, buflen);
	getkey(keyfile,key,keyindex-buflen,buflen,TRUE);	
	for(int i = 0; i < buflen; ++i)
	{
		buf[i] = serializedbuf[i] ^ key[i];
	}
	set_key_index(inbound_counter_file, keyindex + buflen );
	long int rx_key_used = keyindex + buflen;
	if (rx_key_used > rx_key_ref ) {	
		long int key_file_size = get_file_size(keyfile);
		float key_presentage = (100.0*rx_key_used)/key_file_size;
		rx_key_ref = rx_key_used;
		log_debug("[%d] RX key used: %ld (of %ld) %.2f %%",getpid(),rx_key_used,key_file_size,key_presentage );
	}
	return buflen;
}



int main (int argc, char *argv[])
{
	int c;
	opterr = 0;
    int fd_in, fd_out, nread;
    char buf_input[TRANSPORT_BUF_LEN];
    char buf_output[TRANSPORT_BUF_LEN];
    int serialized_output_len;
    unsigned char *base64_out_buffer;
    unsigned char *base64_in_buffer;
    size_t base64_outputlen;
    char *ini_file=NULL;
    char *incoming_pipe=NULL;
    char *outgoing_pipe=NULL;
    char *encrypt_keyfile=NULL;
    char *decrypt_keyfile=NULL;
    int operation_mode=0;
    size_t base64_inputlen;
    int decrypted_input_len;
    char plaintext[PLAINTEXT_BUF_LEN];
    
    char keyindex_filename_encrypt[KEY_INDEX_FILENAME_LEN];
    char keyindex_filename_decrypt[KEY_INDEX_FILENAME_LEN];
	
	while ((c = getopt (argc, argv, "i:hd")) != -1)
	switch (c)
	{
    case 'i':
        ini_file = optarg;
        break;
	case 'h':
		fprintf(stderr,"Usage: -i [ini-file] \n");
        fprintf(stderr,"       -d decrypt mode \n");
		return 1;
    case 'd':
		log_info("[%d] decrypt mode", getpid());
        operation_mode = DECRYPT_MODE;
		break;
	break;
		default:
		break;
	}
    /* Set logging */
    log_set_level(LOG_DEBUG);
    log_set_quiet(FALSE);
    log_info("[%d] otpmsg v0.1", getpid());
    
    /* Read ini-file */
    ini_t *config = ini_load(ini_file);
    ini_sget(config, "otpmsg", "incoming_pipe", NULL, &incoming_pipe);
    ini_sget(config, "otpmsg", "outgoing_pipe", NULL, &outgoing_pipe);
    ini_sget(config, "otpmsg", "encrypt_keyfile", NULL, &encrypt_keyfile);
    ini_sget(config, "otpmsg", "decrypt_keyfile", NULL, &decrypt_keyfile);
    
    log_info("[%d] incoming_pipe: %s", getpid(),incoming_pipe);
    log_info("[%d] outgoing_pipe: %s", getpid(),outgoing_pipe);
    log_info("[%d] encrypt_keyfile: %s", getpid(),encrypt_keyfile);
    log_info("[%d] decrypt_keyfile: %s", getpid(),decrypt_keyfile);
    
    memset(keyindex_filename_encrypt,0,KEY_INDEX_FILENAME_LEN); 
    memset(keyindex_filename_decrypt,0,KEY_INDEX_FILENAME_LEN); 
    sprintf(keyindex_filename_encrypt,"%s.index",encrypt_keyfile);
    sprintf(keyindex_filename_decrypt,"%s.index",decrypt_keyfile);

    if ((fd_in = open(incoming_pipe, O_RDONLY)) < 0)
    {
        log_error("[%d] Failed to open FIFO %s", getpid(),incoming_pipe );
        return 1;
    }
    if ((fd_out = open(outgoing_pipe, O_WRONLY)) < 0)
    {
        log_error("[%d] Failed to open FIFO %s", getpid(), outgoing_pipe);
        return 1;
    }
    log_info("[%d] Opened incoming and outgoing pipes", getpid());
    
    while(1) {
        memset(buf_input, 0, TRANSPORT_BUF_LEN);
        memset(buf_output, 0, TRANSPORT_BUF_LEN);
        nread = read(fd_in, buf_input, TRANSPORT_BUF_LEN-1);
        if (nread > 0) {         
            
            if ( operation_mode == ENCRYPT_MODE ) 
            {
                if ( nread < PLAINTEXT_BUF_LEN )
                {
                    serialized_output_len = encryptpacket(buf_input, strnlen(buf_input,TRANSPORT_BUF_LEN), buf_output, encrypt_keyfile, keyindex_filename_encrypt);
                    base64_out_buffer = base64_encode((unsigned char*)buf_output, serialized_output_len, &base64_outputlen);
                    if (write(fd_out, base64_out_buffer, base64_outputlen) <= 0)
                    {
                        log_error("[%d] Failed to write FIFO %s", getpid(), outgoing_pipe);
                        return 1;
                    }
                    free(base64_out_buffer);
                }
                else 
                {
                    log_error("[%d] Plain text too long, limit is: %d", getpid(), PLAINTEXT_BUF_LEN);
                }
            }
            
            if ( operation_mode == DECRYPT_MODE ) 
            {
                if ( nread < TRANSPORT_BUF_LEN )
                {
                    memset(plaintext, 0, PLAINTEXT_BUF_LEN);
                    base64_in_buffer = base64_decode((unsigned char*)buf_input, strnlen(buf_input,TRANSPORT_BUF_LEN),&base64_inputlen);
                    if ( base64_in_buffer != NULL )
                    {
                        decrypted_input_len = decryptpacket(plaintext,(char *)base64_in_buffer,base64_inputlen,decrypt_keyfile, keyindex_filename_decrypt);
                        if (write(fd_out, plaintext, decrypted_input_len) <= 0)
                        {
                            log_error("[%d] Failed to write FIFO %s", getpid(), outgoing_pipe);
                            return 1;
                        }
                    }
                    free(base64_in_buffer);
                } 
                else
                {
                    log_error("[%d] Transport data too long, limit is: %d", getpid(), TRANSPORT_BUF_LEN);
                }
            }
        }
        sleep(0.5);
    }    
    return 0;
}
