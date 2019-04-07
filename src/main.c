/*
** Copyright (C) 2015 Yuwu Xiong <sansidee@foxmail.com>
**  
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
** 
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
** 
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software 
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "si.h"
#include "libsi.h"
#include "tree.h"
#include "save_html.h"


/* list struct to hold argument of change pid(s) '-c' */
typedef struct _PID_PAIR_NODE{
	unsigned short         old_pid;
	unsigned short         new_pid;
	struct _PID_PAIR_NODE* next;
}PID_PAIR_NODE;

typedef struct{
	int            pid_pair_nr;
	PID_PAIR_NODE* head;
}PID_PAIR_LIST;

#define MAX_TS_SIZE  (500*1024*1024)  // 500MiB should be bigger enough

static void process_args(int argc, char* argv[]);
static void process_change_pid_arg(const char *change_pid_arg, PID_PAIR_LIST* list);
static void process_del_extr_pid_arg(const char *pid_arg, PID_PAIR_LIST* list);
static void show_help(void);
static void show_version(void);
static void cleanup_and_exit(int exit_code);

static int s_is_show_help = 0;
static int s_is_show_version = 0;
static int s_is_verbose = 0;
static int s_is_204to188 = 0;
static int s_is_188to204 = 0;
static int s_is_slim = 0; // remove video/audio/null pids
static int s_is_change_pid = 0;
static char* s_change_pid_arg = 0;
static int s_is_delete_pid = 0;
static char* s_delete_pid_arg = 0;
static int s_is_extract_pid = 0;
static char* s_extract_pid_arg = 0;
static int s_is_defrag = 0;
static int s_is_save_as_html = 0;
static char* s_save_as_dir = 0;  /* directory to save result in html */
static int s_is_output_file = 0;
static char* s_output_file = 0;  /* output file name */
static char* s_input_file = 0;

static char s_cwd[FILENAME_MAX + 1]; /* current work dir */
static struct stat s_input_stat; /* stat of input file */
static int s_input_fd = - 1;     /* descriptor of input file */
static int s_ts_size;  // the size of the ts to be analyzed (mmapped).
static u8* s_p_input_file = 0;   /* point to begining of input file memory */
static TSR_RESULT* s_result = 0; /* analysis result */

static char s_optstring[] = "hVv12lc:d:e:fo:s:";

static struct option const s_long_options[] = {
	{"help",     no_argument,       0, 'h'},
	{"version",  no_argument,       0, 'V'},
	{"verbose",  no_argument,       0, 'v'},

	{"204to188", no_argument,       0, '1'}, 
	{"188to204", no_argument,       0, '2'}, 
    {"slim",     no_argument,       0, 'l'}, 
	{"change",   required_argument, 0, 'c'},
	{"delete",   required_argument, 0, 'd'},
	{"extract",  required_argument, 0, 'e'},
	{"defrag",   no_argument,       0, 'f'},

	{"save",     required_argument, 0, 's'},  /* specify directory to save html result */
	{"output",   required_argument, 0, 'o'},  /* specify output file name */

	{0, 0, 0, 0}
};


int main(int argc, char* argv[]){

        
	process_args(argc, argv);


	if(s_is_show_help){
		show_help();
		exit(0);
	}
	
	if(s_is_show_version){
		show_version();
		exit(0);
	}

	/* get the current_work_directory */
	if(getcwd(s_cwd, FILENAME_MAX) == NULL){
		fprintf(stderr, "getcwd() fail, errno=%d, abort.\n", errno);
		exit(1);
	}

	/* get the file stat */
	if(stat(s_input_file, &s_input_stat)){
		fprintf(stderr, "stat(%s) failed, errno=%d(%s), abort.\n", s_input_file, errno, strerror(errno));
		exit(1);
	}

	/* get the file descriptor */
	if((s_input_fd = open(s_input_file, O_RDONLY)) == - 1){
		fprintf(stderr, "cann't open file %s, errno=%d, abort.\n", s_input_file, errno); 
		exit(1);
	}

    s_ts_size = s_input_stat.st_size;
#if (0)    
    if (ts_size > MAX_TS_SIZE) {
        ts_size = MAX_TS_SIZE;
    }
#endif

	/* mmap the whole file */
	if((s_p_input_file = (u8*)mmap(0, s_ts_size, PROT_READ, MAP_SHARED, s_input_fd, 0)) == MAP_FAILED){
		fprintf(stderr, "mmap file %s failed, errno=%d, abort.\n", s_input_file, errno); 
		cleanup_and_exit(1);
	}

    s_result = build_tsr_result(s_input_file, s_p_input_file, s_ts_size, s_is_verbose);

	if(!s_result){
		fprintf(stderr, "build_tsr_result() failed, abort.\n"); 
		cleanup_and_exit(1);
	}

	summarize_result(stdout, s_result);
	fprintf(stdout, "for details, view the html format result (-s option).\n\n");

	/*** 204 to 188: save to output file, then exit */

	if(s_is_204to188){

		FILE* fpo;
		int   i;

		if(s_result->packet_size == 188){
			fprintf(stderr, "204 to 188: packet size already 188 bytes, do nothing.\n");
			cleanup_and_exit(1);
		}

		if(!s_is_output_file || !s_output_file){
			fprintf(stderr, "204 to 188: output file not specified, do nothing.\n");
			cleanup_and_exit(1); 
		}

		if((fpo = fopen(s_output_file, "wb")) == NULL){
			fprintf(stderr, "204 to 188: can't open output file %s for writing, errno=%d, abort.\n", s_output_file, errno);
			cleanup_and_exit(1);
		}

		for(i = 0; i < s_result->packet_nr; i ++)
			fwrite(s_result->ts_data + s_result->packet_size * i, 188, 1, fpo);

		fclose(fpo);
		
		fprintf(stdout, "204 to 188: saved to %s successfully!\n", s_output_file); 
		
		cleanup_and_exit(0);
	}




	/*** 188 to 204: save to output file, then exit */

	if(s_is_188to204){

		FILE*         fpo;
		int           i;
		unsigned char stuff[204 - 188];

		if(s_result->packet_size == 204){
			fprintf(stderr, "188 to 204: packet size already 204 bytes, do nothing.\n");
			cleanup_and_exit(1);
		}

		if(!s_is_output_file || !s_output_file){
			fprintf(stderr, "188 to 204: output file not specified, do nothing.\n");
			cleanup_and_exit(1); 
		}

		if((fpo = fopen(s_output_file, "wb")) == NULL){
			fprintf(stderr, "188 to 204: can't open output file %s for writing, errno=%d, abort.\n", s_output_file, errno);
			cleanup_and_exit(1);
		}

		for(i = 0; i < 204 - 188; i ++)
			stuff[i] = 0;

		for(i = 0; i < s_result->packet_nr; i ++){
			fwrite(s_result->ts_data + s_result->packet_size * i, 188, 1, fpo);
			fwrite(stuff, 204 - 188, 1, fpo);
		}

		fclose(fpo);

		fprintf(stdout, "188 to 204: saved to %s successfully!\n", s_output_file); 
		
		cleanup_and_exit(0);
	}


    /*** slim */
	if (s_is_slim) {

		FILE*         fpo;
		int           i;
        u8*           p;
        PID_NODE*     pid_node;
        u16           pid;
        int           keep = 1;

		if(!s_is_output_file || !s_output_file){
			fprintf(stderr, "slim: output file not specified, do nothing.\n");
			cleanup_and_exit(1); 
		}

		if((fpo = fopen(s_output_file, "wb")) == NULL){
			fprintf(stderr, "slim: can't open output file %s for writing, errno=%d, abort.\n", s_output_file, errno);
			cleanup_and_exit(1);
		}

        for (i = 0; i < s_result->packet_nr; i ++) {
            p = s_result->ts_data + s_result->packet_size * i;
            keep = 1;
            pid = packet_pid(p);

            if (pid == PID_NUL) {
                keep = 0;
            } else {
            	for (pid_node = s_result->pid_list->head; pid_node != 0; pid_node = pid_node->next) {
                        if (pid_node->pid == pid && 
                           ((pid_node->stream_type == STREAMTYPE_11172_AUDIO) ||
                            (pid_node->stream_type == STREAMTYPE_11172_VIDEO) ||                       
                            (pid_node->stream_type == STREAMTYPE_13818_AUDIO) ||                       
                            (pid_node->stream_type == STREAMTYPE_13818_VIDEO) ||                       
                            (pid_node->stream_type == STREAMTYPE_H264_VIDEO) ||                       
                            (pid_node->stream_type == STREAMTYPE_AAC_AUDIO) ||                       
                            (pid_node->stream_type == STREAMTYPE_AC3_AUDIO) ||                       
                            (pid_node->stream_type == STREAMTYPE_AVS_VIDEO) ||                       
                            (pid_node->stream_type == STREAMTYPE_MPEG4_AUDIO))) {
                            keep = 0;
                            break;
                    }
                }
            }
                    
            if(!keep){
                continue;
            }

            fwrite(p, s_result->packet_size, 1, fpo);
        }

		fclose(fpo);

		fprintf(stdout, "slim: saved to %s successfully!\n", s_output_file); 
		
		cleanup_and_exit(0);
	}

	/*** change pid(s) */

	if(s_is_change_pid){
		
		FILE*          fpo;
		PID_PAIR_NODE* node = NULL;
		PID_PAIR_LIST  list = {0, NULL};
		int            i, match;
		unsigned short old_pid = 0, new_pid = 0;
#ifdef NO_STRICT_ALIASING // gcc: -fno-strict-aliasing
		unsigned char  packet[204];
#else
        union {
            unsigned char packet[204];
            PACKET_HEADER hdr;
        } u_packet;
#endif
		unsigned char* p;

		process_change_pid_arg(s_change_pid_arg, &list);

#if (0)
		fprintf(stdout, "change_pid: pid_pair_nr = %d\n", list.pid_pair_nr);
		for(node = list.head; node != NULL; node = node->next){
			fprintf(stdout, "  %d:%d\n", node->old_pid, node->new_pid);
		}	
#endif

		if(list.pid_pair_nr == 0){
			fprintf(stderr, "change pid(s): change pid argument %s invalid, abort.\n", s_change_pid_arg);
			cleanup_and_exit(1);
		}

		if(!s_is_output_file || !s_output_file){
			fprintf(stderr, "change pid(s): output file not specified, do nothing.\n");
			cleanup_and_exit(1); 
		}

		if((fpo = fopen(s_output_file, "wb")) == NULL){
			fprintf(stderr, "change pid(s): can't open output file %s for writing, errno=%d, abort.\n", s_output_file, errno);
			cleanup_and_exit(1);
		}

		for(i = 0; i < s_result->packet_nr; i ++){
			p = s_result->ts_data + s_result->packet_size * i;
			old_pid = packet_pid(p);
			match = 0;
			for(node = list.head; node != NULL; node = node->next){
				if(node->old_pid == old_pid){
					match = 1;
					new_pid = node->new_pid;
					break;
				}
			}
			if(match){
#ifdef NO_STRICT_ALIASING // gcc: -fno-strict-aliasing
				memcpy(packet, p, s_result->packet_size);
				((PACKET_HEADER*)packet)->pid_hi 
                    = new_pid / 256;
				((PACKET_HEADER*)packet)->pid_lo = new_pid % 256;
				fwrite(packet, s_result->packet_size, 1, fpo);
#else
                memcpy(u_packet.packet, p, s_result->packet_size);
                u_packet.hdr.pid_hi = new_pid / 256;
                u_packet.hdr.pid_lo = new_pid % 256;
                fwrite(u_packet.packet, s_result->packet_size, 1, fpo);
#endif
			}
			else{
				fwrite(p, s_result->packet_size, 1, fpo);
			}
		}


		/* free allocated nodes */
		for(; list.head != NULL;){
			node = list.head->next;
			free(list.head);
			list.head = node;
		}

		fclose(fpo);

		fprintf(stdout, "change pid(s): saved to %s successfully!\n", s_output_file); 

		cleanup_and_exit(0);
	}



	/*** delete pid(s) */

	if(s_is_delete_pid){
		
		FILE*          fpo;
		PID_PAIR_NODE* node = NULL; /* only use the old_pid field */
		PID_PAIR_LIST  list = {0, NULL}; 
		int            i, match;
		unsigned short pid;
		unsigned char* p;

		process_del_extr_pid_arg(s_delete_pid_arg, &list);

#if (0)
		fprintf(stdout, "delete_pid: pid nr = %d\n", list.pid_pair_nr);
		for(node = list.head; node != NULL; node = node->next){
			fprintf(stdout, "  %d\n", node->old_pid);
		}	
#endif

		if(list.pid_pair_nr == 0){
			fprintf(stderr, "delete pid(s): delete pid argument %s invalid, abort.\n", s_delete_pid_arg);
			cleanup_and_exit(1);
		}

		if(!s_is_output_file || !s_output_file){
			fprintf(stderr, "delete pid(s): output file not specified, do nothing.\n");
			cleanup_and_exit(1); 
		}

		if((fpo = fopen(s_output_file, "wb")) == NULL){
			fprintf(stderr, "delete pid(s): can't open output file %s for writing, errno=%d, abort.\n", s_output_file, errno);
			cleanup_and_exit(1);
		}

		for(i = 0; i < s_result->packet_nr; i ++){
			p = s_result->ts_data + s_result->packet_size * i;
			pid = packet_pid(p);
			match = 0;
			for(node = list.head; node != NULL; node = node->next){
				if(node->old_pid == pid){
					match = 1;
					break;
				}
			}
			if(match){
				continue;
			}
			else{
				fwrite(p, s_result->packet_size, 1, fpo);
			}
		}


		/* free allocated nodes */
		for(; list.head != NULL;){
			node = list.head->next;
			free(list.head);
			list.head = node;
		}

		fclose(fpo);

		fprintf(stdout, "delete pid(s): saved to %s successfully!\n", s_output_file); 

		cleanup_and_exit(0);
	}


	/*** extract pid(s) */

	if(s_is_extract_pid){
		
		FILE*          fpo;
		PID_PAIR_NODE* node = NULL; /* only use the old_pid field */
		PID_PAIR_LIST  list = {0, NULL}; 
		int            i, match;
		unsigned short pid;
		unsigned char* p;

		process_del_extr_pid_arg(s_extract_pid_arg, &list);

#if (0)
		fprintf(stdout, "extract_pid: pid nr = %d\n", list.pid_pair_nr);
		for(node = list.head; node != NULL; node = node->next){
			fprintf(stdout, "  %d\n", node->old_pid);
		}	
#endif

		if(list.pid_pair_nr == 0){
			fprintf(stderr, "extract pid(s): extract pid argument %s invalid, abort.\n", s_delete_pid_arg);
			cleanup_and_exit(1);
		}

		if(!s_is_output_file || !s_output_file){
			fprintf(stderr, "extract pid(s): output file not specified, do nothing.\n");
			cleanup_and_exit(1); 
		}

		if((fpo = fopen(s_output_file, "wb")) == NULL){
			fprintf(stderr, "extract pid(s): can't open output file %s for writing, errno=%d, abort.\n", s_output_file, errno);
			cleanup_and_exit(1);
		}

		for(i = 0; i < s_result->packet_nr; i ++){
			p = s_result->ts_data + s_result->packet_size * i;
			pid = packet_pid(p);
			match = 0;
			for(node = list.head; node != NULL; node = node->next){
				if(node->old_pid == pid){
					match = 1;
					break;
				}
			}
			if(match){
				fwrite(p, s_result->packet_size, 1, fpo);
			}
			else{
				continue;
			}
		}


		/* free allocated nodes */
		for(; list.head != NULL;){
			node = list.head->next;
			free(list.head);
			list.head = node;
		}

		fclose(fpo);

		fprintf(stdout, "extract pid(s): saved to %s successfully!\n", s_output_file); 

		cleanup_and_exit(0);
	}



	/*** defrag */

	if(s_is_defrag){
		
		FILE*         fpo;

		if(s_result->file_data == s_result->ts_data){
			fprintf(stderr, "defrag: nothing to be defraged.\n");
			cleanup_and_exit(1);
		}

		if(!s_is_output_file || !s_output_file){
			fprintf(stderr, "defrag: output file not specified, do nothing.\n");
			cleanup_and_exit(1); 
		}
		
		if((fpo = fopen(s_output_file, "wb")) == NULL){
			fprintf(stderr, "defrag: can't open output file %s for writing, errno=%d, abort.\n", s_output_file, errno);
			cleanup_and_exit(1);
		}

		fwrite(s_result->ts_data, s_result->packet_size * s_result->packet_nr, 1, fpo);
		
		fclose(fpo);

		fprintf(stdout, "defrag: saved to %s successfully!\n", s_output_file); 
		
		cleanup_and_exit(0);
	}

	/*** save as html */

	if(s_is_save_as_html){
		struct stat dir_stat;
		int         c;
		if(stat(s_save_as_dir, &dir_stat) || !(dir_stat.st_mode & S_IFDIR)){
			fprintf(stderr, "%s does not exist, create it or not (Y/n)?", s_save_as_dir);
			c = getchar();
			if(c == 'y' || c == 'Y' || c == '\n'){ 
				if(mkdir(s_save_as_dir, 0777)){
					fprintf(stderr, "can not create directory %s, abort.\n", s_save_as_dir);
					cleanup_and_exit(1);
				}
			}
			else{
				cleanup_and_exit(1);
			}
		}
		if(chdir(s_save_as_dir)){
			fprintf(stderr, "chdir(%s) fail. errno=%d, abort.\n", s_save_as_dir, errno);
			cleanup_and_exit(1);
		}
		save_as_html(s_result);
		/* change back to original cwd */
		chdir(s_cwd);
	}

	cleanup_and_exit(0);

    return 0; // just eliminate gcc warning
}

static void process_args(int argc, char* argv[]){
	int c, option_index;

	if(argc == 1){
		s_is_show_help = 1;
		return;
	}

	for(;;){
		c =  getopt_long(argc, argv, s_optstring, s_long_options, &option_index);
		if(c == - 1)
			break;
		switch(c){
			case 'h': 
				s_is_show_help = 1; 
				break;
			case 'V': 
				s_is_show_version = 1; 
				break;
			case 'v': 
				s_is_verbose = 1; 
				break;
			case '1': 
				s_is_204to188 = 1; 
				break;
			case '2': 
				s_is_188to204 = 1; 
				break;
            case 'l':
                s_is_slim = 1;
                break;
			case 'c': 
				s_is_change_pid = 1; 
				s_change_pid_arg = optarg;
				break;
			case 'd': 
				s_is_delete_pid = 1; 
				s_delete_pid_arg = optarg;
				break;
			case 'e': 
				s_is_extract_pid = 1; 
				s_extract_pid_arg = optarg;
				break;
			case 'f': 
				s_is_defrag = 1;
				break;
			case 'o': 
				s_is_output_file = 1;
				s_output_file = optarg; 
				break;
			case 's': 
				s_is_save_as_html = 1;
				s_save_as_dir = optarg; 
				break;
			default:
				break;
		}
	}

	if(optind < argc){
		s_input_file = argv[optind];
	}
	else{
		if(!s_is_show_version)
			s_is_show_help = 1;
	}
}

/* "change_pid_arg" format is:   old_pid:new_pid
where pid number can be either specified in hex (prefix by '0x') or decimal; 
if multiple pids need to be changed, using ',' to separate each pid pair; 
space is not allowed in the option argument. */
static void process_change_pid_arg(const char *change_pid_arg, PID_PAIR_LIST* list){

	PID_PAIR_NODE  *tail = NULL, *node = NULL;
	unsigned int   old_pid, new_pid;
	const char     *p1, *p2;

	list->pid_pair_nr = 0;
	if(change_pid_arg == NULL)
		return;
		
	p1 = change_pid_arg;
	while(1){    /* for each pid pair */

		/* old_pid goes first, before ':' */

		p2 = strstr(p1, ":");
		if(!p2)
			goto ERROR;
		p2 += 1;

		if(*p1 == '0' && (*(p1 + 1) == 'x' || *(p1 + 1) == 'X')){
			if(sscanf(p1 + 2, "%x:", &old_pid) != 1)
				goto ERROR;
		}
		else{
			if(sscanf(p1, "%ud:", &old_pid) != 1)
				goto ERROR;
		}
		if(old_pid > PID_NUL)
			goto ERROR;
		
		/* new_pid goes secondly, possiblely before ',' */
		
		if(*p2 == '0' && (*(p2 + 1) == 'x' || *(p2 + 1) == 'X')){
			if(sscanf(p2 + 2, "%x:", &new_pid) != 1)
				goto ERROR;
		}
		else{
			if(sscanf(p2, "%ud:", &new_pid) != 1)
				goto ERROR;
		}
		if(new_pid > PID_NUL)
			goto ERROR;
		
		/* one pid pair found, add to the list */
		node = (PID_PAIR_NODE*)malloc(sizeof(PID_PAIR_NODE));
		if(node == NULL)
			goto ERROR;
		node->old_pid = (unsigned short)old_pid;
		node->new_pid = (unsigned short)new_pid;
		node->next = NULL;
		if(tail == NULL){ /* the first node */
			list->head = node;
			tail = node;
		}
		else{
			tail->next = node;
			tail = node;
		}
		list->pid_pair_nr ++;
		
		/* search the start of the next pid pair */
		p1 = strstr(p2, ",");
		if(p1 == NULL){
			break;
		}
		else{
			p1 += 1;
		}
	}

	return;

ERROR:	
	/* free allocated nodes */
	for(; list->head != NULL;){
		node = list->head->next;
		free(list->head);
		list->head = node;
	}
	list->pid_pair_nr = 0;
	return;
}

/* "pid_arg" format is:   pid[,pid[,pid]]
where pid number can be either specified in hex (prefix by '0x') or decimal; 
if there is multiple pids, using ',' to separate each pid; space is not 
allowed in the option argument. */
static void process_del_extr_pid_arg(const char *pid_arg, PID_PAIR_LIST* list){

	PID_PAIR_NODE  *tail = NULL, *node = NULL;
	unsigned int   pid;
	const char     *p1, *p2;

	list->pid_pair_nr = 0;
	if(pid_arg == NULL)
		return;
		
	p1 = pid_arg;
	while(1){    /* for each pid */

		if(*p1 == '0' && (*(p1 + 1) == 'x' || *(p1 + 1) == 'X')){
			if(sscanf(p1 + 2, "%x", &pid) != 1)
				goto ERROR;
		}
		else{
			if(sscanf(p1, "%ud:", &pid) != 1)
				goto ERROR;
		}
		if(pid > PID_NUL)
			goto ERROR;
		
		/* one pid found, add to the list */
		node = (PID_PAIR_NODE*)malloc(sizeof(PID_PAIR_NODE));
		if(node == NULL)
			goto ERROR;
		node->old_pid = (unsigned short)pid;
		node->next = NULL;
		if(tail == NULL){ /* the first node */
			list->head = node;
			tail = node;
		}
		else{
			tail->next = node;
			tail = node;
		}
		list->pid_pair_nr ++;
		
		/* search the start of the next pid pair */
		p2 = strstr(p1, ",");
		if(p2 == NULL){
			break;
		}
		else{
			p1 = p2 + 1;
		}
	}

	return;

ERROR:	
	/* free allocated nodes */
	for(; list->head != NULL;){
		node = list->head->next;
		free(list->head);
		list->head = node;
	}
	list->pid_pair_nr = 0;
	return;
}


static void show_help(void){

	fprintf(stderr, "Usage: %s [options] ... ts_file\n\n", PACKAGE);

	fprintf(stderr, 
"Analyzes and manipulates the ts_file, such as:\n"
"  - print brief analysis result (by default)\n"
"  - change packe size from 204 to 188 bytes\n"
"  - change packe size from 188 to 204 bytes\n"
"  - change pid(s) in the ts_file\n"
"  - delete pid(s) from the ts_file\n"
"  - extract pid(s) from the ts_file\n"
"  - defrag the ts_file and save it\n"
"  - save the analysis result in html format\n\n");

	fprintf(stderr, 
"Options:\n"
"  -h, --help       print this help, then exit\n"
"  -V, --version    print version info, then exit\n"
"  -v, --verbose    verbosely report processing\n"
"  -1, --204to188   change packet size from 204 to 188 bytes, save new ts\n"
"                   as specified by -o option, then exit\n"
"  -2, --188to204   change packet size from 188 to 204 bytes, save new ts\n"
"                   as specified by -o option, then exit\n"
"  -l, --slim       remove audio/video/null pids, and save into a new file\n"
"  -c, --change     change pid(s) according to the option argument, save new\n"
"                   ts as specified by -o option, then exit. the argument\n"
"                   format is 'old_pid:new_pid[,old_pid:new_pid]', the pid\n"
"                   number can be either in hex (prefixed by '0x') or decimal;\n"
"                   multiple pid pairs are delimited by ','; space is not\n"
"                   allowed.\n"
"                   e.g., -c 100:200,0x100:0x200,200:0x300\n" 
"  -d, --delete     delete pid(s) according to the option argument, save new\n"
"                   ts as specified by -o option, then exit. the argument\n"
"                   format is 'pid[,pid]', the pid number can be either in\n"
"                   hex (prefixed by '0x') or decimal; multiple pids are\n"
"                   delimited by ','; space is not allowed.\n" 
"                   e.g., -d 100,200,0x100\n" 
"  -e, --extract    extract pid(s) according to the option argument, save new\n"
"                   ts as specified by -o option, then exit. the argument\n"
"                   format is 'pid[,pid]', the pid number can be either in\n"
"                   hex (prefixed by '0x') or decimal; multiple pids are\n"
"                   delimited by ','; space is not allowed.\n" 
"                   e.g., -e 100,200,0x100\n" 
"  -f, --defrag     remove opentv header and/or broken packets at head/tail,\n"
"                   save new ts as specified by -o option, then exit\n"
"  -o, --output     specify output file in the option argument\n"
"  -s, --save       save html analysis result under a directory specified by\n"
"                   the option argument\n"
"\n");

	fprintf(stderr, "Please report bugs to Yuwu Xiong <sansidee@foxmail.com>\n");
}

static void show_version(void){
	fprintf(stderr, "%s %s\n", PACKAGE, VERSION); 
}

static void cleanup_and_exit(int exit_code){

	if(s_result)
		delete_tsr_result(s_result);
#if (0)
	if(s_p_input_file)
		free(s_p_input_file);
#endif
	if(s_p_input_file)
		munmap(s_p_input_file, s_ts_size);
	if(s_input_fd != - 1)
		close(s_input_fd);
	exit(exit_code);
}
