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

#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "si.h"
#include "tree.h"
#include "section_filter.h"
#include "libsi.h"

#define TXT_BUF_SIZE   4096
#define PRINTABLE_CODE(x)   (((x >= 0x20) && (x <= 0x7e))? x : '.')
#define UIMSBF16(p)  ((((unsigned int)p[0]) << 8) + p[1])
#define UIMSBF32(p)  ((((unsigned int)p[0]) << 24) + (((unsigned int)p[1]) << 16) + (((unsigned int)p[2]) << 8) + p[3])
/*--------------------------------------------------------------------+
 | static variables                                                   |
 +--------------------------------------------------------------------*/

static const char s_otv_magic[] = "OTV :-) ";  /* added(bruin, 2003.01.18) */
static int s_is_verbose = 0;                   /* added(bruin, 2004-06-16) */


/*--------------------------------------------------------------------+
 | forward declaration of private routines                            |
 +--------------------------------------------------------------------*/

static PID_LIST* s_create_pid_list(void);
static PID_NODE* s_create_pid_node(u16 pid);
static int s_delete_pid_node(PID_NODE* pid_node);
static int s_add_packet_to_pid_list(PID_LIST* pid_list, u16 pid, int packet_index);
static int s_add_packet_to_pid_node(PID_NODE* pid_node, int packet_index);
static int s_add_pid_node_to_list(PID_LIST* pid_list, PID_NODE* pid_node);

//static int s_add_section_to_table(TABLE* tbl, u8 index, int size, u8 *data, int dedup);
static int s_add_section_to_table(TABLE* tbl, int size, u8 *data, int dedup);
//static u16 s_get_section_data(u16 pid, u8 tid, u8 section_nr, PID_LIST* list, u8* ts, u8 packet_size, u8* last_section_nr, u8** pp);
static u16 s_get_any_section_data(u16 pid, u8 table_id, PID_LIST* pid_list, int* packet_idx, u8 packet_size, u8* p_ts, u8** pp);

static void s_add_otv_header(OTV_HEADER* header, TNODE* root);
static long s_get_table_section_size_sum(TABLE* tbl);
static void s_add_table(TABLE* tbl, TNODE* root);
static void s_add_tables(TABLE** tbl, TNODE* root, PID_LIST* pid_list, void* tbl_list);
static void s_add_pids(TSR_RESULT* result, TNODE* root, int max_packet);
static void s_add_packets(TSR_RESULT* result, TNODE* root, int max_packet);

/* parse sections in each table */
static void s_parse_sect_pat(TNODE* sect_root, TABLE *tbl_pat, int index);
static void s_parse_sect_cat(TNODE* sect_root, TABLE *tbl_cat, int index);
static void s_parse_sect_nit(TNODE* sect_root, TABLE* tbl_nit, int index);
static void s_parse_sect_pmt(TNODE* sect_root, TABLE *tbl_pmt, int index, PID_LIST* pid_list);
static void s_parse_sect_ait(TNODE* sect_root, TABLE *tbl_pmt, int index, PID_LIST* pid_list);
static void s_parse_sect_bat(TNODE* sect_root, TABLE *tbl_bat, int index);
static void s_parse_sect_sdt(TNODE* sect_root, TABLE *tbl_sdt, int index);
static void s_parse_sect_eit(TNODE* sect_root, TABLE *tbl_eit, int index);
static void s_parse_sect_tdt(TNODE* sect_root, TABLE *tbl_tdt, int index);
static void s_parse_sect_tot(TNODE* sect_root, TABLE *tbl_tot, int index);
static void s_parse_sect_rst(TNODE* sect_root, TABLE *tbl_rst, int index);


/* parse dvb-si descriptors loop */
static int s_parse_descriptors_loop(u8* p, int loop_len, TNODE* root);

/* parse each dvb-si descriptor */
static void s_parse_desc_ac3(u8* p, TNODE* root);
static void s_parse_desc_ancillary_data(u8* p, TNODE* root);
static void s_parse_desc_announcement_support(u8* p, TNODE* root);
static void s_parse_desc_application_signalling(u8* p, TNODE* root);
static void s_parse_desc_audio_stream(u8* p, TNODE* root);
static void s_parse_desc_bouquet_name(u8* p, TNODE* root);
static void s_parse_desc_ca(u8* p, TNODE* root);
static void s_parse_desc_ca_identifier(u8* p, TNODE* root);
static void s_parse_desc_ca_system(u8* p, TNODE* root);
static void s_parse_desc_cable_delivery_system(u8* p, TNODE* root);
static void s_parse_desc_cell_frequency_link(u8* p, TNODE* root);
static void s_parse_desc_cell_list(u8* p, TNODE* root);
static void s_parse_desc_component(u8* p, TNODE* root);
static void s_parse_desc_content(u8* p, TNODE* root);
static void s_parse_desc_copyright(u8* p, TNODE* root);
static void s_parse_desc_country_availability(u8* p, TNODE* root);
static void s_parse_desc_data_broadcast(u8* p, TNODE* root);
static void s_parse_desc_data_broadcast_id(u8* p, TNODE* root);
static void s_parse_desc_data_stream_alignment(u8* p, TNODE* root);
static void s_parse_desc_dsng(u8* p, TNODE* root);
static void s_parse_desc_extended_event(u8* p, TNODE* root);
static void s_parse_desc_frequency_list(u8* p, TNODE* root);
static void s_parse_desc_hierarchy(u8* p, TNODE* root);
static void s_parse_desc_ibp(u8* p, TNODE* root);
static void s_parse_desc_carousel_identifier(u8* p, TNODE* root);
static void s_parse_desc_iso639_language(u8* p, TNODE* root);
static void s_parse_desc_linkage(u8* p, TNODE* root);
static void s_parse_desc_local_time_offset(u8* p, TNODE* root);
static void s_parse_desc_maximum_bitrate(u8* p, TNODE* root);
static void s_parse_desc_mosaic(u8* p, TNODE* root);
static void s_parse_desc_multilingual_network_name(u8* p, TNODE* root);
static void s_parse_desc_multilingual_bouquet_name(u8* p, TNODE* root);
static void s_parse_desc_multilingual_service_name(u8* p, TNODE* root);
static void s_parse_desc_multilingual_component(u8* p, TNODE* root);
static void s_parse_desc_multiplex_buffer_utilization(u8* p, TNODE* root);
static void s_parse_desc_network_name(u8* p, TNODE* root);
static void s_parse_desc_nvod_reference(u8* p, TNODE* root);
static void s_parse_desc_opentv_track_tag(u8* p, TNODE* root);
static void s_parse_desc_parental_rating(u8* p, TNODE* root);
static void s_parse_desc_partial_transport_stream(u8* p, TNODE* root);
static void s_parse_desc_pdc(u8* p, TNODE* root);
static void s_parse_desc_private_data_indicator(u8* p, TNODE* root);
static void s_parse_desc_private_data_specifier(u8* p, TNODE* root);
static void s_parse_desc_registration(u8* p, TNODE* root);
static void s_parse_desc_satellite_delivery_system(u8* p, TNODE* root);
static void s_parse_desc_service(u8* p, TNODE* root);
static void s_parse_desc_service_identifier(u8* p, TNODE* root);
static void s_parse_desc_service_list(u8* p, TNODE* root);
static void s_parse_desc_service_move(u8* p, TNODE* root);
static void s_parse_desc_short_event(u8* p, TNODE* root);
static void s_parse_desc_short_smoothing_buffer(u8* p, TNODE* root);
static void s_parse_desc_smoothing_buffer(u8* p, TNODE* root);
static void s_parse_desc_std(u8* p, TNODE* root);
static void s_parse_desc_stream_identifier(u8* p, TNODE* root);
static void s_parse_desc_stuffing(u8* p, TNODE* root);
static void s_parse_desc_subtitling(u8* p, TNODE* root);
static void s_parse_desc_system_clock(u8* p, TNODE* root);
static void s_parse_desc_target_background_grid(u8* p, TNODE* root);
static void s_parse_desc_telephone(u8* p, TNODE* root);
static void s_parse_desc_teletext(u8* p, TNODE* root);
static void s_parse_desc_terrestrial_delivery_system(u8* p, TNODE* root);
static void s_parse_desc_time_shifted_event(u8* p, TNODE* root);
static void s_parse_desc_time_shifted_service(u8* p, TNODE* root);
static void s_parse_desc_transport_stream(u8* p, TNODE* root);
static void s_parse_desc_vbi_data(u8* p, TNODE* root);
static void s_parse_desc_vbi_teletext(u8* p, TNODE* root);
static void s_parse_desc_video_stream(u8* p, TNODE* root);
static void s_parse_desc_video_window(u8* p, TNODE* root);
static void s_parse_desc_rcs_content(u8* p, TNODE* root); /* added(bruin, 2003.02.17) */
static void s_parse_desc_logical_channel(u8* p, TNODE* root); /* added(bruin, 2003.12.18) */

/* parse mhp descriptors loop */
static int s_parse_mhp_descriptors_loop(u8* p, int loop_len, TNODE* root);

/* parse each mhp descriptor */
static void s_parse_mhp_desc_application(u8* p, TNODE* root);
static void s_parse_mhp_desc_application_name(u8* p, TNODE* root);   
static void s_parse_mhp_desc_transport_protocol(u8* p, TNODE* root);
static void s_parse_mhp_desc_dvb_j_application(u8* p, TNODE* root);
static void s_parse_mhp_desc_dvb_j_application_location(u8* p, TNODE* root);
static void s_parse_mhp_desc_external_application_authorization(u8* p, TNODE* root);
static void s_parse_mhp_desc_ipv4_routing(u8* p, TNODE* root);
static void s_parse_mhp_desc_ipv6_routing(u8* p, TNODE* root);
static void s_parse_mhp_desc_dvb_html_application(u8* p, TNODE* root);
static void s_parse_mhp_desc_dvb_html_application_location(u8* p, TNODE* root);
static void s_parse_mhp_desc_dvb_html_application_boundary(u8* p, TNODE* root);
static void s_parse_mhp_desc_application_icons(u8* p, TNODE* root);
static void s_parse_mhp_desc_prefetch(u8* p, TNODE* root);
static void s_parse_mhp_desc_dll_location(u8* p, TNODE* root);
static void s_parse_mhp_desc_delegated_application(u8* p, TNODE* root);
static void s_parse_mhp_desc_plug_in(u8* p, TNODE* root);
static void s_parse_mhp_desc_private_data_specifier(u8* p, TNODE* root);


/*--------------------------------------------------------------------+
 |                                                                    |
 | public routines definition                                         |
 |                                                                    |
 +--------------------------------------------------------------------*/

/* added(bruin, 2003.01.19): build a pid list from the ts data to group packets
     of the same pid; the result pid list is sorted by pid in increasing order 
 */
PID_LIST* build_pid_list(u8* ts, u32 packet_nr, u8 packet_size){
    u32       i;
    u16       pid;
    u8*       p;
    PID_LIST* list;
    
    if(!ts || !packet_nr)
        return 0;
    

    list = s_create_pid_list();
    
    for(i = 0; i < packet_nr; i ++){
        p = ts + i * packet_size;
        pid = ((PACKET_HEADER*)p)->pid_hi * 256 + ((PACKET_HEADER*)p)->pid_lo;
        s_add_packet_to_pid_list(list, pid, i);
    }

    return list;
}

    
int delete_pid_list(PID_LIST* pid_list){
    PID_NODE* pid_node;

    if(!pid_list)
        return 0;

    while(pid_list->head){
        pid_node = pid_list->head;
        pid_list->head = pid_list->head->next;
        s_delete_pid_node(pid_node);
    }
    free(pid_list);
    pid_list = 0;
    return 1;
}


/*
 * create a table for pid/id, by collecting all sections for that table.
 */
TABLE* build_table_with_sections(u16 pid, u8 tid, PID_LIST* pid_list, u8* p_ts, u8 packet_size){
    
    TABLE* tbl;
    u8     *p_sect = 0; // don't need to free this. it's either from a static variable, or from the ts mmap area.
    u16    section_size; 
    int    i;

    /* sanity checks */
    if(pid > PID_NUL)
        return 0;
    if(tid != TID_PMT && tid != TID_AIT){
        if(pid != get_pid_of_tid(tid))
            return 0;
    }

	if(s_is_verbose){
		fprintf(stdout, "\t%s (pid 0x%04x)...", get_tid_name_by_id(tid), pid);
		fflush(stdout);
	}
    
    /* allocate table and init it */
    if (!(tbl = (TABLE*)malloc(sizeof(TABLE)))) {
        return 0;
    } else {

        tbl->tid = tid;
        tbl->section_nr = 0;
		tbl->array_size = SECTION_ALLOC_INCREMENTAL_STEP;
		tbl->sections = (SECTION*)malloc(sizeof(SECTION) * SECTION_ALLOC_INCREMENTAL_STEP);
    }

    /* adding unique sections for the table */
    i = 0; // packet index to start with
    for (;;) {
        p_sect = 0;
        section_size = s_get_any_section_data(pid, tbl->tid, pid_list, &i, packet_size, p_ts, &p_sect);
        if (section_size == 0)
            break;
        s_add_section_to_table(tbl, section_size, p_sect, 1); // fixme: check return value
    }

    
	if(s_is_verbose){
		fprintf(stdout, "build_table_with_sections(tid=%d): done\n", tbl->tid);
		fflush(stdout);
	}

    return tbl;
}


int delete_table(TABLE* tbl){
    
    int i;

    if(!tbl)
        return 1;

    for(i = 0; i < tbl->section_nr; i ++){
        if(tbl->sections[i].data)
            free(tbl->sections[i].data);
    }

	free(tbl->sections);

    free(tbl);
    tbl = 0;

    return 1;
}


int set_pmt_list_by_pat_sect(SECTION* pat_sect, PMT_LIST* pmt_list){


    u8            *p;
    PAT_SECT_HEADER *p_pat_sect;
    int             section_length;
    int             i, j;

    pmt_list->pmt_nr = 0;

    p_pat_sect = (PAT_SECT_HEADER*)pat_sect->data;

    if(p_pat_sect->table_id != TID_PAT)
        return 0;

    section_length = p_pat_sect->section_length_hi * 256 + p_pat_sect->section_length_lo;
    j = (section_length - 5 - CRC_32_SIZE) / 4;

    p = (u8*)p_pat_sect + PAT_SECT_HEADER_LEN;
    for(i = 0; i < j; i ++, p += 4){
        if(p[0] != 0 || p[1] != 0){   /* not for NIT */
            pmt_list->prog_nr[pmt_list->pmt_nr] = p[0] * 256 + p[1];
            pmt_list->pmt_pid[pmt_list->pmt_nr] = (p[2] & 0x1f) * 256 + p[3];
            pmt_list->pmt_nr ++;
        }
    }
    

    return 1;
}

/* added(bruin, 2003.01.13) */
int set_ait_list_by_pmts(TABLE** tbl_pmts, int pmt_nr, AIT_LIST* ait_list){
    u8* p;
    int i, j, k, g, section_length, program_info_length, es_loop_length;
    u16 prog_nr;

    ait_list->ait_nr = 0;
    
    for(i = 0; i < pmt_nr; i ++){ /* for each PMT table */
        for(j = 0; j < tbl_pmts[i]->section_nr; j ++){ /* for each section */
            
            p = (u8*)(tbl_pmts[i]->sections[j].data);

            section_length = ((PMT_SECT_HEADER*)p)->section_length_hi * 256 + ((PMT_SECT_HEADER*)p)->section_length_lo;
            prog_nr = ((PMT_SECT_HEADER*)p)->program_number_hi * 256 + ((PMT_SECT_HEADER*)p)->program_number_lo;
            program_info_length = ((PMT_SECT_HEADER*)p)->program_info_length_hi * 256 + ((PMT_SECT_HEADER*)p)->program_info_length_lo;
            es_loop_length = section_length - 9 - program_info_length - 4;
            p +=  (PMT_SECT_HEADER_LEN + program_info_length);
            
            g = 0; /* data range guard */
            
            /*
             * ETSI TS 102 809 V1.1.1 (2010-01):
             * 5.3.5.1 Application signalling descriptor
             *  The application_signalling_descriptor is defined for use in the elementary stream loop of the PMT where the
             *  stream_type of the elementary stream is 0x05. It identifies that the elementary stream carries an Application
             *  Information Table.
             */
            for(k = 0; g < es_loop_length; k ++){ /* k: es index, g: data range guard */

                int g2;
                u8  stream_type = p[0];
                u16 es_pid = (p[1] & 0x1f) * 256 + p[2];
                int es_info_length = (p[3] & 0x0f) * 256 + p[4];
                
                p += 5;
                g += 5;
                
                if(stream_type != 0x05){
                    p +=  es_info_length;
                    g +=  es_info_length;
                    continue;
                }

                /* g2: es_info_length guard */
                g2 = 0; 
                for(; g2 < es_info_length;){
                    if(p[0] == DESC_APPLICATION_SIGNALLING){
                        ait_list->ait_pid[ait_list->ait_nr] = es_pid;
                        ait_list->prog_nr[ait_list->ait_nr] = prog_nr;
                        ait_list->ait_nr ++;
                    }

                    g2 += p[1] + 2;
                    p += p[1] + 2;
                }
            }

        }
    }

    return 1;
}

/* added(bruin, 2003.02.17) */
int set_rcs_tables_by_pmts(TABLE** tbl_pmts, int pmt_nr, RCS_TABLES* rcs_tbls){
    u8* p;
    int i, j, k, l, g, section_length, program_info_length, es_loop_length;
    
    for(i = 0; i < pmt_nr; i ++){ /* for each PMT table */
        for(j = 0; j < tbl_pmts[i]->section_nr; j ++){ /* for each section */
            
            p = (u8*)(tbl_pmts[i]->sections[j].data);

            section_length = ((PMT_SECT_HEADER*)p)->section_length_hi * 256 + ((PMT_SECT_HEADER*)p)->section_length_lo;
            program_info_length = ((PMT_SECT_HEADER*)p)->program_info_length_hi * 256 + ((PMT_SECT_HEADER*)p)->program_info_length_lo;
            es_loop_length = section_length - 9 - program_info_length - 4;
            p +=  (PMT_SECT_HEADER_LEN + program_info_length);
            
            g = 0; /* data range guard */
            for(k = 0; g < es_loop_length; k ++){ /* k: es index, g: data range guard */

                int g2;
                u8  stream_type = p[0];
                u16 es_pid = (p[1] & 0x1f) * 256 + p[2];
                int es_info_length = (p[3] & 0x0f) * 256 + p[4];
                
                p += 5;
                g += 5;
                
                if(stream_type != 0x05){
                    p +=  es_info_length;
                    g +=  es_info_length;
                    continue;
                }

                /* g2: es_info_length guard */
                g2 = 0; 
                for(; g2 < es_info_length;){
                    if(p[0] == DESC_RCS_CONTENT){
                        for(l = 0; l < p[1]; l ++){
                            switch(p[ 2 + l]){ /* table_id */
                                case 0x41: rcs_tbls->rmt_pid = es_pid;
                                case 0xa0: rcs_tbls->sct_pid = es_pid;
                                case 0xa1: rcs_tbls->fct_pid = es_pid;
                                case 0xa2: rcs_tbls->tct_pid = es_pid;
                                case 0xa3: rcs_tbls->spt_pid = es_pid;
                                case 0xa4: rcs_tbls->cmt_pid = es_pid;
                                case 0xa5: rcs_tbls->tbtp_pid = es_pid;
                                case 0xa6: rcs_tbls->pcr_pid = es_pid;
                                case 0xb0: rcs_tbls->tim_pid = es_pid;
                            }
                        }
                    }

                    g2 += p[1] + 2;
                    p += p[1] + 2;
                }
            }

        }
    }

    return 1;
}

TSR_RESULT* build_tsr_result(const char* file_path, u8* file_data, u32 file_size, int is_verbose){


    TSR_RESULT* result;
    u16         offset_and_size;
    u32         i;

    TNODE       *si_root;
    char        txt[TXT_BUF_SIZE + 1];

	s_is_verbose = is_verbose;

    if(!file_data || !file_size)
        return 0;

    /*** 0. allocate and init the result */
    result = (TSR_RESULT*)calloc(sizeof(TSR_RESULT), 1);
    if(!result)
        return 0;

	result->file_path = strdup(file_path);
    result->file_data = file_data;
    result->file_size = file_size;

    /*************************************
     * 1. get all section data 
     */
    
    /* 1.1. check otv header */
    i = check_otv_header(result->file_data, &(result->otv_header));
    result->is_otv_header= i? 1: 0;
	
	if(s_is_verbose){
		fprintf(stdout, "checking opentv header...\n\t%s otv header\n", i? "has" : "no");
		fflush(stdout);
	}
    
    result->ts_data = result->file_data + i;
    result->ts_size = result->file_size - i;

    /* 1.2. check packet size */
    offset_and_size = get_packet_offset_and_size(result->ts_data, result->ts_size);
    if(offset_and_size == 0){
        /* not recognized file data */
		if(s_is_verbose){
			fprintf(stdout, "unrecognized file format, giving up...\n");
			fflush(stdout);
		}
        free(result);
        return 0;
    }

    result->packet_size = offset_and_size % 256;
    result->ts_data += offset_and_size / 256;
    result->packet_nr = (result->ts_size - offset_and_size / 256) / result->packet_size;

	if(s_is_verbose){
		fprintf(stdout, "checking packet size...\n\tpacket size is %d\n\ttotally %d packets%s\n", result->packet_size, result->packet_nr, (offset_and_size / 256)? "\n\tone broken packet at head discarded" : "");
		fflush(stdout);
	}

    /* 1.3. pid list */
	if(s_is_verbose){
		fprintf(stdout, "building pid list...\n");
		fflush(stdout);
	}
    result->pid_list = build_pid_list(result->ts_data, result->packet_nr, result->packet_size);

    /* 1.4. tables, except pmts/aits */

	if(s_is_verbose){
		fprintf(stdout, "building tables...\n");
		fflush(stdout);
	}
    result->tbl_pat         = build_table_with_sections(get_pid_of_tid(TID_PAT), TID_PAT, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_cat         = build_table_with_sections(get_pid_of_tid(TID_CAT), TID_CAT, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_nit_act     = build_table_with_sections(get_pid_of_tid(TID_NIT_ACT), TID_NIT_ACT, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_nit_oth     = build_table_with_sections(get_pid_of_tid(TID_NIT_OTH), TID_NIT_OTH, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_bat         = build_table_with_sections(get_pid_of_tid(TID_BAT), TID_BAT, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_sdt_act     = build_table_with_sections(get_pid_of_tid(TID_SDT_ACT), TID_SDT_ACT, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_sdt_oth     = build_table_with_sections(get_pid_of_tid(TID_SDT_OTH), TID_SDT_OTH, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_eit_act     = build_table_with_sections(get_pid_of_tid(TID_EIT_ACT), TID_EIT_ACT, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_eit_oth     = build_table_with_sections(get_pid_of_tid(TID_EIT_OTH), TID_EIT_OTH, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_eit_act_sch = build_table_with_sections(get_pid_of_tid(TID_EIT_ACT_SCH), TID_EIT_ACT_SCH, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_eit_oth_sch = build_table_with_sections(get_pid_of_tid(TID_EIT_OTH_SCH), TID_EIT_OTH_SCH, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_tdt         = build_table_with_sections(get_pid_of_tid(TID_TDT), TID_TDT, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_tot         = build_table_with_sections(get_pid_of_tid(TID_TOT), TID_TOT, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_rst         = build_table_with_sections(get_pid_of_tid(TID_RST), TID_RST, result->pid_list, result->ts_data, result->packet_size);
    result->tbl_st          = build_table_with_sections(get_pid_of_tid(TID_ST), TID_ST, result->pid_list, result->ts_data, result->packet_size);
    
    /* 1.5. set pmt_list and tables */
    if(result->tbl_pat->section_nr)
        set_pmt_list_by_pat_sect(result->tbl_pat->sections, &(result->pmt_list));
    if(result->pmt_list.pmt_nr){
        result->tbl_pmts = (TABLE**)malloc(sizeof(TABLE*) * result->pmt_list.pmt_nr);
        for(i = 0; i < result->pmt_list.pmt_nr; i ++){
            result->tbl_pmts[i] = build_table_with_sections(result->pmt_list.pmt_pid[i], TID_PMT, result->pid_list, result->ts_data, result->packet_size);
        }
    }
    else{
        result->tbl_pmts = 0;
    }

    /* 1.6. set ait_list and tables */
    if(result->pmt_list.pmt_nr)
        set_ait_list_by_pmts(result->tbl_pmts, result->pmt_list.pmt_nr, &(result->ait_list));

    if(result->ait_list.ait_nr){
        result->tbl_aits = (TABLE**)malloc(sizeof(TABLE*) * result->ait_list.ait_nr);
        for(i = 0; i < result->ait_list.ait_nr; i ++){
            result->tbl_aits[i] = build_table_with_sections(result->ait_list.ait_pid[i], TID_AIT, result->pid_list, result->ts_data, result->packet_size);
        }
    }
    else{
        result->tbl_aits = 0;
    }

    /* 1.7. added(bruin, 2003.02.17) */
    if(result->pmt_list.pmt_nr){
        set_rcs_tables_by_pmts(result->tbl_pmts, result->pmt_list.pmt_nr, &(result->rcs));
        /* todo: build tables */

    }

    
    /*************************************
     * 2. build tree
     */
     
	if(s_is_verbose){
		fprintf(stdout, "building result tree by parsing tables/sections...\n");
		fflush(stdout);
	}

    /* 2.0. root */
    result->root = tnode_new(NODE_TYPE_TS_FILE);
    snprintf(txt, TXT_BUF_SIZE, "%s [size: %d; packet_size: %d%s", file_path, result->file_size, result->packet_size, result->is_otv_header? "; OTV header]":"]");
    result->root->txt = strdup(txt);

    /* 2.1. otv hinfo */
    if(result->is_otv_header){
        s_add_otv_header(&(result->otv_header), result->root);
		if(s_is_verbose){
			fprintf(stdout, "\tattaching opentv header info...done\n");
			fflush(stdout);
		}
	}
    
    /* 2.2. psi/si root */
    si_root = tnode_new(NODE_TYPE_PSI_SI);
    si_root->txt = strdup("PSI/SI");
    tnode_attach(result->root, si_root);

    s_add_table(result->tbl_pat, si_root);
    s_add_table(result->tbl_cat, si_root);
    s_add_tables(result->tbl_pmts, si_root, result->pid_list, &(result->pmt_list));
    s_add_tables(result->tbl_aits, si_root, result->pid_list, &(result->ait_list));
    s_add_table(result->tbl_nit_act, si_root);
    s_add_table(result->tbl_nit_oth, si_root);
    s_add_table(result->tbl_bat, si_root);
    s_add_table(result->tbl_sdt_act, si_root);
    s_add_table(result->tbl_sdt_oth, si_root);
    s_add_table(result->tbl_eit_act, si_root);
    s_add_table(result->tbl_eit_act_sch, si_root);
    s_add_table(result->tbl_eit_oth, si_root);
    s_add_table(result->tbl_eit_oth_sch, si_root);
    s_add_table(result->tbl_tdt, si_root);
    s_add_table(result->tbl_tot, si_root);
    s_add_table(result->tbl_rst, si_root);

    /* 2.3. pids root */
    s_add_pids(result, result->root, 16);
    
    /* 2.4. packets root */
    s_add_packets(result, result->root, 64);

	if(s_is_verbose){
		fprintf(stdout, "\n\n");
		fflush(stdout);
	}
    
    return result;    
}

int delete_tsr_result(TSR_RESULT* result){
    int i;

    if(!result)
        return 0;

	if(result->file_path)
		free(result->file_path);
    
    delete_pid_list(result->pid_list);

    delete_table(result->tbl_pat);
    delete_table(result->tbl_cat);
    delete_table(result->tbl_nit_act);
    delete_table(result->tbl_nit_oth);
    delete_table(result->tbl_sdt_act);
    delete_table(result->tbl_sdt_oth);
    delete_table(result->tbl_bat);
    delete_table(result->tbl_eit_act);
    delete_table(result->tbl_eit_oth);
    delete_table(result->tbl_eit_act_sch);
    delete_table(result->tbl_eit_oth_sch);
    delete_table(result->tbl_tdt);
    delete_table(result->tbl_tot);
    delete_table(result->tbl_rst);
    delete_table(result->tbl_st);

    if(result->tbl_pmts){
        for(i = 0; i < result->pmt_list.pmt_nr; i ++)
            delete_table(result->tbl_pmts[i]);
        free(result->tbl_pmts);
    }

    if(result->tbl_aits){
        for(i = 0; i < result->ait_list.ait_nr; i ++)
            delete_table(result->tbl_aits[i]);
        free(result->tbl_aits);
    }

    tnode_delete(result->root);

    free(result);

    return 1;
}


/* return / 256 : offset of the first packet from beginning of data chunk,
   return % 256 : packet size, either 188 or 204, if 0, error. */
u16 get_packet_offset_and_size(u8 *data, int data_size){

    u8  sync_byte = 0x47;
    u8  offset, packet_size = 0;
    int i, min_packets = 10;  /* minimum packets to check */

    /* check for minimum data size */
    if(data_size < 204 * (min_packets + 2))
        return 0;

    for(offset = 0; offset < 204; offset ++){
        if(data[offset] != sync_byte)
            continue;

        /* try 188 */
        for(i = 0; i < min_packets; i ++)
            if(data[offset + 188 * i] != sync_byte)
                break;
        if(i == min_packets){
            packet_size = 188;
            break;
        }

        /* try 204 */
        for(i = 0; i < min_packets; i ++)
            if(data[offset + 204 * i] != sync_byte)
                break;
        if(i == min_packets){
            packet_size = 204;
            break;
        }
    }

    if(offset == 204)
        return 0;

    return offset * 256 + packet_size;
}

PACKET_HEADER* get_packet_by_index(u8* p_ts, int index, int packet_size){
    return (PACKET_HEADER*)(p_ts + index * packet_size);
}

/*
 * -------------------------------------------------------------------
 * return:
 *   0: no otv header
 *   other: size of the otv header
 * -------------------------------------------------------------------
 */
u32 check_otv_header(u8 *p_file_data, OTV_HEADER* p_otv_header){

    if(strncmp(s_otv_magic, (const char*)p_file_data, strlen(s_otv_magic)) == 0){
        int head_size;
        p_otv_header->data_size[0] = p_file_data[8];
        p_otv_header->data_size[1] = p_file_data[9];
        p_otv_header->data_size[2] = p_file_data[10];
        p_otv_header->data_size[3] = p_file_data[11];
        head_size = (p_otv_header->data_size[0] * 256 + p_otv_header->data_size[1]) * 65536 + 
                     p_otv_header->data_size[2] * 256 + p_otv_header->data_size[3];
        p_otv_header->data = p_file_data + 12;
        return head_size + 12;
    }
    else{
        return 0;
    }
}


/* added(bruin, 2004-06-22) */
void summarize_result(FILE* fp, TSR_RESULT* result){

	PID_NODE*   pid_node;
	const char* pidname;
	int         i;

	if(fp == NULL || result == NULL)
		return;
	
	fprintf(fp, "brief report of the anaysis result\n");
	fprintf(fp, "================================================\n");

	/* basic information */

	fprintf(fp, "\nfile basic info\n");
	fprintf(fp, "------------------\n");
	fprintf(fp, "  file path: %s\n", result->file_path);
	fprintf(fp, "  file size: %d\n", result->file_size);
	if(result->is_otv_header){
		fprintf(fp, "  opentv header exists, size: %d\n", 
				(int)(result->ts_data - result->file_data));
		fprintf(fp, "  ts data size: %d\n", result->ts_size);
	}
	else{
		if(result->ts_data != result->file_data){
			fprintf(fp, "  broken packet found at head, size: %d\n", 
					(int)(result->ts_data - result->file_data));
		}
	}
	fprintf(fp, "  packet size: %d\n", result->packet_size);
	fprintf(fp, "  packet number: %d\n", result->packet_nr);

	/* pid info */

	fprintf(fp, "\npid info\n");
	fprintf(fp, "--------\n");
	for(pid_node = result->pid_list->head; 
		pid_node != 0; 
		pid_node = pid_node->next){

        pidname = get_pid_name_by_id(pid_node->pid);
        
		if(!pidname){ /* pmt or ait? */

        	/* check if it's pmt pid */
        	for(i = 0; i < result->pmt_list.pmt_nr; i ++)
        		if(result->pmt_list.pmt_pid[i] == pid_node->pid)
        			pidname = "PMT";
                
            /* check if it's ait pid */
            for(i = 0; i < result->ait_list.ait_nr; i ++)
                if(result->ait_list.ait_pid[i] == pid_node->pid)
                    pidname = "AIT";
		}
        
		if(!pidname){ /* es? */
			pidname = get_stream_type_name_by_id(pid_node->stream_type);
		}

		fprintf(fp, "  pid 0x%04x (%4d), %6d packets, %5.2f%% => %s\n", 
				pid_node->pid, 
				pid_node->pid, 
				pid_node->packet_nr, 
				pid_node->packet_nr * 100.0 / result->packet_nr,
				pidname?pidname:"");
	}

	/* psi/si info */
	fprintf(fp, "\npsi/si info\n");
	fprintf(fp, "-----------\n");
	if(result->tbl_pat && result->tbl_pat->section_nr)
		fprintf(fp, "  PAT exists\n");
	if(result->pmt_list.pmt_nr)
		fprintf(fp, "  %d PMT exist\n", result->pmt_list.pmt_nr);
	if(result->ait_list.ait_nr)
		fprintf(fp, "  %d AIT exist\n", result->ait_list.ait_nr);
	if(result->tbl_bat && result->tbl_bat->section_nr)
		fprintf(fp, "  BAT exists\n");
	if(result->tbl_cat && result->tbl_cat->section_nr)
		fprintf(fp, "  CAT exists\n");
	if(result->tbl_nit_act && result->tbl_nit_act->section_nr)
		fprintf(fp, "  NIT ACTUAL exists\n");
	if(result->tbl_nit_oth && result->tbl_nit_oth->section_nr)
		fprintf(fp, "  NIT OTHER exists\n");
	if(result->tbl_sdt_act && result->tbl_sdt_act->section_nr)
		fprintf(fp, "  SDT ACTUAL exists\n");
	if(result->tbl_sdt_oth && result->tbl_sdt_oth->section_nr)
		fprintf(fp, "  SDT OTHER exists\n");
	if(result->tbl_eit_act && result->tbl_eit_act->section_nr)
		fprintf(fp, "  EIT ACTUAL exists\n");
	if(result->tbl_eit_oth && result->tbl_eit_oth->section_nr)
		fprintf(fp, "  EIT OTHER exists\n");
	if(result->tbl_eit_act_sch && result->tbl_eit_act_sch->section_nr)
		fprintf(fp, "  EIT ACTUAL SCHEDULE exists\n");
	if(result->tbl_eit_oth_sch && result->tbl_eit_oth_sch->section_nr)
		fprintf(fp, "  EIT OTHER SCHEDULE exists\n");
	if(result->tbl_tdt && result->tbl_tdt->section_nr)
		fprintf(fp, "  TDT exists\n");
	if(result->tbl_tot && result->tbl_tot->section_nr)
		fprintf(fp, "  TOT exists\n");
	if(result->tbl_rst && result->tbl_rst->section_nr)
		fprintf(fp, "  RST exists\n");
	if(result->tbl_st && result->tbl_st->section_nr)
		fprintf(fp, "  ST exists\n");

	fprintf(fp, "================================================\n");

	fflush(fp);
}







/*--------------------------------------------------------------------+
 |                                                                    |
 | private routines definition                                        |
 |                                                                    |
 +--------------------------------------------------------------------*/


static PID_NODE* s_create_pid_node(u16 pid){

    PID_NODE* pid_node;
    
    if(!(pid_node = (PID_NODE*)malloc(sizeof(PID_NODE))))
        return 0;

    /* init the node struct */

    pid_node->pid = pid;
    pid_node->packet_nr = 0;
    pid_node->stream_type = 0;
    pid_node->size = PID_NODE_ALLOC_INCREMENTAL_STEP; 
    pid_node->index = (u32*)malloc(sizeof(u32) * pid_node->size);
    if(!pid_node->index){
        free(pid_node);
        return 0;
    }
    pid_node->pre = 0;
    pid_node->next = 0;
    
    return pid_node;
}


static int s_delete_pid_node(PID_NODE* pid_node){

    if(pid_node->index)
        free(pid_node->index);
    free(pid_node);

    return 1;
}


static int s_add_packet_to_pid_node(PID_NODE* pid_node, int packet_index){

    pid_node->index[pid_node->packet_nr] = packet_index;
    pid_node->packet_nr ++;

    if(pid_node->packet_nr == pid_node->size){
        pid_node->size += PID_NODE_ALLOC_INCREMENTAL_STEP;
        pid_node->index = (u32*)realloc(pid_node->index, sizeof(u32) * pid_node->size);
        if(!pid_node->index)
            return 0;
    }
    return 1;
}

static int s_add_pid_node_to_list(PID_LIST* pid_list, PID_NODE* pid_node){

    /* insert the node as sorted by pid */

    PID_NODE* node; /* insert after node */

    if(!pid_list->head){
        pid_list->head = pid_node;
        pid_list->pid_nr = 1;
        return 1;
    }
    else{
        if(pid_list->head->pid > pid_node->pid){
            pid_list->head->pre = pid_node;
            pid_node->next = pid_list->head;
            pid_list->head = pid_node;
            pid_list->pid_nr ++;
        }
        else{
            for(node = pid_list->head; node != 0; node = node->next){
                if((node->pid < pid_node->pid) && (node->next == 0 || node->next->pid > pid_node->pid)){
                    pid_node->pre = node;
                    pid_node->next = node->next;
                    node->next = pid_node;
                    pid_list->pid_nr ++;
                    break;
                }
            }
        }
    }

    return 1;
}


static PID_LIST* s_create_pid_list(void){

    PID_LIST* pid_list;

    if(!(pid_list = (PID_LIST*)malloc(sizeof(PID_LIST))))
        return 0;
        
    pid_list->pid_nr = 0;
    pid_list->head = 0;

    return pid_list;
}



static int s_add_packet_to_pid_list(PID_LIST* pid_list, u16 pid, int packet_index){

    PID_NODE* pid_node;
    int pid_exist = 0;

    for(pid_node = pid_list->head; pid_node != 0; pid_node = pid_node->next){
        if(pid_node->pid == pid){
            pid_exist = 1;
            break;
        }
    }
    
    if(pid_exist){
        if(!s_add_packet_to_pid_node(pid_node, packet_index))
            return 0;
    }
    else{
        if(!(pid_node = s_create_pid_node(pid)))
            return 0;
        if(!s_add_packet_to_pid_node(pid_node, packet_index))
            return 0;
        if(!s_add_pid_node_to_list(pid_list, pid_node))
            return 0;

		if(s_is_verbose){
			fprintf(stdout, "\tpid 0x%04x (%4d)...done\n", pid, pid);
			fflush(stdout);
		}
    }

    return 1;
}



/*  arguments:
        pid(==>):            the pid of the section
        table_id(==>):       the table_id of the section
        section_number(==>): section_number of the section
        pid_list(==>):       pid_list

        last_section_number(<==): last section nr of the table 
        pp(<==): pointer to the pointer of the section data, (*pp) should be NULL. 

    return: 
        0: error or not found
        others: size of the total section
*/
#if (0)
static u16 s_get_section_data(u16           pid,                   /* --> */
                     u8            table_id,              /* --> */
                     u8            section_number,        /* --> */
                     PID_LIST*     pid_list,              /* --> */
                     u8*           p_ts,                  /* --> */
                     u8            packet_size,           /* --> */
                     u8*           last_section_number,   /* <-- */
                     u8**          pp){                   /* <-- */

#define MAX_SECT_BUF           4096
    static u8 s_section_buf[MAX_SECT_BUF];

    PID_NODE*        pid_node = 0;
    int              i, j;
    u16              section_size = 0;    /* total size */
    u16              section_length = 0;  /* value in the section header */
    int              first_packet_found = 0;
    int              continuity_counter = 0;
    PACKET_HEADER*   packet = 0;
    PAT_SECT_HEADER* sect_head = 0;
    int              sect_offset = 0;
    u8*              p = 0;
    
    /* sanity checks */
    if(*pp || pid > PID_NUL)
        goto END;

    if(table_id != TID_PMT && table_id != TID_AIT){
        if(pid != get_pid_of_tid(table_id))
            goto END;
    }


    /* locate the pid_node */

    for(pid_node = pid_list->head; pid_node != 0; pid_node = pid_node->next)
        if(pid_node->pid == pid)
            break;

    if(!pid_node)  /* pid not found */
        goto END;

    /* search the section in pid_node */
    for(i = 0; i < (int)(pid_node->packet_nr); i ++){

        packet = get_packet_by_index(p_ts, pid_node->index[i], packet_size);
        p = (u8*)packet;

        /* for simplicity, we do not handle adaptation field at this moment */
        if(!packet_payload_unit_start_indicator(p) || packet_adaptation_field_control(p) != 0x01)
            continue;

        /* use PAT_SECT_HEADER as generic section header at this point, except for TDT/TOT/RST */
        sect_offset = TS_HEADER_LEN + 1 + p[4];  /* 1: pointer_field size; p[4]: pointer_field value */
        for(; sect_offset < 188 - TS_HEADER_LEN - PAT_SECT_HEADER_LEN ;){
            sect_head = (PAT_SECT_HEADER*)(p + sect_offset);
            if((sect_head->table_id == table_id) && ((table_id == TID_TDT || table_id == TID_TOT || table_id == TID_RST)? 1 : sect_head->section_number == section_number)){
                first_packet_found = 1;
                continuity_counter = packet_continuity_counter(p);
                break;
            }
            sect_offset += 3 + sect_head->section_length_hi * 256 + sect_head->section_length_lo;
        }

        if(first_packet_found)
            break;
    }

    if(!first_packet_found)
        goto END;

    /* "i" is the fisrt packet index */
    if(table_id == TID_TDT || table_id == TID_TOT || table_id == TID_RST)
        *last_section_number = 0;
    else
        *last_section_number = sect_head->last_section_number;
    section_length = sect_head->section_length_hi * 256 + sect_head->section_length_lo;
    section_size = section_length + 3;
    if(sect_offset + section_size <= 188){
        *pp = (u8*)sect_head;
        goto END;
    }
    else{
        int sect_size_in_current_packet = 188 - sect_offset;
        int remain_sect_size = section_size - sect_size_in_current_packet;
        int remain_packet_nr = (remain_sect_size - 1) / (188 - TS_HEADER_LEN) + 1;

        if((i + 1 + remain_packet_nr) > (int)(pid_node->packet_nr)){
            section_size = 0;
            goto END;
        }
        else{
            int copied_size;
            /* copy the first packet data into buf */
            memcpy(s_section_buf, sect_head, sect_size_in_current_packet);
            copied_size = sect_size_in_current_packet;
            for(j = 0; j < remain_packet_nr - 1; j ++){
                p = (u8*)get_packet_by_index(p_ts, pid_node->index[i + 1 + j], packet_size);
                memcpy(s_section_buf + copied_size, p + TS_HEADER_LEN, 188 - TS_HEADER_LEN);
                copied_size += 188 - TS_HEADER_LEN;
            }
            p = (u8*)get_packet_by_index(p_ts, pid_node->index[i + 1 + j], packet_size);
            memcpy(s_section_buf + copied_size, p + TS_HEADER_LEN, section_size - copied_size);
            *pp = s_section_buf;
        }
    }

END:
    return section_size;
}
#endif

/*
 * added(bruin, 2015-04-21): a copy of s_get_section_data(): 
 *
 *
 * arguments:
        pid(==>):            the pid of the section
        table_id(==>):       the table_id of the section. For EIT-S, pass in the first TID meaning the full TID range.
        pid_list(==>):       pid_list
        packet_idx(<==>):     search from which packet, and return where we are now.
        pp(<==): pointer to the pointer of the section data, (*pp) should be NULL. 

    return: 
        0: error or not found
        others: size of the total section
*/
static u16 s_get_any_section_data(u16           pid,      /* --> */
                     u8            table_id,              /* --> */
                     PID_LIST*     pid_list,              /* --> */
                     int*          packet_idx,            /* <--> */
                     u8            packet_size,           /* --> */
                     u8*           p_ts,                  /* --> */
                     u8**          pp){                   /* <-- */

#define MAX_SECT_BUF           4096
    static u8 s_section_buf[MAX_SECT_BUF];

    PID_NODE*        pid_node = 0;
    int              i, j;
    u16              section_size = 0;    /* total size */
    u16              section_length = 0;  /* value in the section header */
    int              first_packet_found = 0;
    //int              continuity_counter = 0;
    PACKET_HEADER*   packet = 0;
    PAT_SECT_HEADER* sect_head = 0;
    int              sect_offset = 0;
    u8*              p = 0;
    u8               tid_start, tid_end; // for EIT-S, which has a range of tids.

    //fprintf(stdout, "s_get_any_section_data() enter: tid=%d, packet_idx=%d\n", table_id, *packet_idx);
    
    /* sanity checks */
    if(*pp || pid > PID_NUL) {
        goto END;
    }   
    
    if(table_id != TID_PMT && table_id != TID_AIT){
        if(pid != get_pid_of_tid(table_id)) {
            goto END;
        }
    }


    /* locate the pid_node */
    for(pid_node = pid_list->head; pid_node != 0; pid_node = pid_node->next) {
        if(pid_node->pid == pid) {
            break;
        }
    }

    if(!pid_node) {  /* pid not found */
        goto END;
    }

    // convert table_id into a range
    if (table_id == TID_EIT_ACT_SCH) {
        tid_start = TID_EIT_ACT_SCH;
        tid_end = TID_EIT_ACT_SCH_LAST;
    } else if (table_id == TID_EIT_OTH_SCH) {
        tid_start = TID_EIT_OTH_SCH;
        tid_end = TID_EIT_OTH_SCH_LAST;
    } else {
        tid_start = table_id;
        tid_end = table_id;
    }

    //fprintf(stdout, "  s_get_any_section_data(): packet_idx=%d, packet_nr=%d\n", *packet_idx, pid_node->packet_nr);
    
    /* 
     * search the section in pid_node, from the packet_idx indicated 
     */
    for(i = *packet_idx; i < (int)(pid_node->packet_nr); i ++){

        //fprintf(stdout, "  s_get_any_section_data(): i=%d\n", i);
        
        packet = get_packet_by_index(p_ts, pid_node->index[i], packet_size);
        p = (u8*)packet;

        /* for simplicity, we do not handle adaptation field at this moment */
        if(!packet_payload_unit_start_indicator(p) || packet_adaptation_field_control(p) != 0x01)
            continue;

        /* use PAT_SECT_HEADER as generic section header at this point, except for TDT/TOT/RST */
        sect_offset = TS_HEADER_LEN + 1 + p[4];  /* 1: pointer_field size; p[4]: pointer_field value */
        for(; sect_offset < 188 - TS_HEADER_LEN - PAT_SECT_HEADER_LEN ;){
            sect_head = (PAT_SECT_HEADER*)(p + sect_offset);
//            if(sect_head->table_id == table_id) {
            if(sect_head->table_id >= tid_start && sect_head->table_id <= tid_end) {
                first_packet_found = 1;
                //continuity_counter = packet_continuity_counter(p);
                break;
            }
            sect_offset += 3 + sect_head->section_length_hi * 256 + sect_head->section_length_lo;
        }

        if(first_packet_found){
            //fprintf(stdout, "  s_get_any_section_data(): first_packet_found\n");
            break;
        }
    }

    if(!first_packet_found) {
        //fprintf(stdout, "  s_get_any_section_data(): !!!first_packet_found, i=%d\n", i);
        goto END;
    }

    /* "i" is the fisrt packet index */
    *packet_idx = i + 1; // advance it at least for i + 1
    section_length = sect_head->section_length_hi * 256 + sect_head->section_length_lo;
    section_size = section_length + 3;
    if(sect_offset + section_size <= 188){
        *pp = (u8*)sect_head;
        goto END;
    }
    else{
        int sect_size_in_current_packet = 188 - sect_offset;
        int remain_sect_size = section_size - sect_size_in_current_packet;
        int remain_packet_nr = (remain_sect_size - 1) / (188 - TS_HEADER_LEN) + 1;

        if((i + 1 + remain_packet_nr) > (int)(pid_node->packet_nr)){
            section_size = 0;
            goto END;
        }
        else{
            int copied_size;
            /* copy the first packet data into buf */
            memcpy(s_section_buf, sect_head, sect_size_in_current_packet);
            copied_size = sect_size_in_current_packet;
            for(j = 0; j < remain_packet_nr - 1; j ++){
                p = (u8*)get_packet_by_index(p_ts, pid_node->index[i + 1 + j], packet_size);
                memcpy(s_section_buf + copied_size, p + TS_HEADER_LEN, 188 - TS_HEADER_LEN);
                copied_size += 188 - TS_HEADER_LEN;
            }
            p = (u8*)get_packet_by_index(p_ts, pid_node->index[i + 1 + j], packet_size);
            memcpy(s_section_buf + copied_size, p + TS_HEADER_LEN, section_size - copied_size);
            *pp = s_section_buf;
            *packet_idx += j; // advance it for extra packets
        }
    }

END:

    //fprintf(stdout, "s_get_any_section_data() leaving: section_size=%d\n", section_size);
    return section_size;
}


/* return 1 for error, 0 for ok (added) */
/* dedup: 1 for dedup, otherwise no dedup */
static int s_add_section_to_table(TABLE* tbl, int size, u8 *data, int dedup){
    int i;

    if (!data || size <= 0) {
        return 1;
    }
    
    /*
     * added(bruin, 2015-04-22):
     * dedup the section that if there is an identical section, don't add again
     */
    if (dedup == 1) {
        for (i = 0; i < tbl->section_nr; i ++) {
            if (memcmp(tbl->sections[i].data, data, size) == 0) {
				tbl->sections[i].repeat ++;
                return 1;
            }
        }
    }
    
    tbl->sections[tbl->section_nr].repeat = 1;
    tbl->sections[tbl->section_nr].size = size;
    if(!(tbl->sections[tbl->section_nr].data = (u8*)malloc(size)))
        return 1;
    memcpy(tbl->sections[tbl->section_nr].data, data, size);

    tbl->section_nr ++;
	// increment the array size if necessary
	if (tbl->section_nr == tbl->array_size) {
		tbl->array_size += SECTION_ALLOC_INCREMENTAL_STEP;
		tbl->sections = (SECTION*)realloc(tbl->sections, sizeof(SECTION) * tbl->array_size);
		if (!tbl->sections) {
			fprintf(stderr, "fatal: realloc() for sections failed. array_size=%d\n", tbl->array_size);
			return 1;
		}
	}
	
    return 0;
}


static void s_add_otv_header(OTV_HEADER* header, TNODE* root){
    char*  p;
    TNODE  *otv_root, *node;

    otv_root = tnode_new(NODE_TYPE_OTV_HINFO);
    otv_root->txt = strdup("OTV HINFO");
    tnode_attach(root, otv_root);

    p = (char*)(header->data);
    for(; *p != 0 ;){
        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup(p);
        tnode_attach(otv_root, node);
        p = strchr(p, 0);
        p ++;
    }
}

static long s_get_table_section_size_sum(TABLE* tbl) 
{
	int i;
	long sum = 0;
	for (i = 0; i < tbl->section_nr; i ++)
		sum += tbl->sections[i].size;

	return sum;
}
	

/* attach SI table (except pmt/ait) parsing result to "root" node */
static void s_add_table(TABLE* tbl, TNODE* root){
    int    i;
    TNODE  *tbl_root, *sect_root;
    char   txt[TXT_BUF_SIZE + 1];
	long   sum;

	NIT_SECT_HEADER* nit_sec_hdr;
	SDT_SECT_HEADER* sdt_sec_hdr;
    EIT_SECT_HEADER* eit_sec_hdr;

    if(!tbl || !root || tbl->tid == TID_PMT || tbl->tid == TID_AIT)
        return;

	sum = s_get_table_section_size_sum(tbl);
	
    tbl_root = tnode_new(NODE_TYPE_TABLE);
    switch(tbl->tid){
        case TID_PAT:
            tbl_root->txt = strdup("PAT"); break;
        case TID_CAT:
            tbl_root->txt = strdup("CAT"); break;
        case TID_NIT_ACT:
            tbl_root->txt = strdup("NIT ACTUAL"); break;
        case TID_NIT_OTH:
            tbl_root->txt = strdup("NIT OTHER"); break;
        case TID_SDT_ACT:
			snprintf(txt, TXT_BUF_SIZE, "SDT ACTUAL (%d sections, %ld bytes)", tbl->section_nr, sum);
            tbl_root->txt = strdup(txt); 
			break;
        case TID_SDT_OTH:
			snprintf(txt, TXT_BUF_SIZE, "SDT OTHER (%d sections, %ld bytes)", tbl->section_nr, sum);
            tbl_root->txt = strdup(txt); 
			break;
        case TID_BAT:
            tbl_root->txt = strdup("BAT"); break;
        case TID_EIT_ACT:
			snprintf(txt, TXT_BUF_SIZE, "EIT ACTUAL (%d sections, %ld bytes)", tbl->section_nr, sum);
            tbl_root->txt = strdup(txt); 
			break;
        case TID_EIT_OTH:
			snprintf(txt, TXT_BUF_SIZE, "EIT OTHER (%d sections, %ld bytes)", tbl->section_nr, sum);
            tbl_root->txt = strdup(txt); 
			break;
        case TID_EIT_ACT_SCH:
			snprintf(txt, TXT_BUF_SIZE, "EIT ACTUAL SCHEDULE (%d sections, %ld bytes)", tbl->section_nr, sum);
            tbl_root->txt = strdup(txt); 
			break;
        case TID_EIT_OTH_SCH:
			snprintf(txt, TXT_BUF_SIZE, "EIT OTHER SCHEDULE (%d sections, %ld bytes)", tbl->section_nr, sum);
            tbl_root->txt = strdup(txt); 
			break;
        case TID_TDT:
            tbl_root->txt = strdup("TDT"); break;
        case TID_TOT:
            tbl_root->txt = strdup("TOT"); break;
        case TID_RST:
            tbl_root->txt = strdup("RST"); break;
        case TID_ST:
            tbl_root->txt = strdup("ST"); break;
        default:
            tbl_root->txt = strdup("?unknown_table?"); break;
    }
    tnode_attach(root, tbl_root);

	if(s_is_verbose){
		fprintf(stdout, "\tparsing & attaching %s...", tbl_root->txt);
		fflush(stdout);
	}
    
    for(i = 0; i < tbl->section_nr; i ++){
        sect_root = tnode_new(NODE_TYPE_SECTION);
        snprintf(txt, TXT_BUF_SIZE, "SECTION(+%d): %d", tbl->sections[i].repeat, i);
        sect_root->txt = strdup(txt);
        sect_root->tag = (long)(&(tbl->sections[i]));
        tnode_attach(tbl_root, sect_root);
        
        switch(tbl->tid){
            case TID_PAT:
                s_parse_sect_pat(sect_root, tbl, i); break;
            case TID_CAT:
                s_parse_sect_cat(sect_root, tbl, i); break;
            case TID_NIT_ACT:
            case TID_NIT_OTH:
                /* replace the description for the section root node */
                nit_sec_hdr = (NIT_SECT_HEADER*)(tbl->sections[i].data);
                snprintf(txt, TXT_BUF_SIZE, "SECTION(+%d): network-id=0x%04x, version=%2d, section-number=%d/%d", 
					tbl->sections[i].repeat,
                    nit_sec_hdr->network_id_hi * 256 + nit_sec_hdr->network_id_lo,
                    nit_sec_hdr->version_number,
                    nit_sec_hdr->section_number, 
                    nit_sec_hdr->last_section_number);
                free(sect_root->txt);
                sect_root->txt = strdup(txt);
                s_parse_sect_nit(sect_root, tbl, i); break;
            case TID_SDT_ACT:
            case TID_SDT_OTH:
                /* replace the description for the section root node */
                sdt_sec_hdr = (SDT_SECT_HEADER*)(tbl->sections[i].data);
                snprintf(txt, TXT_BUF_SIZE, "SECTION(+%d): onid.tsid=0x%04x.%04x, version=%2d, section-number=%d/%d", 
					tbl->sections[i].repeat,
                    sdt_sec_hdr->original_network_id_hi * 256 + sdt_sec_hdr->original_network_id_lo,
                    sdt_sec_hdr->transport_stream_id_hi * 256 + sdt_sec_hdr->transport_stream_id_lo,
                    sdt_sec_hdr->version_number,
                    sdt_sec_hdr->section_number, 
                    sdt_sec_hdr->last_section_number);
                free(sect_root->txt);
                sect_root->txt = strdup(txt);
                s_parse_sect_sdt(sect_root, tbl, i); break;
            case TID_BAT:
                s_parse_sect_bat(sect_root, tbl, i); break;
            case TID_EIT_ACT:
            case TID_EIT_OTH:
            case TID_EIT_ACT_SCH:
            case TID_EIT_OTH_SCH:
                /* replace the description for the section root node */
                eit_sec_hdr = (EIT_SECT_HEADER*)(tbl->sections[i].data);
                snprintf(txt, TXT_BUF_SIZE, "SECTION(+%d): tid=0x%02x, svc=(0x%04x.%04x.%04x), version=%2d, section-number=%d/%d/%d", 
					tbl->sections[i].repeat,
                    eit_sec_hdr->table_id,
                    eit_sec_hdr->original_network_id_hi * 256 + eit_sec_hdr->original_network_id_lo,
                    eit_sec_hdr->transport_stream_id_hi * 256 + eit_sec_hdr->transport_stream_id_lo,
                    eit_sec_hdr->service_id_hi * 256 + eit_sec_hdr->service_id_lo,
                    eit_sec_hdr->version_number,
                    eit_sec_hdr->section_number, 
                    eit_sec_hdr->segment_last_section_number, 
                    eit_sec_hdr->last_section_number);
                free(sect_root->txt);
                sect_root->txt = strdup(txt);
                s_parse_sect_eit(sect_root, tbl, i); break;
            case TID_TDT:
                s_parse_sect_tdt(sect_root, tbl, i); break;
            case TID_TOT:
                s_parse_sect_tot(sect_root, tbl, i); break;
            case TID_RST:
                s_parse_sect_rst(sect_root, tbl, i); break;
            case TID_ST:
            default:
                break;
        }
    }

	if(s_is_verbose){
		fprintf(stdout, "done\n");
		fflush(stdout);
	}
}

/* attach pmt/ait table array parsing result to "PSI/SI" node */
static void s_add_tables(TABLE** tbl, TNODE* root, PID_LIST* pid_list, void* tbl_list){
    int    i, j;
    TNODE  *tbls_root, *tbl_root, *sect_root;
    char   txt[TXT_BUF_SIZE + 1];

    if(!tbl || !root || (tbl[0]->tid != TID_PMT && tbl[0]->tid != TID_AIT))
        return;

    
    tbls_root = tnode_new(NODE_TYPE_TABLE);
    if(tbl[0]->tid == TID_PMT)
        tbls_root->txt = strdup("PMTs");
    else
        tbls_root->txt = strdup("AITs");
    tnode_attach(root, tbls_root);

    if(tbl[0]->tid == TID_PMT){
        
        PMT_LIST* pmt_list = (PMT_LIST*)tbl_list;
        
        for(i = 0; i < pmt_list->pmt_nr; i ++){

            tbl_root = tnode_new(NODE_TYPE_PROGRAM);
            snprintf(txt, TXT_BUF_SIZE, "program 0x%04x (%d) => pmt pid: 0x%03x (%d)", pmt_list->prog_nr[i], pmt_list->prog_nr[i], pmt_list->pmt_pid[i], pmt_list->pmt_pid[i]);
            tbl_root->txt = strdup(txt);
            tnode_attach(tbls_root, tbl_root);

			if(s_is_verbose){
				fprintf(stdout, "\tparsing & attaching PMT for %s...", tbl_root->txt);
				fflush(stdout);
			}

            for(j = 0; j < tbl[i]->section_nr; j ++){
                sect_root = tnode_new(NODE_TYPE_SECTION);
                snprintf(txt, TXT_BUF_SIZE, "SECTION(+%d): %d", tbl[i]->sections[j].repeat, j);
                sect_root->txt = strdup(txt);
                sect_root->tag = (long)(&(tbl[i]->sections[j]));
                tnode_attach(tbl_root, sect_root);

                s_parse_sect_pmt(sect_root, tbl[i], j, pid_list);
            }

			if(s_is_verbose){
				fprintf(stdout, "done\n");
				fflush(stdout);
			}

        }
    }
    else{ /* TID_AIT */
        
        AIT_LIST* ait_list = (AIT_LIST*)tbl_list;
        
        for(i = 0; i < ait_list->ait_nr; i ++){

            tbl_root = tnode_new(NODE_TYPE_PROGRAM);
            snprintf(txt, TXT_BUF_SIZE, "program 0x%04x (%d) => ait pid: 0x%03x (%d)", ait_list->prog_nr[i], ait_list->prog_nr[i], ait_list->ait_pid[i], ait_list->ait_pid[i]);
            tbl_root->txt = strdup(txt);
            tnode_attach(tbls_root, tbl_root);

			if(s_is_verbose){
				fprintf(stdout, "\tparsing & attaching AIT for %s...", tbl_root->txt);
				fflush(stdout);
			}

            for(j = 0; j < tbl[i]->section_nr; j ++){
                sect_root = tnode_new(NODE_TYPE_SECTION);
                snprintf(txt, TXT_BUF_SIZE, "SECTION(+%d): %d", tbl[i]->sections[j].repeat, j);
                sect_root->txt = strdup(txt);
                sect_root->tag = (long)(&(tbl[i]->sections[j]));
                tnode_attach(tbl_root, sect_root);

                s_parse_sect_ait(sect_root, tbl[i], j, pid_list);
            }

			if(s_is_verbose){
				fprintf(stdout, "done\n");
				fflush(stdout);
			}

        }
    }
}

/* modified(bruin, 2003.04.28): output all psi/si packets, "max_packets" only
   apply to es packets and null packets */
static void s_add_pids(TSR_RESULT* result, TNODE* root, int max_packet){
    
	PID_NODE       *pid_node;
    PACKET_HEADER  *ph;
    TNODE          *node, *n2, *n3;
    char           txt[TXT_BUF_SIZE + 1];
    const char     *pidname;
    int            i, j;

	int            is_es_or_null;  /* added(bruin, 2003.04.28) */


    if(!result || !root)
        return;


    /* pids root */
    node = tnode_new(NODE_TYPE_PIDS);
	snprintf(txt, TXT_BUF_SIZE, "PIDs, %d total", result->pid_list->pid_nr);
	node->txt = strdup(txt);
    tnode_attach(root, node);


	/* pid leaves */
	for(pid_node = result->pid_list->head; pid_node != 0; pid_node = pid_node->next){

        n2 = tnode_new(NODE_TYPE_PID);

        pidname = get_pid_name_by_id(pid_node->pid);
        
		if(!pidname){ /* pmt or ait? */

        	/* check if it's pmt pid */
        	for(i = 0; i < result->pmt_list.pmt_nr; i ++)
        		if(result->pmt_list.pmt_pid[i] == pid_node->pid)
        			pidname = "PMT";
                
            /* added(bruin, 2003.01.13): check if it's ait pid */
            for(i = 0; i < result->ait_list.ait_nr; i ++)
                if(result->ait_list.ait_pid[i] == pid_node->pid)
                    pidname = "AIT";
            
		}
        
		is_es_or_null = 0;
		if(!pidname){ /* es */
			is_es_or_null = 1;
			pidname = get_stream_type_name_by_id(pid_node->stream_type);
		}
		else{
			if(pid_node->pid == PID_NUL){
				is_es_or_null = 1;
			}
		}

		snprintf(txt, TXT_BUF_SIZE, "PID 0x%04x(%d), %d(%.2f%%) => %s", 
			                         pid_node->pid, 
									 pid_node->pid, 
									 pid_node->packet_nr, 
									 pid_node->packet_nr * 100.0 / result->packet_nr,
									 pidname?pidname:"");
        n2->txt = strdup(txt);
        tnode_attach(node, n2);

		if(s_is_verbose){
			fprintf(stdout, "\tattaching pid 0x%04x %s...", pid_node->pid, pidname?pidname:"");
			fflush(stdout);
		}

		for(j = 0; 
		    /* modified(bruin, 2004.05.24): "j <" was ommited before "(int)(pid_node->packet_nr)"  */
		    is_es_or_null? (j < (int)(pid_node->packet_nr) && j < max_packet) : (j < (int)(pid_node->packet_nr)); 
			/* j < (int)(pid_node->packet_nr); */
			j ++){ 
          
            n3 = tnode_new(NODE_TYPE_PACKET);
			ph = (PACKET_HEADER*)(result->ts_data + pid_node->index[j] * result->packet_size);
			snprintf(txt, TXT_BUF_SIZE, "%-7d: 0x%02x, 0x%01x, 0x%01x, 0x%01x ,0x%04x ,0x%01x, 0x%01x, 0x%01x", 
										 pid_node->index[j],
										 packet_sync_byte(ph),
										 packet_transport_error_indicator(ph),
										 packet_payload_unit_start_indicator(ph),
										 packet_transport_priority(ph),
										 packet_pid(ph),
										 packet_transport_scrambling_control(ph),
										 packet_adaptation_field_control(ph),
										 packet_continuity_counter(ph));
            n3->txt = strdup(txt);
            n3->tag = pid_node->index[j];
            tnode_attach(n2, n3);
		}

		if(s_is_verbose){
			fprintf(stdout, "done\n");
			fflush(stdout);
		}
	}
}

static void s_add_packets(TSR_RESULT* result, TNODE* root, int max_packet){
    
    PACKET_HEADER  *ph;
    TNODE          *node, *n2;
    char           txt[TXT_BUF_SIZE + 1];
    int            i;

    if(!result || !root)
        return;

    /* packets root */
    node = tnode_new(NODE_TYPE_PACKETS);
	snprintf(txt, TXT_BUF_SIZE, "Packets, %d total", result->packet_nr);
    node->txt = strdup(txt);
    tnode_attach(root, node);

	if(s_is_verbose){
		fprintf(stdout, "\tattaching %d sample packets' raw content...", max_packet);
		fflush(stdout);
	}

	/* packet leaves */
	for(i = 0; i < max_packet && i < (int)(result->packet_nr); i ++){  
		ph = (PACKET_HEADER*)(result->ts_data + i * result->packet_size);
        n2 = tnode_new(NODE_TYPE_PACKET);
		snprintf(txt, TXT_BUF_SIZE, "%-4d: 0x%02x, 0x%01x, 0x%01x, 0x%01x ,0x%04x ,0x%01x, 0x%01x, 0x%01x",
									 i,
									 packet_sync_byte(ph),
									 packet_transport_error_indicator(ph),
									 packet_payload_unit_start_indicator(ph),
									 packet_transport_priority(ph),
									 packet_pid(ph),
									 packet_transport_scrambling_control(ph),
									 packet_adaptation_field_control(ph),
									 packet_continuity_counter(ph));
        n2->txt = strdup(txt);
        n2->tag = i;
        tnode_attach(node, n2);
	}

	if(s_is_verbose){
		fprintf(stdout, "done\n");
		fflush(stdout);
	}
}


/*--------------------------------------------------------------------+
 | parse of each table sections                                       |
 +--------------------------------------------------------------------*/

static void s_parse_sect_pat(TNODE* sect_root, TABLE *tbl_pat, int index){

    char   txt[TXT_BUF_SIZE + 1];
    int    section_length, npmt, i;
    TNODE* node;
    u8     *p;

    p = (u8*)(tbl_pat->sections[index].data);

    /* table_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "table_id: 0x%02x", ((PAT_SECT_HEADER*)p)->table_id);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_syntax_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_syntax_indicator: 0x%02x", ((PAT_SECT_HEADER*)p)->section_syntax_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_length */
    section_length = ((PAT_SECT_HEADER*)p)->section_length_hi * 256 + ((PAT_SECT_HEADER*)p)->section_length_lo;
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_length: 0x%02x(%d)", section_length, section_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* transport_stream_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "transport_stream_id: 0x%04x", ((PAT_SECT_HEADER*)p)->transport_stream_id_hi * 256 + ((PAT_SECT_HEADER*)p)->transport_stream_id_lo);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* version_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "version_number: 0x%02x", ((PAT_SECT_HEADER*)p)->version_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* current_next_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "current_next_indicator: 0x%01x", ((PAT_SECT_HEADER*)p)->current_next_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_number: 0x%02x(%d)", ((PAT_SECT_HEADER*)p)->section_number, ((PAT_SECT_HEADER*)p)->section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* last_section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "last_section_number: 0x%02x(%d)", ((PAT_SECT_HEADER*)p)->last_section_number, ((PAT_SECT_HEADER*)p)->last_section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* programs loop */
    node = tnode_new(NODE_TYPE_DEFAULT);
    node->txt = strdup("programs");
    tnode_attach(sect_root, node);

    npmt = (section_length - 5 - CRC_32_SIZE) / 4; /* each program uses 4 bytes */
    p += PAT_SECT_HEADER_LEN; 
    for(i = 0; i < npmt; i ++, p += 4){
        TNODE* n = tnode_new(NODE_TYPE_PROGRAM);
        snprintf(txt, TXT_BUF_SIZE, "program_number: 0x%02x%02x (%d) => pid: 0x%02x%02x (%d)", 
            p[0], p[1], p[0] * 256 + p[1],
            p[2] & 0x1f, p[3], (p[2] & 0x1f) * 256 + p[3]);
        n->txt = strdup(txt);
        tnode_attach(node, n);
    }

    /* crc 32 */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "crc_32: 0x%02x%02x%02x%02x", p[0], p[1], p[2], p[3]);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);
}


static void s_parse_sect_cat(TNODE* sect_root, TABLE *tbl_cat, int index){


    char   txt[TXT_BUF_SIZE + 1];
    int    section_length, descriptors_loop_length;
    TNODE* node;
    u8     *p;

    p = (u8*)(tbl_cat->sections[index].data);

    /* table_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "table_id: 0x%02x", ((CAT_SECT_HEADER*)p)->table_id);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_syntax_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_syntax_indicator: 0x%02x", ((CAT_SECT_HEADER*)p)->section_syntax_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    section_length = ((CAT_SECT_HEADER*)p)->section_length_hi * 256 + ((CAT_SECT_HEADER*)p)->section_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "section_length: 0x%02x(%d)", section_length, section_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* version_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "version_number: 0x%02x", ((CAT_SECT_HEADER*)p)->version_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* current_next_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "current_next_indicator: 0x%01x", ((CAT_SECT_HEADER*)p)->current_next_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_number: 0x%02x(%d)", ((CAT_SECT_HEADER*)p)->section_number, ((CAT_SECT_HEADER*)p)->section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* last_section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "last_section_number: 0x%02x(%d)", ((CAT_SECT_HEADER*)p)->last_section_number, ((CAT_SECT_HEADER*)p)->last_section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* descriptors_loop_length */
    descriptors_loop_length = section_length - 5 - CRC_32_SIZE;

    /* program_info_descriptors loop */
    p += CAT_SECT_HEADER_LEN;
    if(descriptors_loop_length > 0){
        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup("descriptors");
        tnode_attach(sect_root, node);
        s_parse_descriptors_loop(p, descriptors_loop_length, node);
        p += descriptors_loop_length;
    }

    /* crc 32 */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "crc_32: 0x%02x%02x%02x%02x", p[0], p[1], p[2], p[3]);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);
}


static void s_parse_sect_pmt(TNODE* sect_root, TABLE *tbl_pmt, int index, PID_LIST* pid_list){
    
    char   txt[TXT_BUF_SIZE + 1];
    int    section_length, program_info_length, es_loop_length, es_info_length, i, j;
    TNODE* node;
    u16    pcr_pid;
    u8*    p;
    
    p = (u8*)(tbl_pmt->sections[index].data);

    /* table_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "table_id: 0x%02x", ((PMT_SECT_HEADER*)p)->table_id);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_syntax_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_syntax_indicator: 0x%02x", ((PMT_SECT_HEADER*)p)->section_syntax_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    section_length = ((PMT_SECT_HEADER*)p)->section_length_hi * 256 + ((PMT_SECT_HEADER*)p)->section_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "section_length: 0x%02x(%d)", section_length, section_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* program_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "program_number: 0x%04x", ((PMT_SECT_HEADER*)p)->program_number_hi * 256 + ((PMT_SECT_HEADER*)p)->program_number_lo);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* version_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "version_number: 0x%02x", ((PMT_SECT_HEADER*)p)->version_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* current_next_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "current_next_indicator: 0x%01x", ((PMT_SECT_HEADER*)p)->current_next_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_number: 0x%02x(%d)", ((PMT_SECT_HEADER*)p)->section_number, ((PMT_SECT_HEADER*)p)->section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* last_section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "last_section_number: 0x%02x(%d)", ((PMT_SECT_HEADER*)p)->last_section_number, ((PMT_SECT_HEADER*)p)->last_section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* pcr_pid */
    node = tnode_new(NODE_TYPE_DEFAULT);
    pcr_pid = ((PMT_SECT_HEADER*)p)->pcr_pid_hi * 256 + ((PMT_SECT_HEADER*)p)->pcr_pid_lo;
    snprintf(txt, TXT_BUF_SIZE, "pcr_pid: 0x%03x (%d)", pcr_pid, pcr_pid);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* program_info_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    program_info_length = ((PMT_SECT_HEADER*)p)->program_info_length_hi * 256 + ((PMT_SECT_HEADER*)p)->program_info_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "program_info_length: 0x%04x (%d)", program_info_length, program_info_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* program_info_descriptors loop */
    p += PMT_SECT_HEADER_LEN;
    if(program_info_length > 0){
        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup("program_info_descriptors");
        tnode_attach(sect_root, node);
        s_parse_descriptors_loop(p, program_info_length, node);
        p += program_info_length;
    }

    /* es_loop */
    node = tnode_new(NODE_TYPE_DEFAULT);
    node->txt = strdup("components");
    tnode_attach(sect_root, node);

    es_loop_length = section_length - 9 - program_info_length - 4;
    j = 0;
    for(i = 0; j < es_loop_length; i ++){ /* i: es index, j: data range guard */
        
        /* update pid_list for the stream_type field of each pid node */
        u8         stream_type = p[0];
        u16        es_pid = (p[1] & 0x1f) * 256 + p[2];
        PID_NODE*  pid_node;
        TNODE      *n2, *n3;
        for(pid_node = pid_list->head; pid_node != 0; pid_node = pid_node->next){
            if(pid_node->pid == es_pid){
                pid_node->stream_type = stream_type;
                break;
            }
        }

        switch(p[0]){
            case STREAMTYPE_11172_VIDEO:
            case STREAMTYPE_13818_VIDEO:
                n2 = tnode_new(NODE_TYPE_VIDEO_STREAM);
                break;
            case STREAMTYPE_11172_AUDIO:
            case STREAMTYPE_13818_AUDIO:
                n2 = tnode_new(NODE_TYPE_AUDIO_STREAM);
                break;
            case STREAMTYPE_13818_PRIVATE:
                n2 = tnode_new(NODE_TYPE_PRIVATE_DATA_STREAM);
                break;
            default:
                n2 = tnode_new(NODE_TYPE_DEFAULT);
                break;
        }
        snprintf(txt, TXT_BUF_SIZE, "stream_type: 0x%02x => %s", stream_type, get_stream_type_name_by_id(stream_type));
        n2->txt = strdup(txt);
        tnode_attach(node, n2);

        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "elementary_pid: 0x%03x(%d)", es_pid, es_pid);
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        n3 = tnode_new(NODE_TYPE_DEFAULT);
        es_info_length = (p[3] & 0x0f) * 256 + p[4];
        snprintf(txt, TXT_BUF_SIZE, "es_info_length: 0x%02x", es_info_length);
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        p += 5;
        j += 5;
        if(es_info_length > 0){
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            n3->txt = strdup("es descriptors");
            tnode_attach(n2, n3);

            s_parse_descriptors_loop(p, es_info_length, n3);
            p += es_info_length;
            j += es_info_length;
        }
    }

    /* crc 32 */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "crc_32: 0x%02x%02x%02x%02x", p[0], p[1], p[2], p[3]);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);
}

static void s_parse_sect_ait(TNODE* sect_root, TABLE *tbl_ait, int index, PID_LIST* pid_list){

    char   txt[TXT_BUF_SIZE + 1];
    int    section_length, i, j;
    u16    application_type, common_descriptors_length, application_loop_length, application_descriptors_loop_length;
    TNODE  *node, *n2, *n3;
    u8*    p;
    
    p = (u8*)(tbl_ait->sections[index].data);

    /* table_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "table_id: 0x%02x", ((AIT_SECT_HEADER*)p)->table_id);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_syntax_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_syntax_indicator: 0x%02x", ((AIT_SECT_HEADER*)p)->section_syntax_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    section_length = ((AIT_SECT_HEADER*)p)->section_length_hi * 256 + ((AIT_SECT_HEADER*)p)->section_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "section_length: 0x%02x(%d)", section_length, section_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* application_type */
    node = tnode_new(NODE_TYPE_DEFAULT);
    application_type = ((AIT_SECT_HEADER*)p)->application_type_hi * 256 + ((AIT_SECT_HEADER*)p)->application_type_lo;
    snprintf(txt, TXT_BUF_SIZE, "application_type: 0x%04x => %s", application_type, get_application_type_by_code(application_type));
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* version_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "version_number: 0x%02x", ((AIT_SECT_HEADER*)p)->version_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* current_next_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "current_next_indicator: 0x%01x", ((AIT_SECT_HEADER*)p)->current_next_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_number: 0x%02x(%d)", ((AIT_SECT_HEADER*)p)->section_number, ((AIT_SECT_HEADER*)p)->section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* last_section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "last_section_number: 0x%02x(%d)", ((AIT_SECT_HEADER*)p)->last_section_number, ((AIT_SECT_HEADER*)p)->last_section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* common_descriptors_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    common_descriptors_length = ((AIT_SECT_HEADER*)p)->common_descriptors_length_hi * 256 + ((AIT_SECT_HEADER*)p)->common_descriptors_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "common_descriptors_length: 0x%03x (%d)", common_descriptors_length, common_descriptors_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    p += AIT_SECT_HEADER_LEN;
        
    /* common_descriptors_loop */
    if(common_descriptors_length > 0){
        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup("common_descriptors");
        tnode_attach(sect_root, node);

        s_parse_descriptors_loop(p, common_descriptors_length, node);
        p += common_descriptors_length;
    }

    node = tnode_new(NODE_TYPE_DEFAULT);
    application_loop_length = (p[0] & 0x0f) * 256 + p[1];
    snprintf(txt, TXT_BUF_SIZE, "application_loop_length: 0x%03x (%d)", application_loop_length, application_loop_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    p += 2;

    if(application_loop_length > 0){
        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup("application_loops");
        tnode_attach(sect_root, node);

        /* i is loop idx */
        j = 0; /* range guard */
        for(i = 0; j < application_loop_length; i ++){
            
            n2 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "application_loop_index: %d", i);
            n2->txt = strdup(txt);
            tnode_attach(node, n2);

            /* application_identifier.organization_id */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "application_identifier.organization_id: 0x%02x%02x%02x%02x", p[0], p[1], p[2], p[3]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);
            
            /* application_identifier.application_id */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "application_identifier.application_id: 0x%02x%02x => %s", p[4], p[5], get_application_id_name_by_id((u16)(p[4] * 256 + p[5])));
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            /* application_control_code */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "application_control_code: 0x%02x => %s", p[6], get_application_control_code_name(application_type, p[6]));
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            /* application_descriptors_loop_length */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            application_descriptors_loop_length = (p[7] & 0x0f) * 256 + p[8];
            snprintf(txt, TXT_BUF_SIZE, "application_descriptors_loop_length: 0x%03x (%d)", application_descriptors_loop_length, application_descriptors_loop_length);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            p += 9;
            j += 9;
            if(application_descriptors_loop_length > 0){
                n3 = tnode_new(NODE_TYPE_DEFAULT);
                n3->txt = strdup("application_descriptors");
                tnode_attach(n2, n3);
                
                s_parse_mhp_descriptors_loop(p, application_descriptors_loop_length, n3);
                p += application_descriptors_loop_length;
                j += application_descriptors_loop_length;
            }
                    
        }
    }
    
    /* crc 32 */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "crc_32: 0x%02x%02x%02x%02x", p[0], p[1], p[2], p[3]);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);
}

static void s_parse_sect_nit(TNODE* sect_root, TABLE* tbl_nit, int index){

    char   txt[TXT_BUF_SIZE + 1];
    int    section_length, network_descriptors_length, transport_stream_loop_length, transport_descriptors_length, i, k;
    TNODE  *node, *n2, *n3;
    u8     *p;
    
    p = (u8*)(tbl_nit->sections[index].data);

    /* table_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "table_id: 0x%02x", ((NIT_SECT_HEADER*)p)->table_id);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_syntax_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_syntax_indicator: 0x%02x", ((NIT_SECT_HEADER*)p)->section_syntax_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    section_length = ((NIT_SECT_HEADER*)p)->section_length_hi * 256 + ((NIT_SECT_HEADER*)p)->section_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "section_length: 0x%02x(%d)", section_length, section_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* network_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "network_id: 0x%04x", ((NIT_SECT_HEADER*)p)->network_id_hi * 256 + ((NIT_SECT_HEADER*)p)->network_id_lo);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* version_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "version_number: 0x%02x", ((NIT_SECT_HEADER*)p)->version_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* current_next_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "current_next_indicator: 0x%01x", ((NIT_SECT_HEADER*)p)->current_next_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_number: 0x%02x(%d)", ((NIT_SECT_HEADER*)p)->section_number, ((NIT_SECT_HEADER*)p)->section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* last_section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "last_section_number: 0x%02x(%d)", ((NIT_SECT_HEADER*)p)->last_section_number, ((NIT_SECT_HEADER*)p)->last_section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* network_descriptors_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    network_descriptors_length = ((NIT_SECT_HEADER*)p)->network_descriptors_length_hi * 256 + ((NIT_SECT_HEADER*)p)->network_descriptors_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "network_descriptors_length: 0x%02x", network_descriptors_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    p += NIT_SECT_HEADER_LEN;
    
    /* network_descriptors */
    if(network_descriptors_length > 0){
        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup("network_descriptors");
        tnode_attach(sect_root, node);

        s_parse_descriptors_loop(p, network_descriptors_length, node);
        p += network_descriptors_length;
    }

    /* transport_stream_loop_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    transport_stream_loop_length = (p[0] & 0x0f) * 256 + p[1];
    snprintf(txt, TXT_BUF_SIZE, "transport_stream_loop_length: 0x%02x", transport_stream_loop_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    p += 2;
   
    /* transport_stream_loop */
    if(transport_stream_loop_length > 0){
        
        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup("transport_streams");
        tnode_attach(sect_root, node);

        k = 0;
        for(i = 0; k < transport_stream_loop_length; i ++){   /* index to transport stream */
            n2 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "transport_stream_id: 0x%04x", p[0] * 256 + p[1]);
            n2->txt = strdup(txt);
            tnode_attach(node, n2);

            /* original_network_id */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "orignal_network_id: 0x%04x", p[2] * 256 + p[3]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            transport_descriptors_length = (p[4] & 0x0F) * 256 + p[5];
            snprintf(txt, TXT_BUF_SIZE, "transport_descriptors_length: 0x%02x", transport_descriptors_length);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);
            
            p += 6; 
            k += 6;

            if(transport_descriptors_length > 0){
                n3 = tnode_new(NODE_TYPE_DEFAULT);
                n3->txt = strdup("transport_descriptors");
                tnode_attach(n2, n3);

                /* transport stream descriptors */
                s_parse_descriptors_loop(p, transport_descriptors_length, n3);
                p += transport_descriptors_length;
                k += transport_descriptors_length;
            }
        }
    }

    /* crc 32 */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "crc_32: 0x%02x%02x%02x%02x", p[0], p[1], p[2], p[3]);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);
}

static void s_parse_sect_bat(TNODE* sect_root, TABLE *tbl_bat, int index){
    
    char   txt[TXT_BUF_SIZE + 1];
    int    section_length, bouquet_descriptors_length, transport_stream_loop_length, transport_descriptors_length, i, k;
    TNODE  *node, *n2, *n3;
    u8     *p;

    p = (u8*)(tbl_bat->sections[index].data);

    /* table_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "table_id: 0x%02x", ((BAT_SECT_HEADER*)p)->table_id);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_syntax_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_syntax_indicator: 0x%02x", ((BAT_SECT_HEADER*)p)->section_syntax_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    section_length = ((BAT_SECT_HEADER*)p)->section_length_hi * 256 + ((BAT_SECT_HEADER*)p)->section_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "section_length: 0x%02x(%d)", section_length, section_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* bouquet_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "bouquet_id: 0x%04x", ((BAT_SECT_HEADER*)p)->bouquet_id_hi * 256 + ((BAT_SECT_HEADER*)p)->bouquet_id_lo);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* version_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "version_number: 0x%02x", ((BAT_SECT_HEADER*)p)->version_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* current_next_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "current_next_indicator: 0x%01x", ((BAT_SECT_HEADER*)p)->current_next_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_number: 0x%02x(%d)", ((BAT_SECT_HEADER*)p)->section_number, ((BAT_SECT_HEADER*)p)->section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* last_section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "last_section_number: 0x%02x(%d)", ((BAT_SECT_HEADER*)p)->last_section_number, ((BAT_SECT_HEADER*)p)->last_section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* bouquet_descriptors_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    bouquet_descriptors_length = ((BAT_SECT_HEADER*)p)->bouquet_descriptors_length_hi * 256 + ((BAT_SECT_HEADER*)p)->bouquet_descriptors_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "bouquet_descriptors_length: 0x%02x (%d)", bouquet_descriptors_length, bouquet_descriptors_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* bouquet_descriptors loop */
    p += BAT_SECT_HEADER_LEN;
    if(bouquet_descriptors_length > 0){
        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup("bouquet_descriptors");
        tnode_attach(sect_root, node);
        s_parse_descriptors_loop(p, bouquet_descriptors_length, node);
        p += bouquet_descriptors_length;
    }

    /* transport_stream_loop_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    transport_stream_loop_length = (p[0] & 0x0f) * 256 + p[1];
    snprintf(txt, TXT_BUF_SIZE, "transport_stream_loop_length: 0x%02x (%d)", transport_stream_loop_length, transport_stream_loop_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    p += 2;
        
    /* transport_stream_loop */
    if(transport_stream_loop_length){
        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup("transport_streams");
        tnode_attach(sect_root, node);

        k = 0;
        for(i = 0; k < transport_stream_loop_length; i ++){   /* index to transport stream */

            n2 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "transport_stream_id: 0x%04x", p[0] * 256 + p[1]);
            n2->txt = strdup(txt);
            tnode_attach(node, n2);

            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "orignal_network_id: 0x%04x", p[2] * 256 + p[3]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);
            
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            transport_descriptors_length = (p[4] & 0x0F) * 256 + p[5];
            snprintf(txt, TXT_BUF_SIZE, "transport_descriptors_length: 0x%02x", transport_descriptors_length);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            p += 6; 
            k += 6;

            if(transport_descriptors_length > 0){

                n3 = tnode_new(NODE_TYPE_DEFAULT);
                n3->txt = strdup("transport_descriptors");
                tnode_attach(n2, n3);
                
                /* transport stream descriptors */
                s_parse_descriptors_loop(p, transport_descriptors_length, n3);
                p += transport_descriptors_length;
                k += transport_descriptors_length;
            }
        }
    }

    /* crc 32 */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "crc_32: 0x%02x%02x%02x%02x", p[0], p[1], p[2], p[3]);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);
}



static void s_parse_sect_sdt(TNODE* sect_root, TABLE *tbl_sdt, int index){

    char   txt[TXT_BUF_SIZE + 1];
    int    section_length, services_loop_length, descriptors_loop_length, i, k;
    TNODE  *node, *n2, *n3;
    u8     *p;
    
    p = (u8*)(tbl_sdt->sections[index].data);

    /* table_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "table_id: 0x%02x", ((SDT_SECT_HEADER*)p)->table_id);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_syntax_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_syntax_indicator: 0x%02x", ((SDT_SECT_HEADER*)p)->section_syntax_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    section_length = ((SDT_SECT_HEADER*)p)->section_length_hi * 256 + ((SDT_SECT_HEADER*)p)->section_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "section_length: 0x%02x(%d)", section_length, section_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* transport_stream_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "transport_stream_id: 0x%04x", ((SDT_SECT_HEADER*)p)->transport_stream_id_hi * 256 + ((SDT_SECT_HEADER*)p)->transport_stream_id_lo);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* version_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "version_number: 0x%02x", ((SDT_SECT_HEADER*)p)->version_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* current_next_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "current_next_indicator: 0x%01x", ((SDT_SECT_HEADER*)p)->current_next_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_number: 0x%02x(%d)", ((SDT_SECT_HEADER*)p)->section_number, ((SDT_SECT_HEADER*)p)->section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* last_section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "last_section_number: 0x%02x(%d)", ((SDT_SECT_HEADER*)p)->last_section_number, ((SDT_SECT_HEADER*)p)->last_section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* original_network_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "original_network_id: 0x%04x", ((SDT_SECT_HEADER*)p)->original_network_id_hi * 256 + ((SDT_SECT_HEADER*)p)->original_network_id_lo);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* services loop length */
    services_loop_length = section_length - 8 - CRC_32_SIZE;
    
    p += SDT_SECT_HEADER_LEN;

    if(services_loop_length > 0){
        
        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup("services");
        tnode_attach(sect_root, node);

        k = 0;
        for(i = 0; k < services_loop_length; i ++){   /* index to outer loop instance */

            n2 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "service_id: 0x%04x (%d)", p[0] * 256 + p[1], p[0] * 256 + p[1]);
            n2->txt = strdup(txt);
            tnode_attach(node, n2);

            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "eit_schedule_flag: 0x%01x", (p[2] >> 1) & 0x1);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "eit_present_following_flag: 0x%01x", p[2] & 0x01);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);
            
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "running_status: 0x%01x", p[3] >> 5);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);
            
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "free_ca_mode: 0x%01x", (p[3] >> 4)& 0x1);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            n3 = tnode_new(NODE_TYPE_DEFAULT);
            descriptors_loop_length = (p[3] & 0x0F) * 256 + p[4];
            snprintf(txt, TXT_BUF_SIZE, "descriptors_loop_length: 0x%02x", descriptors_loop_length);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            p += 5;
            k += 5;
            
            if(descriptors_loop_length > 0){
                n3 = tnode_new(NODE_TYPE_DEFAULT);
                n3->txt = strdup("descriptors");
                tnode_attach(n2, n3);
                
                s_parse_descriptors_loop(p, descriptors_loop_length, n3);
                p += descriptors_loop_length;
                k += descriptors_loop_length;
            }
        }
    }

    /* crc 32 */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "crc_32: 0x%02x%02x%02x%02x", p[0], p[1], p[2], p[3]);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);
}

    
static void s_parse_sect_eit(TNODE* sect_root, TABLE *tbl_eit, int index){

    char   txt[TXT_BUF_SIZE + 1];
    int    section_length, events_loop_length, descriptors_loop_length, i, k;
    TNODE  *node, *n2, *n3;
    u8     *p;
    
    p = (u8*)(tbl_eit->sections[index].data);

    /* table_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "table_id: 0x%02x", ((EIT_SECT_HEADER*)p)->table_id);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_syntax_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_syntax_indicator: 0x%02x", ((EIT_SECT_HEADER*)p)->section_syntax_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    section_length = ((EIT_SECT_HEADER*)p)->section_length_hi * 256 + ((EIT_SECT_HEADER*)p)->section_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "section_length: 0x%02x(%d)", section_length, section_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* service_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "service_id: 0x%04x", ((EIT_SECT_HEADER*)p)->service_id_hi * 256 + ((EIT_SECT_HEADER*)p)->service_id_lo);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* version_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "version_number: 0x%02x", ((EIT_SECT_HEADER*)p)->version_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* current_next_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "current_next_indicator: 0x%01x", ((EIT_SECT_HEADER*)p)->current_next_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_number: 0x%02x(%d)", ((EIT_SECT_HEADER*)p)->section_number, ((EIT_SECT_HEADER*)p)->section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* last_section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "last_section_number: 0x%02x(%d)", ((EIT_SECT_HEADER*)p)->last_section_number, ((EIT_SECT_HEADER*)p)->last_section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* transport_stream_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "transport_stream_id: 0x%04x", ((EIT_SECT_HEADER*)p)->transport_stream_id_hi * 256 + ((EIT_SECT_HEADER*)p)->transport_stream_id_lo);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* original_network_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "original_network_id: 0x%04x", ((EIT_SECT_HEADER*)p)->original_network_id_hi * 256 + ((EIT_SECT_HEADER*)p)->original_network_id_lo);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* segment_last_section_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "segment_last_section_number: 0x%02x(%d)", ((EIT_SECT_HEADER*)p)->segment_last_section_number, ((EIT_SECT_HEADER*)p)->segment_last_section_number);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* last_table_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "last_table_id: 0x%02x", ((EIT_SECT_HEADER*)p)->last_table_id);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    p += EIT_SECT_HEADER_LEN;

    /* events loop length */
    events_loop_length = section_length - 11 - CRC_32_SIZE;

    if(events_loop_length > 0){

        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup("events");
        tnode_attach(sect_root, node);

        k = 0;
        for(i = 0; k < events_loop_length; i ++){   /* index to outer loop instance */

            n2 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "event_id: 0x%04x", p[0] * 256 + p[1]);
            n2->txt = strdup(txt);
            tnode_attach(node, n2);

            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "start_time: 0x%02x%02x%02x%02x%02x", p[2], p[3], p[4], p[5],p[6]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "duration: 0x%02x%02x%02x", p[7], p[8], p[9]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "running_status: 0x%01x", p[10] >> 5);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);
            
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "free_ca_mode: 0x%01x", (p[10] >> 4)& 0x1);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            n3 = tnode_new(NODE_TYPE_DEFAULT);
            descriptors_loop_length = (p[10] & 0x0F) * 256 + p[11];
            snprintf(txt, TXT_BUF_SIZE, "descriptors_loop_length: 0x%02x", descriptors_loop_length);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            p += 12;
            k += 12;
            if(descriptors_loop_length > 0){
                s_parse_descriptors_loop(p, descriptors_loop_length, n3);
                p += descriptors_loop_length;
                k += descriptors_loop_length;
            }
        }
    }

    /* crc 32 */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "crc_32: 0x%02x%02x%02x%02x", p[0], p[1], p[2], p[3]);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);
}

static void s_parse_sect_tdt(TNODE* sect_root, TABLE *tbl_tdt, int index){

    char   txt[TXT_BUF_SIZE + 1];
    int    section_length, len, j;
    TNODE  *node;
    u8     *p;

    p = (u8*)(tbl_tdt->sections[index].data);

    /* table_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "table_id: 0x%02x", ((TDT_SECTION*)p)->table_id);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_syntax_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_syntax_indicator: 0x%02x", ((TDT_SECTION*)p)->section_syntax_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    section_length = ((TDT_SECTION*)p)->section_length_hi * 256 + ((TDT_SECTION*)p)->section_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "section_length: 0x%02x(%d)", section_length, section_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* utc_time */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "utc_time: 0x");
    for(j = 0; j < 5; j ++)
        len += snprintf(txt + len, TXT_BUF_SIZE - len, "%02x", ((TDT_SECTION*)p)->utc_time[j]);
    snprintf(txt + len, TXT_BUF_SIZE - len, " => %s", get_string_by_utc_time(((TDT_SECTION*)p)->utc_time));
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* note: tdt table does not contain a tailing crc_32 */
}

static void s_parse_sect_tot(TNODE* sect_root, TABLE *tbl_tot, int index){

    char   txt[TXT_BUF_SIZE + 1];
    int    section_length, len, descriptors_loop_length, j;
    TNODE  *node;
    u8     *p;

    p = (u8*)(tbl_tot->sections[index].data);

    /* table_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "table_id: 0x%02x", ((TOT_SECT_HEADER*)p)->table_id);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_syntax_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_syntax_indicator: 0x%02x", ((TOT_SECT_HEADER*)p)->section_syntax_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    section_length = ((TOT_SECT_HEADER*)p)->section_length_hi * 256 + ((TOT_SECT_HEADER*)p)->section_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "section_length: 0x%02x(%d)", section_length, section_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* utc_time */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "utc_time: 0x");
    for(j = 0; j < 5; j ++)
        len += snprintf(txt + len, TXT_BUF_SIZE - len, "%02x", ((TOT_SECT_HEADER*)p)->utc_time[j]);
    snprintf(txt + len, TXT_BUF_SIZE - len, " => %s", get_string_by_utc_time(((TOT_SECT_HEADER*)p)->utc_time));
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* descriptors_loop_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    descriptors_loop_length = ((TOT_SECT_HEADER*)p)->descriptors_loop_length_hi * 256 + ((TOT_SECT_HEADER*)p)->descriptors_loop_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "descriptors_loop_length: 0x%02x (%d)", descriptors_loop_length, descriptors_loop_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    p += TOT_SECT_HEADER_LEN;

    /* descriptors_loop */
    if(descriptors_loop_length > 0){
        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup("descriptors");
        tnode_attach(sect_root, node);
        
        s_parse_descriptors_loop(p, descriptors_loop_length, node);
        p += descriptors_loop_length;
    }

    /* crc 32 */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "crc_32: 0x%02x%02x%02x%02x", p[0], p[1], p[2], p[3]);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);
}


static void s_parse_sect_rst(TNODE* sect_root, TABLE *tbl_rst, int index){

    char   txt[TXT_BUF_SIZE + 1];
    int    section_length, events_nr, i;
    TNODE  *node, *n2, *n3;
    u8     *p;

    p = (u8*)(tbl_rst->sections[index].data);

    /* table_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "table_id: 0x%02x", ((RST_SECT_HEADER*)p)->table_id);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_syntax_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "section_syntax_indicator: 0x%02x", ((RST_SECT_HEADER*)p)->section_syntax_indicator);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    /* section_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    section_length = ((RST_SECT_HEADER*)p)->section_length_hi * 256 + ((RST_SECT_HEADER*)p)->section_length_lo;
    snprintf(txt, TXT_BUF_SIZE, "section_length: 0x%02x(%d)", section_length, section_length);
    node->txt = strdup(txt);
    tnode_attach(sect_root, node);

    p += 3;
    events_nr = section_length / RST_OF_EVENT_SIZE;

    /* events loop */
    if(events_nr > 0){
        
        node = tnode_new(NODE_TYPE_DEFAULT);
        node->txt = strdup("events");
        tnode_attach(sect_root, node);

        for(i = 0; i < events_nr; i ++){   /* index to event */
            
            n2 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "index: %d", i);
            n2->txt = strdup(txt);
            tnode_attach(sect_root, n2);
            
            /* transport_stream_id */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "transport_stream_id: 0x%04x", p[0] * 256 + p[1]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            /* orignal_network_id */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "orignal_network_id: 0x%04x", p[2] * 256 + p[3]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            /* service_id */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "service_id: 0x%04x", p[4] * 256 + p[5]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            /* event_id */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "event_id: 0x%04x", p[6] * 256 + p[7]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            /* running_status */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "running_status: 0x%01x => %s", ((RST_OF_EVENT*)p)->running_status, get_running_status_by_code(((RST_OF_EVENT*)p)->running_status));
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            p += RST_OF_EVENT_SIZE;
        }
    }

    /* note: rst table does not contain a tailing crc_32 */
}




static int s_parse_descriptors_loop(u8* p, int loop_len, TNODE* root){
    
    TNODE          *node, *n2;
    char           txt[TXT_BUF_SIZE + 1];
    int            len, i, j, k;

    k = 0;
    for(i = 0; k < loop_len; i ++){

        /* for each descriptor, p[0] and p[1] mean the same, i.e., 
             p[0] is "descriptor_tag", 
             p[1] is "descriptor_length". 
           we parse this two coommon fileds here. 
           
           the whole descriptor data fields are also hex dumped here, 
           which may of value especially for customer descriptors.
         */

        /* descriptor_tag */
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "descriptor_tag: 0x%02x => %s", p[0], get_desc_name_by_id(p[0]));
        node->txt = strdup(txt);
        tnode_attach(root, node);

        /* descriptor_length */        
        n2 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "descriptor_length(byte): %d", p[1]);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);

        n2 = tnode_new(NODE_TYPE_DEFAULT);
        len = snprintf(txt, TXT_BUF_SIZE, "descriptor_data(hex): ");
        for(j = 0; j < p[1]; j ++)
            len += snprintf(txt + len, TXT_BUF_SIZE - len, "%02x ", p[2 + j]);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);

        /* parse the descriptor value */
        switch(p[0]){
            case DESC_VIDEO_STREAM:
                s_parse_desc_video_stream(p, n2);
                break;
            case DESC_AUDIO_STREAM:
                s_parse_desc_audio_stream(p, n2);
                break;
            case DESC_HIERARCHY:
                s_parse_desc_hierarchy(p, n2);
                break;
            case DESC_REGISTRATION:
                s_parse_desc_registration(p, n2);
                break;
            case DESC_DATA_STREAM_ALIGNMENT:
                s_parse_desc_data_stream_alignment(p, n2);
                break;
            case DESC_TARGET_BACKGROUND_GRID:
                s_parse_desc_target_background_grid(p, n2);
                break;
            case DESC_VIDEO_WINDOW:
                s_parse_desc_video_window(p, n2);
                break;
            case DESC_CA:
                s_parse_desc_ca(p, n2);
                break;
            case DESC_ISO_639_LANGUAGE:
                s_parse_desc_iso639_language(p, n2);
                break;
            case DESC_SYSTEM_CLOCK:
                s_parse_desc_system_clock(p, n2);
                break;
            case DESC_MULTIPLEX_BUFFER_UTILIZATION:
                s_parse_desc_multiplex_buffer_utilization(p, n2);
                break;
            case DESC_COPYRIGHT:
                s_parse_desc_copyright(p, n2);
                break;
            case DESC_MAXIMUM_BITRATE:
                s_parse_desc_maximum_bitrate(p, n2);
                break;
            case DESC_PRIVATE_DATA_INDICATOR:
                s_parse_desc_private_data_indicator(p, n2);
                break;
            case DESC_SMOOTHING_BUFFER:
                s_parse_desc_smoothing_buffer(p, n2);
                break;
            case DESC_STD:
                s_parse_desc_std(p, n2);
                break;
            case DESC_IBP:
                s_parse_desc_ibp(p, n2);
                break;
            case DESC_CAROUSEL_IDENTIFIER: // 2015-05-13
                s_parse_desc_carousel_identifier(p, n2);
                break;
            case DESC_NETWORK_NAME:
                s_parse_desc_network_name(p, n2);
                break;
            case DESC_SERVICE_LIST:
                s_parse_desc_service_list(p, n2);
                break;
            case DESC_STUFFING:
                s_parse_desc_stuffing(p, n2);
                break;
            case DESC_SATELLITE_DELIVERY_SYSTEM:
                s_parse_desc_satellite_delivery_system(p, n2);
                break;
            case DESC_CABLE_DELIVERY_SYSTEM:
                s_parse_desc_cable_delivery_system(p, n2);
                break;
            case DESC_VBI_DATA:
                s_parse_desc_vbi_data(p, n2);
                break;
            case DESC_VBI_TELETEXT:
                s_parse_desc_vbi_teletext(p, n2);
                break;
            case DESC_BOUQUET_NAME:
                s_parse_desc_bouquet_name(p, n2);
                break;
            case DESC_SERVICE:
                s_parse_desc_service(p, n2);
                break;
            case DESC_COUNTRY_AVAILABILITY:
                s_parse_desc_country_availability(p, n2);
                break;
            case DESC_LINKAGE:
                s_parse_desc_linkage(p, n2);
                break;
            case DESC_NVOD_REFERENCE:
                s_parse_desc_nvod_reference(p, n2);
                break;
            case DESC_TIME_SHIFTED_SERVICE:
                s_parse_desc_time_shifted_service(p, n2);
                break;
            case DESC_SHORT_EVENT:
                s_parse_desc_short_event(p, n2);
                break;
            case DESC_EXTENDED_EVENT:
                s_parse_desc_extended_event(p, n2);
                break;
            case DESC_TIME_SHIFTED_EVENT:
                s_parse_desc_time_shifted_event(p, n2);
                break;
            case DESC_COMPONENT:
                s_parse_desc_component(p, n2);
                break;
            case DESC_MOSAIC:
                s_parse_desc_mosaic(p, n2);
                break;
            case DESC_STREAM_IDENTIFIER:
                s_parse_desc_stream_identifier(p, n2);
                break;
            case DESC_CA_IDENTIFIER:
                s_parse_desc_ca_identifier(p, n2);
                break;
            case DESC_CONTENT:
                s_parse_desc_content(p, n2);
                break;
            case DESC_PARENTAL_RATING:
                s_parse_desc_parental_rating(p, n2);
                break;
            case DESC_TELETEXT:
                s_parse_desc_teletext(p, n2);
                break;
            case DESC_TELEPHONE:
                s_parse_desc_telephone(p, n2);
                break;
            case DESC_LOCAL_TIME_OFFSET:
                s_parse_desc_local_time_offset(p, n2);
                break;
            case DESC_SUBTITLING:
                s_parse_desc_subtitling(p, n2);
                break;
            case DESC_TERRESTRIAL_DELIVERY_SYSTEM:
                s_parse_desc_terrestrial_delivery_system(p, n2);
                break;
            case DESC_MULTILINGUAL_NETWORK_NAME:
                s_parse_desc_multilingual_network_name(p, n2);
                break;
            case DESC_MULTILINGUAL_BOUQUET_NAME:
                s_parse_desc_multilingual_bouquet_name(p, n2);
                break;
            case DESC_MULTILINGUAL_SERVICE_NAME:
                s_parse_desc_multilingual_service_name(p, n2);
                break;
            case DESC_MULTILINGUAL_COMPONENT:
                s_parse_desc_multilingual_component(p, n2);
                break;
            case DESC_PRIVATE_DATA_SPECIFIER:
                s_parse_desc_private_data_specifier(p, n2);
                break;
            case DESC_SERVICE_MOVE:
                s_parse_desc_service_move(p, n2);
                break;
            case DESC_SHORT_SMOOTHING_BUFFER:
                s_parse_desc_short_smoothing_buffer(p, n2);
                break;
            case DESC_FREQUENCY_LIST:
                s_parse_desc_frequency_list(p, n2);
                break;
            case DESC_PARTIAL_TRANSPORT_STREAM:
                s_parse_desc_partial_transport_stream(p, n2);
                break;
            case DESC_DATA_BROADCAST:
                s_parse_desc_data_broadcast(p, n2);
                break;
            case DESC_CA_SYSTEM:
                s_parse_desc_ca_system(p, n2);
                break;
            case DESC_DATA_BROADCAST_ID:
                s_parse_desc_data_broadcast_id(p, n2);
                break;
            case DESC_TRANSPORT_STREAM:
                s_parse_desc_transport_stream(p, n2);
                break;
            case DESC_DSNG:
                s_parse_desc_dsng(p, n2);
                break;
            case DESC_PDC:
                s_parse_desc_pdc(p, n2);
                break;
            case DESC_AC_3:
                s_parse_desc_ac3(p, n2);
                break;
            case DESC_ANCILLARY_DATA:
                s_parse_desc_ancillary_data(p, n2);
                break;
            case DESC_CELL_LIST:
                s_parse_desc_cell_list(p, n2);
                break;
            case DESC_CELL_FREQUENCY_LINK:
                s_parse_desc_cell_frequency_link(p, n2);
                break;
            case DESC_ANNOUNCEMENT_SUPPORT:
                s_parse_desc_announcement_support(p, n2);
                break;
            case DESC_OPENTV_TRACK_TAG:
                s_parse_desc_opentv_track_tag(p, n2);
                break;
            case DESC_APPLICATION_SIGNALLING:
                s_parse_desc_application_signalling(p, n2);
                break;
            case DESC_SERVICE_IDENTIFIER:
                s_parse_desc_service_identifier(p, n2);
                break;
                
            /* added(bruin, 2003.02.17) */
            case DESC_RCS_CONTENT:
                s_parse_desc_rcs_content(p, n2);
                break;
                
			/* added(2003.12.18): LCN draft from LCN draft from <CSevior@nine.com.au> */
			case DESC_LOGICAL_CHANNEL:
				s_parse_desc_logical_channel(p, n2);
				break;

            default:
                break;
        }

        k += p[1] + 2;
        p += p[1] + 2;
    }

    return i;
}




/*--------------------------------------------------------------------+
 | parse of each individual descriptor                                |
 +--------------------------------------------------------------------*/

static void s_parse_desc_video_stream(u8 *p, TNODE* root){

    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    VIDEO_STREAM_DESC* desc = (VIDEO_STREAM_DESC*)p;

    /* multiple_frame_rate_flag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "multiple_frame_rate_flag: %d", desc->multiple_frame_rate_flag);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* frame_rate_code */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "frame_rate_code: 0x%01x => %s", desc->frame_rate_code, get_frame_rate_by_code(desc->frame_rate_code));
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* mpeg_1_only_flag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "mpeg_1_only_flag: %d", desc->mpeg_1_only_flag);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* constrained_parameter_flag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "constrained_parameter_flag: %d", desc->constrained_parameter_flag);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* still_picture_flag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "still_picture_flag: %d", desc->still_picture_flag);
    node->txt = strdup(txt);
    tnode_attach(root, node);
    
    if(!desc->mpeg_1_only_flag){
        /* profile_and_level_indication */
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "profile_and_level_indication: 0x%02x => %s@%s", desc->profile_and_level_indication, get_video_profile_by_code(desc->profile_and_level_indication), get_video_level_by_code(desc->profile_and_level_indication));
        node->txt = strdup(txt);
        tnode_attach(root, node);

        /* chroma_format */
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "chroma_format: 0x%01x => %s", desc->chroma_format, get_chroma_format_by_code(desc->chroma_format));
        node->txt = strdup(txt);
        tnode_attach(root, node);

        /* frame_rate_extension_flag */
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "frame_rate_extension_flag: %d", desc->frame_rate_extension_flag);
        node->txt = strdup(txt);
        tnode_attach(root, node);
    }
}

static void s_parse_desc_audio_stream(u8 *p, TNODE* root){

    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    AUDIO_STREAM_DESC* desc = (AUDIO_STREAM_DESC*)p;

    /* free_format_flag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "free_format_flag: %d", desc->free_format_flag);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "id: %d", desc->id);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* layer */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "layer: %d", desc->layer);
    node->txt = strdup(txt);
    tnode_attach(root, node);
    
    /* variable_rate_audio_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "variable_rate_audio_indicator: %d", desc->variable_rate_audio_indicator);
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_maximum_bitrate(u8 *p, TNODE* root){

    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    bitrate;

    MAXIMUM_BITRATE_DESC* desc = (MAXIMUM_BITRATE_DESC*)p;

    /* maximum_bitrate */
    node = tnode_new(NODE_TYPE_DEFAULT);
    bitrate = desc->maximum_bitrate_hi * 256 * 256 + desc->maximum_bitrate_mi * 256 + desc->maximum_bitrate_lo;
    bitrate *= 50; /* bps */
    snprintf(txt, TXT_BUF_SIZE, "maximum_bitrate: %d bps", bitrate);
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_ca(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    i, len;

    CA_DESC_HEADER* desc = (CA_DESC_HEADER*)p;

    /* ca_system_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "ca_system_id: 0x%02x%02x (%d)", desc->ca_system_id_hi, desc->ca_system_id_lo, desc->ca_system_id_hi * 256 + desc->ca_system_id_lo);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* ca_pid */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "ca_pid: 0x%02x%02x (%d)", desc->ca_pid_hi, desc->ca_pid_lo, desc->ca_pid_hi * 256 + desc->ca_pid_lo);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    p += 6;
    /* private_data_byte */
    if(desc->descriptor_length > 4){
        node = tnode_new(NODE_TYPE_DEFAULT);
        len = snprintf(txt, TXT_BUF_SIZE, "private_data_byte: ");
        for(i = 0; i < desc->descriptor_length - 4; i ++) 
            len += snprintf(txt + len, TXT_BUF_SIZE - len, "0x%02x, ", p[i]);
        node->txt = strdup(txt);
        tnode_attach(root, node);
    }
}


static void s_parse_desc_hierarchy(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    HIERARCHY_DESC* desc = (HIERARCHY_DESC*)p;

    /* hierarchy_type */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "hierarchy_type: %d", desc->hierarchy_type);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* hierarchy_layer_index */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "hierarchy_layer_index: %d", desc->hierarchy_layer_index);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* hierarchy_embedded_layer */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "hierarchy_embedded_layer: %d", desc->hierarchy_embedded_layer);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* hierarchy_priority */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "hierarchy_priority: %d", desc->hierarchy_priority);
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_registration(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    i, len;

    REGISTRATION_DESC_HEADER* desc = (REGISTRATION_DESC_HEADER*)p;

    /* format_identifier */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "format_identifier: 0x%02x%02x%02x%02x", desc->format_identifier[0], desc->format_identifier[1], desc->format_identifier[2], desc->format_identifier[3]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    p += 6;
    
    /* additional_identification_info */
    if(desc->descriptor_length > 4){
        node = tnode_new(NODE_TYPE_DEFAULT);
        len = snprintf(txt, TXT_BUF_SIZE, "additional_identification_info: ");
        for(i = 0; i < desc->descriptor_length - 4; i ++) 
            len += snprintf(txt + len, TXT_BUF_SIZE - len, "0x%02x, ", p[i]);
        node->txt = strdup(txt);
        tnode_attach(root, node);
    }

}

static void s_parse_desc_system_clock(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    SYSTEM_CLOCK_DESC* desc = (SYSTEM_CLOCK_DESC*)p;

    /* external_clock_reference_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "external_clock_reference_indicator: %d", desc->external_clock_reference_indicator);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* clock_accuracy_integer */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "clock_accuracy_integer: %d", desc->clock_accuracy_integer);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* clock_accuracy_exponent */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "clock_accuracy_exponent: %d", desc->clock_accuracy_exponent);
    node->txt = strdup(txt);
    tnode_attach(root, node);
}


static void s_parse_desc_copyright(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    i, len;
    
    COPYRIGHT_DESC_HEADER* desc = (COPYRIGHT_DESC_HEADER*)p;

    /* copyright_identifier */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "copyright_identifier: 0x%02x%02x%02x%02x", desc->copyright_identifier[0], desc->copyright_identifier[1], desc->copyright_identifier[2], desc->copyright_identifier[3]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    p += 6;
    
    /* additional_copyright_info */
    if(desc->descriptor_length > 4){
        node = tnode_new(NODE_TYPE_DEFAULT);
        len = snprintf(txt, TXT_BUF_SIZE, "additional_copyright_info: ");
        for(i = 0; i < desc->descriptor_length - 4; i ++) 
            len += snprintf(txt + len, TXT_BUF_SIZE - len, "0x%02x, ", p[i]);
        node->txt = strdup(txt);
        tnode_attach(root, node);
    }
}

static void s_parse_desc_opentv_track_tag(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    OPENTV_TRACK_TAG_DESC* desc = (OPENTV_TRACK_TAG_DESC*)p;

    /* private_data_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "opentv_track_tag: 0x%02x%02x%02x%02x => \"%c%c%c%c\"", 
              desc->track_tag[0], 
              desc->track_tag[1], 
              desc->track_tag[2], 
              desc->track_tag[3],
              /*
              (desc->track_tag[0] > 0x20 && desc->track_tag[0] < 0x7e)? desc->track_tag[0]: '.', 
              (desc->track_tag[1] > 0x20 && desc->track_tag[1] < 0x7e)? desc->track_tag[1]: '.', 
              (desc->track_tag[2] > 0x20 && desc->track_tag[2] < 0x7e)? desc->track_tag[2]: '.', 
              (desc->track_tag[3] > 0x20 && desc->track_tag[3] < 0x7e)? desc->track_tag[3]: '.');
              */
              PRINTABLE_CODE(desc->track_tag[0]),
              PRINTABLE_CODE(desc->track_tag[1]),
              PRINTABLE_CODE(desc->track_tag[2]),
              PRINTABLE_CODE(desc->track_tag[3]));
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_private_data_indicator(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    PRIVATE_DATA_INDICATOR_DESC* desc = (PRIVATE_DATA_INDICATOR_DESC*)p;

    /* private_data_indicator */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "private_data_indicator: 0x%02x%02x%02x%02x => \"%c%c%c%c\"", 
              desc->private_data_indicator[0], 
              desc->private_data_indicator[1], 
              desc->private_data_indicator[2], 
              desc->private_data_indicator[3],
              /*
              (desc->private_data_indicator[0] > 0x20 && desc->private_data_indicator[0] < 0x7e)? desc->private_data_indicator[0]: '.', 
              (desc->private_data_indicator[1] > 0x20 && desc->private_data_indicator[1] < 0x7e)? desc->private_data_indicator[1]: '.', 
              (desc->private_data_indicator[2] > 0x20 && desc->private_data_indicator[2] < 0x7e)? desc->private_data_indicator[2]: '.', 
              (desc->private_data_indicator[3] > 0x20 && desc->private_data_indicator[3] < 0x7e)? desc->private_data_indicator[3]: '.');
              */
              PRINTABLE_CODE(desc->private_data_indicator[0]),
              PRINTABLE_CODE(desc->private_data_indicator[1]),
              PRINTABLE_CODE(desc->private_data_indicator[2]),
              PRINTABLE_CODE(desc->private_data_indicator[3]));

    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_iso639_language(u8 *p, TNODE* root){
    TNODE  *node, *n2, *n3;
    char   txt[TXT_BUF_SIZE + 1];
    int    langs, i;

    ISO_639_LANGUAGE_DESC_HEADER* desc = (ISO_639_LANGUAGE_DESC_HEADER*)p;

    /* languages */
    node = tnode_new(NODE_TYPE_DEFAULT);
    langs = desc->descriptor_length / 4;
    snprintf(txt, TXT_BUF_SIZE, "number of audio languages: %d", langs);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    p += 2;
    
    for(i = 0; i < langs; i ++){
        /* index */
        n2 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "language_index: %d", i);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);

        /* iso_639_language_code */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "iso_639_language_code: 0x%02x%02x%02x => \"%c%c%c\"", 
            p[i * 4 ], 
            p[i * 4 + 1], 
            p[i * 4 + 2], 
            /*
            (p[i * 4 ] > 0x20 && p[i * 4] < 0x7e)? p[i * 4] : '.', 
            (p[i * 4 + 1] > 0x20 && p[i * 4 + 1] < 0x7e)? p[i * 4 + 1] : '.', 
            (p[i * 4 + 2] > 0x20 && p[i * 4 + 2] < 0x7e)? p[i * 4 + 2] : '.'); 
            */
            PRINTABLE_CODE(p[i * 4 ]),
            PRINTABLE_CODE(p[i * 4 + 1]),
            PRINTABLE_CODE(p[i * 4 + 2]));

        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* audio_type */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "audio_type: 0x%02x => %s", p[i * 4 + 3], get_audio_type_by_code(p[i * 4]));
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);
    }
}


static void s_parse_desc_data_stream_alignment(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    DATA_STREAM_ALIGNMENT_DESC* desc = (DATA_STREAM_ALIGNMENT_DESC*)p;

    /* alignment_type */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "alignment_type: 0x%02x", desc->alignment_type);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* TBD:  get_data_stream_alignment_by_code(...) */

}

static void s_parse_desc_target_background_grid(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    TARGET_BACKGROUND_GRID_DESC* desc = (TARGET_BACKGROUND_GRID_DESC*)p;

    /* horizontal_size */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "horizontal_size(pixel): %d", desc->horizontal_size_hi * 256 + desc->horizontal_size_lo);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* vertical_size */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "vertical_size(pixel): %d", desc->vertical_size_hi * 256 * 256 + desc->vertical_size_mi * 256 + desc->vertical_size_lo);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* aspect_ratio_information */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "aspect_ratio_information: 0x%01x => %s", desc->aspect_ratio_information, get_aspect_ratio_information_by_code(desc->aspect_ratio_information));
    node->txt = strdup(txt);
    tnode_attach(root, node);

}

static void s_parse_desc_video_window(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    VIDEO_WINDOW_DESC* desc = (VIDEO_WINDOW_DESC*)p;

    /* horizontal_offset */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "horizontal_offset(pixel): %d", desc->horizontal_offset_hi * 256 + desc->horizontal_offset_lo);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* vertical_offset */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "vertical_offset(pixel): %d", desc->vertical_offset_hi * 256 * 256 + desc->vertical_offset_mi * 256 + desc->vertical_offset_lo);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* window_priority */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "window_priority: 0x%01x", desc->window_priority);
    node->txt = strdup(txt);
    tnode_attach(root, node);
}


static void s_parse_desc_multiplex_buffer_utilization(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    MULTIPLEX_BUFFER_UTILIZATION_DESC* desc = (MULTIPLEX_BUFFER_UTILIZATION_DESC*)p;

    /* bound_valid_flag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "bound_valid_flag: %d", desc->bound_valid_flag);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* ltw_offset_lower_bound */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "ltw_offset_lower_bound: %d", desc->ltw_offset_lower_bound_hi * 256 + desc->ltw_offset_lower_bound_lo);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* ltw_offset_upper_bound */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "ltw_offset_upper_bound: %d", desc->ltw_offset_upper_bound_hi * 256 + desc->ltw_offset_upper_bound_lo);
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_smoothing_buffer(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    sb_leak_rate, sb_size;

    SMOOTHING_BUFFER_DESC* desc = (SMOOTHING_BUFFER_DESC*)p;

    /* sb_leak_rate */
    node = tnode_new(NODE_TYPE_DEFAULT);
    sb_leak_rate = desc->sb_leak_rate_hi * 256 * 256 + desc->sb_leak_rate_mi * 256 + desc->sb_leak_rate_lo;
    sb_leak_rate *= 400;
    snprintf(txt, TXT_BUF_SIZE, "sb_leak_rate: %d bps", sb_leak_rate);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* sb_size */
    node = tnode_new(NODE_TYPE_DEFAULT);
    sb_size = desc->sb_size_hi * 256 * 256 + desc->sb_size_mi * 256 + desc->sb_size_lo;
    snprintf(txt, TXT_BUF_SIZE, "sb_size: %d byte", sb_size);
    node->txt = strdup(txt);
    tnode_attach(root, node);

}

static void s_parse_desc_std(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    STD_DESC* desc = (STD_DESC*)p;

    /* leak_valid_flag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "leak_valid_flag: %d", desc->leak_valid_flag);
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_ibp(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    IBP_DESC* desc = (IBP_DESC*)p;

    /* closed_gop_flag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "closed_gop_flag: %d", desc->closed_gop_flag);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* identical_gop_flag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "identical_gop_flag: %d", desc->identical_gop_flag);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* max_gop_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "max_gop_length: %d", desc->max_gop_length_hi * 256 + desc->max_gop_length_lo);
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

// 2015-05-13, PMT ES loop for dsm-cc dc/oc carousel, tr101202, table 4.17
static void s_parse_desc_carousel_identifier(u8 *p, TNODE* root){
    TNODE  *node;
    TNODE  *fs; // format specifier node
    char   txt[TXT_BUF_SIZE + 1];
    int i, len, desc_len;

    desc_len = p[1];
    p += 2; // skip the descriptor tag and descriptor len
    
    // carousel_id
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "carousel_id: 0x%08x(%d)", UIMSBF32(p), UIMSBF32(p));
    node->txt = strdup(txt);
    tnode_attach(root, node);

    // FormatId
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "FormatId: 0x%02x(%d)", p[4], p[4]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    if(p[4] == 0x1) {
        // FormatSpecifier
        fs = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "FormatSpecifier");
        fs->txt = strdup(txt);
        tnode_attach(root, fs);
        
        // ModuleVersion
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "ModuleVersion: 0x%02x(%d)", p[5], p[5]);
        node->txt = strdup(txt);
        tnode_attach(fs, node);
        p += 6;
        
        // ModuleId
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "ModuleId: 0x%04x(%d)", UIMSBF16(p), UIMSBF16(p));
        node->txt = strdup(txt);
        tnode_attach(fs, node);
        p += 2;
        
        // BlockSize
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "BlockSize: 0x%04x(%d)", UIMSBF16(p), UIMSBF16(p));
        node->txt = strdup(txt);
        tnode_attach(fs, node);
        p += 2;        
        
        // ModuleSize
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "ModuleSize: 0x%08x(%d)", UIMSBF32(p), UIMSBF32(p));
        node->txt = strdup(txt);
        tnode_attach(fs, node);
        p += 4;
        
        // CompressionMethod
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "CompressionMethod: 0x%02x(%d)", p[0], p[0]);
        node->txt = strdup(txt);
        tnode_attach(fs, node);
        p += 1;
        
        // OriginalSize
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "OriginalSize: 0x%08x(%d)", UIMSBF32(p), UIMSBF32(p));
        node->txt = strdup(txt);
        tnode_attach(fs, node);
        p += 4;
        
        // Timeout
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "Timeout: 0x%02x(%d) seconds", p[0], p[0]);
        node->txt = strdup(txt);
        tnode_attach(fs, node);
        p += 1;
        
        // ObjectKeyLength
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "ObjectKeySize: 0x%02x(%d) bytes", p[0], p[0]);
        node->txt = strdup(txt);
        tnode_attach(fs, node);
        
        // ObjectKeyData
        node = tnode_new(NODE_TYPE_DEFAULT);
        len = snprintf(txt, TXT_BUF_SIZE, "ObjectKeyData(hex): ");
        for(i = 0; i < p[0]; i ++)
            len += snprintf(txt + len, TXT_BUF_SIZE - len, "%02x ", p[1 + i]);
        node->txt = strdup(txt);
        tnode_attach(fs, node);
    } else {
        // FormatSpecifier
        node = tnode_new(NODE_TYPE_DEFAULT);
        len = snprintf(txt, TXT_BUF_SIZE, "FormatSpecifier(hex): ");
        for(i = 0; i < desc_len - 5; i ++)
            len += snprintf(txt + len, TXT_BUF_SIZE - len, "%02x ", p[5 + i]);
        node->txt = strdup(txt);
        tnode_attach(root, node);
    }
}

static void s_parse_desc_network_name(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    i, len;

    /* network_name */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "network_name: \"");
    for(i = 0; i < p[1]; i ++)
        len += snprintf(txt + len, TXT_BUF_SIZE - len, "%c", PRINTABLE_CODE(p[2 + i])); /* (p[2 + i] > 0x20 && p[2 + i] < 0x7e)? p[2 + i] : '.'); */
    len += snprintf(txt + len, TXT_BUF_SIZE - len, "\"");
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_bouquet_name(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    i, len;

    /* bouquet_name */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "bouquet_name: \"");
    for(i = 0; i < p[1]; i ++)
        len += snprintf(txt + len, TXT_BUF_SIZE - len, "%c", PRINTABLE_CODE(p[2 + i])); /* (p[2 + i] > 0x20 && p[2 + i] < 0x7e)? p[2 + i] : '.'); */
    len += snprintf(txt + len, TXT_BUF_SIZE - len, "\"");
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_service_list(u8 *p, TNODE* root){
    TNODE  *node, *n2;
    char   txt[TXT_BUF_SIZE + 1];
    int    i, service_nr;

    /* number_of_services */
    node = tnode_new(NODE_TYPE_DEFAULT);
    service_nr = p[1] / 3;
    snprintf(txt, TXT_BUF_SIZE, "number_of_services: %d", service_nr);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    for(i = 0; i < service_nr; i ++){
        n2 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "service_id: 0x%04x(%d), service_type: 0x%02x => %s", 
            p[2 + i * 3] * 256 +  p[2 + i * 3 + 1], p[2 + i * 3] * 256 +  p[2 + i * 3 + 1],
            p[2 + i * 3 + 2], get_service_type_by_code(p[2 + i * 3 + 2]));
        n2->txt = strdup(txt);
        tnode_attach(node, n2);
    }
}

static void s_parse_desc_stuffing(u8 *p, TNODE* root){}

static void s_parse_desc_satellite_delivery_system(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    /* frequency */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "frequency: %3x.%01x%02x%02x ghz", p[2] * 16 + ((p[3] & 0xf0) >> 4), p[3] & 0x0f, p[4], p[5]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /*  orbital_position */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "orbital_position: %3x.%01x degree", p[6] * 16 + ((p[7] & 0xf0) >> 4), p[7] & 0x0f);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* west_east_flag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "west_east_flag: 0x%01x => %s", p[8] >> 7, (p[8] >> 7)? "eastern position" : "western position");
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* polarization */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "polarization: 0x%01x => %s", (p[8] >> 5) & 0x03, get_polariztion_by_code((u8)((p[8] >> 5) & 0x03)));
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* modulation */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "modulation: 0x%02x => %s", p[8] & 0x1f , get_satellite_modulation_scheme_by_code((u8)(p[8] & 0x1f)));
    node->txt = strdup(txt);
    tnode_attach(root, node);
    
    /* symbol_rate */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "symbol_rate: %3x.%01x%02x%01x msymbol/s", p[9] * 16 + ((p[10] & 0xf0) >> 4), p[10] & 0x0f, p[11], (p[12] & 0xf0) >> 4);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* fec_inner */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "fec_inner: 0x%1x => %s", p[12] & 0x0f, get_inner_fec_scheme_by_code((u8)(p[12] & 0x0f)));
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_cable_delivery_system(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    /* frequency */
	/* modified(bruin, 2003.11.20): "%2x%2x." to "%2x%02x." */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "frequency: %2x%02x.%02x%02x mhz", p[2], p[3], p[4], p[5]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* fec_outer */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "fec_outer: 0x%1x => %s", p[7] & 0x0f, get_outer_fec_scheme_by_code((u8)(p[7] & 0x0f)));
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* modulation */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "modulation: 0x%1x => %s", p[8], get_cable_modulation_scheme_by_code(p[8]));
    node->txt = strdup(txt);
    tnode_attach(root, node);
    
    /* symbol_rate */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "symbol_rate: %3x.%01x%02x%01x msymbol/s", p[9] * 256 + ((p[10] & 0xf0) >> 4), p[10] & 0x0f, p[11], (p[12] & 0xf0) >> 4);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* fec_inner */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "fec_inner: 0x%1x => %s", p[12] & 0x0f, get_inner_fec_scheme_by_code((u8)(p[12] & 0x0f)));
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

/* implemented(bruin, 2003.12.19) */
static void s_parse_desc_terrestrial_delivery_system(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];

    /* center_frequency */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "center_frequency: %d hz", (p[2] * 16777216 + p[3] * 65536 + p[4] * 256 + p[5]) * 10);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* bandwidth */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "bandwidth: 0x%1x => %s", p[6] >> 5, get_terrestrial_bandwidth_by_code(p[6] >> 5));
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* constellation */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "constellation: 0x%1x => %s", p[7] >> 6, get_terrestrial_constellation_pattern_by_code(p[7] >> 6));
    node->txt = strdup(txt);
    tnode_attach(root, node);
    
    /* hierarchy_information */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "hierarchy_information: 0x%1x => %s", (p[7] & 0x3f) >> 3, get_terrestrial_hierarchy_information_by_code((p[7] & 0x3f) >> 3));
    node->txt = strdup(txt);
    tnode_attach(root, node);

	/* code_rate-HP_stream */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "code_rate-HP_stream: 0x%1x => %s", (p[7] & 0x07), get_terrestrial_code_rate_by_code(p[7] & 0x07));
    node->txt = strdup(txt);
    tnode_attach(root, node);

	/* code_rate-LP_stream */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "code_rate-LP_stream: 0x%1x => %s", (p[8] >> 5), get_terrestrial_code_rate_by_code(p[8] >> 5));
    node->txt = strdup(txt);
    tnode_attach(root, node);

	/* guard_interval */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "guard_interval: 0x%1x => %s", (p[8] >> 3) & 0x02, get_terrestrial_guard_interval_by_code((p[8] >> 3) & 0x02));
    node->txt = strdup(txt);
    tnode_attach(root, node);

	/* transmission_mode */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "transmission_mode: 0x%1x => %s", (p[8] >> 1) & 0x02, get_terrestrial_transmission_mode_by_code((p[8] >> 1) & 0x02));
    node->txt = strdup(txt);
    tnode_attach(root, node);

	/* other_frequency_flag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "other_frequency_flag: 0x%1x => %s", p[8] & 0x01, (p[8] & 0x01)? "one or more other frequencies in use" : "no other frequency in use");
    node->txt = strdup(txt);
    tnode_attach(root, node);

	/* reserved_future_use */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "reserved_future_use: 0x%02x%02x%02x%02x", p[9], p[10], p[11], p[12]);
    node->txt = strdup(txt);
    tnode_attach(root, node);
}


static void s_parse_desc_service(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    len;

    /* service_type */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "service_type: 0x%02x => %s", p[2], get_service_type_by_code(p[2]));
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* service_provider_name_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "service_provider_name_length: %d", p[3]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* service_provider_name */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "service_provider_name: \"");
    memcpy(txt + len, p + 4, p[3]);
    txt[len + p[3]] = '\"';
    txt[len + p[3] + 1] = '\0';
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* service_name_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "service_name_length: %d", p[4 + p[3]]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* service_name */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "service_name: \"");
    memcpy(txt + len, p + 5 + p[3], p[4 + p[3]]);
    txt[len + p[4 + p[3]]] = '\"';
    txt[len + p[4 + p[3]] + 1] = '\0';
    node->txt = strdup(txt);
    tnode_attach(root, node);
}


static void s_parse_desc_short_event(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    len;

    /* iso_639_language_code */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "iso_639_language_code: 0x%02x%02x%02x => \"%c%c%c\"", 
        p[2], p[3], p[4], 
        PRINTABLE_CODE(p[2]), 
        PRINTABLE_CODE(p[3]), 
        PRINTABLE_CODE(p[4]));
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* event_name_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "event_name_length: 0x%02x(%d)", p[5], p[5]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* event_name */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "event_name: \"");
    memcpy(txt + len, p + 6, p[5]);
    txt[len + p[5]] = '\"';
    txt[len + p[5] + 1] = '\0';
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* text_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "text_length: 0x%02x(%d)", p[6 + p[5]], p[6 + p[5]]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* text */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "text: \"");
    memcpy(txt + len, p + 7 + p[5], p[6 + p[5]]);
    txt[len + p[6 + p[5]]] = '\"';
    txt[len + p[6 + p[5]] + 1] = '\0';
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_extended_event(u8 *p, TNODE* root){
    TNODE  *node, *n2;
    char   txt[TXT_BUF_SIZE + 1];
    int    length_of_items, item_description_length, item_length, len, i, j;

    /* descriptor_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "descriptor_number: 0x%01x", p[2] >> 4);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* last_descriptor_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "last_descriptor_number: 0x%01x", p[2] & 0x0f);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* iso_639_language_code */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "iso_639_language_code: 0x%02x%02x%02x => \"%c%c%c\"", 
        p[3], p[4], p[5], 
        PRINTABLE_CODE(p[3]), 
        PRINTABLE_CODE(p[4]), 
        PRINTABLE_CODE(p[5]));
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* length_of_items */
    node = tnode_new(NODE_TYPE_DEFAULT);
    length_of_items = p[6];
    snprintf(txt, TXT_BUF_SIZE, "length_of_items: 0x%02x(%d)", p[6], p[6]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /*** items_loop(2 columns of text, eg, cast list) ***/
    node = tnode_new(NODE_TYPE_DEFAULT);
    node->txt = strdup("items_loop(index => item_description_char : item_char)");
    tnode_attach(root, node);

    p += 7;
    j = 0; /* loop range guard */

    for(i = 0; j < length_of_items; i ++){

        n2 = tnode_new(NODE_TYPE_DEFAULT);
        
        item_description_length = p[0];
        item_length = p[item_description_length + 1];

        len = snprintf(txt, TXT_BUF_SIZE, "%d : ", i);

        /* item_description_char */
        memcpy(txt + len, p + 1, item_description_length);
        len += item_description_length;
        txt[len] = ' ';
        txt[len + 1] = ':';
        txt[len + 2] = ' ';
        len += 3;

        /* item_char */
        memcpy(txt + len, p + 1 + item_description_length, item_length);
        len += item_length;
        txt[len] = '\0';
        len += 1;

        n2->txt = strdup(txt);
        tnode_attach(node,n2);

        j += item_description_length + item_length + 2;
        p += item_description_length + item_length + 2;
    }

    /*** non-itemized text ***/

    /* text_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "text_length: 0x%02x(%d)", p[0], p[0]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* text_char */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "text_char: \"");
    memcpy(txt + len, p + 1, p[0]);
    len += p[0];
    txt[len] = '"';
    txt[len + 1] = '\0';
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_component(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    len;

    /* stream_content */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "stream_content: 0x%01x", p[2] & 0x0f);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* component_type */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "component_type: 0x%02x", p[3]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* component_tag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "component_tag: 0x%02x", p[4]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* iso_639_language_code */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "iso_639_language_code: 0x%02x%02x%02x => \"%c%c%c\"", 
        p[5], p[6], p[7], 
        PRINTABLE_CODE(p[5]), 
        PRINTABLE_CODE(p[6]), 
        PRINTABLE_CODE(p[7]));
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* text */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "text: \"");
    memcpy(txt + len, p + 8, p[1] - 6);
    txt[len + p[1] - 6] = '\"';
    txt[len + p[1] - 5] = '\0';
    node->txt = strdup(txt);
    tnode_attach(root, node);
}

static void s_parse_desc_local_time_offset(u8 *p, TNODE* root){
    TNODE  *node, *n2, *n3;
    char   txt[TXT_BUF_SIZE + 1];
    int    descriptor_length, country_loop_size = 13, n, len, i, j;

    descriptor_length = p[1];
    n = descriptor_length / country_loop_size;

    /* country_loop */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "country_loop: %d", n);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    p += 2;
    for(i = 0; i < n; i ++){

        p += i * country_loop_size;

        n2 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "index: %d", i);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);


        /* country_code */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "country_code: 0x%02x%02x%02x => \"%c%c%c\"", 
            p[0], p[1], p[2], 
            PRINTABLE_CODE(p[0]), 
            PRINTABLE_CODE(p[1]), 
            PRINTABLE_CODE(p[2]));
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* country_region_id */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "country_region_id: %d", p[3] >> 2);
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* local_time_offset_polarity */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "local_time_offset_polarity: %d", p[3] & 0x01);
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* local_time_offset */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "local_time_offset: %02x:%02x(hh:mm)", p[4], p[5]);
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* time_of_change */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        len = snprintf(txt, TXT_BUF_SIZE, "time_of_change: 0x");
        for(j = 0; j < 5; j ++)
            len += snprintf(txt + len, TXT_BUF_SIZE - len, "%02x", p[6 + j]);
        snprintf(txt + len, TXT_BUF_SIZE - len, " => %s", get_string_by_utc_time(p + 6));
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* next_time_offset */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "next_time_offset: %02x:%02x(hh:mm)", p[11], p[12]);
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);
    }
}

static void s_parse_desc_data_broadcast(u8 *p, TNODE* root){

    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    len, i;

    /* data_broadcast_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "data_broadcast_id: 0x%02x%02x", p[2], p[3]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* component_tag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "component_tag: 0x%02x", p[4]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* selector_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "selector_length: 0x%02x", p[5]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* selector_byte */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "selector_byte(hex): ");
    for(i = 0; i < p[5]; i ++)
        len += snprintf(txt + len, TXT_BUF_SIZE -len, "%02x ", p[6 + i]);
    txt[len] = '\0';
    node->txt = strdup(txt);
    tnode_attach(root, node);

    p += 6 + p[5];

    /* iso_639_language_code */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "iso_639_language_code: 0x%02x%02x%02x => \"%c%c%c\"", 
        p[0], p[1], p[2], 
        PRINTABLE_CODE(p[0]), 
        PRINTABLE_CODE(p[1]), 
        PRINTABLE_CODE(p[2]));
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* text_length */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "text_length: 0x%02x", p[3]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* text_char */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "text_char: \"");
    memcpy(txt + len, p + 3, p[3]);
    len += p[3];
    txt[len] = '"';
    txt[len + 1] = '\0';
    node->txt = strdup(txt);
    tnode_attach(root, node);
}


static void s_parse_desc_data_broadcast_id(u8 *p, TNODE* root){
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    len, i;

    /* data_broadcast_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "data_broadcast_id: 0x%02x%02x", p[2], p[3]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* id_selector_byte */
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "id_selector_byte(hex): ");
    for(i = 0; i < p[1] - 2; i ++)
        len += snprintf(txt + len, TXT_BUF_SIZE -len, "%02x ", p[4 + i]);
    txt[len] = '\0';
    node->txt = strdup(txt);
    tnode_attach(root, node);
}


/* added(bruin, 2003.01.13): this descriptor is in PMT */
static void s_parse_desc_application_signalling(u8 *p, TNODE* root){

    TNODE  *node, *n2, *n3;
    char   txt[TXT_BUF_SIZE + 1];
    int    n, i, loop_size = 3;

    n = p[1] / loop_size;      /* number of loops */
    
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "loop_number: %d", n);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    p += 2;
    for(i = 0; i < n; i ++){
        p += i * loop_size;

        n2 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "index: %d", i);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);

        /* application_type */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "application_type: 0x%02x%02x => %s", p[0], p[1], get_application_type_by_code((u16)(p[0] * 256 + p[1])));
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* ait_version_number */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "ait_version_number: 0x%02x", p[2] & 0x1f);
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);
    }
}


/* added(bruin, 2003.02.17) */
static void s_parse_desc_rcs_content(u8* p, TNODE* root){
    TNODE  *node, *n2;
    char   txt[TXT_BUF_SIZE + 1];
    int    n, i;

    /* number of tables */
    n = p[1]; 

    if(n > 0){
        /* number_of_table_id */
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "number_of_table_id: %d", n);
        node->txt = strdup(txt);
        tnode_attach(root, node);

        for(i = 0; i < n; i ++){
            n2 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "table_id: 0x%02x => %s", p[2 + i], get_rcs_tid_name_by_id(p[2 + i]));
            n2->txt = strdup(txt);
            tnode_attach(node, n2);
        }
    }
}


static void s_parse_desc_linkage(u8 *p, TNODE* root){
    
    TNODE  *node;
    char   txt[TXT_BUF_SIZE + 1];
    int    descriptor_length, len, i;
    int    head_len = 9; 
    
    descriptor_length = p[1]; /* not including 2 byte descriptor_tag and descriptor_length */

    /* transport_stream_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "transport_stream_id: 0x%02x%02x", p[2], p[3]);
    node->txt = strdup(txt);
    tnode_attach(root, node);
    
    /* original_network_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "original_network_id: 0x%02x%02x", p[4], p[5]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* service_id */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "service_id: 0x%02x%02x", p[6], p[7]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* linkage_type */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "linkage_type: 0x%02x => %s", p[8], get_linkage_type_by_code(p[8]));
    node->txt = strdup(txt);
    tnode_attach(root, node);

        
    if(p[8] != 0x08){
        p += head_len;
        
        /* private_data_byte */
        node = tnode_new(NODE_TYPE_DEFAULT);
        len = snprintf(txt, TXT_BUF_SIZE, "private_data_byte(hex):");
        for(i = 0; i < descriptor_length - (head_len - 2); i ++)
            len += snprintf(txt + len, TXT_BUF_SIZE - len, " %02x", p[i]);
        node->txt = strdup(txt);
        tnode_attach(root, node);
    }
    else{ /* type: mobile_hand_over */
        
        u8 hand_over_type, origin_type, private_data_len;
        
        p += head_len;
        private_data_len = descriptor_length - (head_len - 2);
        
        /* hand_over_type */
        hand_over_type = p[0] >> 4;
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "hand_over_type: 0x%01x => %s", hand_over_type, get_hand_over_type_by_code(hand_over_type));
        node->txt = strdup(txt);
        tnode_attach(root, node);

        /* origin_type */
        origin_type = p[0] & 0x01;
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "origin_type: 0x%01x => %s", origin_type, origin_type? "sdt" : "nit");
        node->txt = strdup(txt);
        tnode_attach(root, node);

        p += 1;
        private_data_len -= 1;
        
        if(hand_over_type == 0x01 ||
           hand_over_type == 0x02 || 
           hand_over_type == 0x03){
           
            /* network_id */
            node = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "network_id: 0x%02x%02x", p[0], p[1]);
            node->txt = strdup(txt);
            tnode_attach(root, node);
            p += 2;
            private_data_len -= 2;
        }

        if(origin_type == 0x00){
            /* initial_service_id */
            node = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "initial_service_id: 0x%02x%02x", p[0], p[1]);
            node->txt = strdup(txt);
            tnode_attach(root, node);
            p += 2;
            private_data_len -= 2;
        }
            
        /* private_data_byte */
        node = tnode_new(NODE_TYPE_DEFAULT);
        len = snprintf(txt, TXT_BUF_SIZE, "private_data_byte(hex):");
        for(i = 0; i < private_data_len; i ++)
            len += snprintf(txt + len, TXT_BUF_SIZE - len, " %02x", p[i]);
        node->txt = strdup(txt);
        tnode_attach(root, node);
    }
}

static void s_parse_desc_multilingual_service_name(u8 *p, TNODE* root){
    
    TNODE  *node, *n2;
    char   txt[TXT_BUF_SIZE + 1];
    int    descriptor_length, len, service_provider_name_length, service_name_length, k;

    descriptor_length = p[1]; /* not including 2 byte descriptor_tag and descriptor_length */
    
    p += 2;
    k = 0;
    for(; k < descriptor_length; ){
        
        /* iso_639_language_code */
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "iso_639_language_code: 0x%02x%02x%02x => \"%c%c%c\"", 
            p[0], p[1], p[2], 
            PRINTABLE_CODE(p[0]),
            PRINTABLE_CODE(p[1]),
            PRINTABLE_CODE(p[2]));
        node->txt = strdup(txt);
        tnode_attach(root, node);
        p += 3;
        k += 3;
        
        /* service_provider_name_length */
        service_provider_name_length = p[0];
        n2 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "service_provider_name_length: %d", service_provider_name_length);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);
        p += 1;
        k += 1;
        
        /* service_provide_name */
        if(service_provider_name_length > 0){
            n2 = tnode_new(NODE_TYPE_DEFAULT);
            len = snprintf(txt, TXT_BUF_SIZE, "service_provider_name: \"");
            memcpy(txt + len, p, service_provider_name_length);
            txt[len + service_provider_name_length] = '\"';
            txt[len + service_provider_name_length + 1] = '\0';       
            n2->txt = strdup(txt);
            tnode_attach(node, n2);
            
            p += service_provider_name_length;
            k += service_provider_name_length;
        }
        
        /* service_name_length */
        service_name_length = p[0];
        n2 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "service_name_length: %d", service_name_length);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);
        p += 1;
        k += 1;
        
        /* service_name */
        if(service_name_length > 0){
            n2 = tnode_new(NODE_TYPE_DEFAULT);
            len = snprintf(txt, TXT_BUF_SIZE, "service_name: \"");
            memcpy(txt + len, p, service_name_length);
            txt[len + service_name_length] = '\"';
            txt[len + service_name_length + 1] = '\0';       
            n2->txt = strdup(txt);
            tnode_attach(node, n2);
            
            p += service_name_length;
            k += service_name_length;
        }
    }
    
}


static void s_parse_desc_content(u8 *p, TNODE* root){
    TNODE  *node, *n2, *n3;
    char   txt[TXT_BUF_SIZE + 1];
    int    descriptor_length, nr, i;

    descriptor_length = p[1];
    nr = descriptor_length / 2; /* nr content descriptors in the loop */

    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "number_of_nibbles: %d", nr);
    node->txt = strdup(txt);
    tnode_attach(root, node);
    
    p += 2;
    
    for(i = 0; i < nr; i ++){
        n2 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "index: %d", i);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);

        /* content_nibble_level_1 */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "content_nibble_level_1: 0x%01x => %s", 
            (p[0] >> 4),
            get_content_nibble_name_by_code(p[0], 1));
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* content_nibble_level_2 */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "content_nibble_level_2: 0x%01x => %s", 
            (p[0] & 0x0f),
            get_content_nibble_name_by_code(p[0], 0));
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* user_nibble */        
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "user_nibble: 0x%01x", (p[1] >> 4));
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);        

        /* user_nibble */        
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "user_nibble: 0x%01x", (p[1] & 0x0f));
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        p += 2;
    }
}

static void s_parse_desc_parental_rating(u8 *p, TNODE* root){
    TNODE  *node, *n2, *n3;
    char   txt[TXT_BUF_SIZE + 1];
    int    descriptor_length, nr, i;

    descriptor_length = p[1];
    nr = descriptor_length / 4; /* nr countries in the loop */

    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "number_of_countries: %d", nr);
    node->txt = strdup(txt);
    tnode_attach(root, node);
    
    p += 2;
    
    for(i = 0; i < nr; i ++){
        n2 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "index: %d", i);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);

        /* country_code */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "country_code: 0x%02x%02x%02x => \"%c%c%c\"", 
            p[0], p[1], p[2], 
            PRINTABLE_CODE(p[0]), 
            PRINTABLE_CODE(p[1]), 
            PRINTABLE_CODE(p[2]));
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);
        
        /* rating */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "rating: 0x%02x => %s", p[3], get_minimum_age_by_rating(p[3]));
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        p += 4;
    }
}



static void s_parse_desc_vbi_data(u8 *p, TNODE* root){}
static void s_parse_desc_vbi_teletext(u8 *p, TNODE* root){}
static void s_parse_desc_country_availability(u8 *p, TNODE* root){}
static void s_parse_desc_nvod_reference(u8 *p, TNODE* root){}
static void s_parse_desc_time_shifted_service(u8 *p, TNODE* root){}
static void s_parse_desc_time_shifted_event(u8 *p, TNODE* root){}
static void s_parse_desc_mosaic(u8 *p, TNODE* root){}
static void s_parse_desc_stream_identifier(u8 *p, TNODE* root){}
static void s_parse_desc_ca_identifier(u8 *p, TNODE* root){}
static void s_parse_desc_teletext(u8 *p, TNODE* root){}
static void s_parse_desc_telephone(u8 *p, TNODE* root){}
static void s_parse_desc_subtitling(u8 *p, TNODE* root){}
static void s_parse_desc_multilingual_network_name(u8 *p, TNODE* root){}
static void s_parse_desc_multilingual_bouquet_name(u8 *p, TNODE* root){}
static void s_parse_desc_multilingual_component(u8 *p, TNODE* root){}
static void s_parse_desc_private_data_specifier(u8 *p, TNODE* root){}
static void s_parse_desc_service_move(u8 *p, TNODE* root){}
static void s_parse_desc_short_smoothing_buffer(u8 *p, TNODE* root){}
static void s_parse_desc_frequency_list(u8 *p, TNODE* root){}
static void s_parse_desc_partial_transport_stream(u8 *p, TNODE* root){}
static void s_parse_desc_ca_system(u8 *p, TNODE* root){}
static void s_parse_desc_transport_stream(u8 *p, TNODE* root){}
static void s_parse_desc_dsng(u8 *p, TNODE* root){}
static void s_parse_desc_pdc(u8 *p, TNODE* root){}
static void s_parse_desc_ac3(u8 *p, TNODE* root){}
static void s_parse_desc_ancillary_data(u8 *p, TNODE* root){}
static void s_parse_desc_cell_list(u8 *p, TNODE* root){}
static void s_parse_desc_cell_frequency_link(u8 *p, TNODE* root){}
static void s_parse_desc_announcement_support(u8 *p, TNODE* root){}
static void s_parse_desc_service_identifier(u8* p, TNODE* root){}






static int s_parse_mhp_descriptors_loop(u8* p, int loop_len, TNODE* root){
    
    TNODE          *node, *n2;
    char           txt[TXT_BUF_SIZE + 1];
    int            len, i, j, k;

    k = 0;
    for(i = 0; k < loop_len; i ++){

        /* for each descriptor, p[0] and p[1] mean the same, i.e., 
             p[0] is "descriptor_tag", 
             p[1] is "descriptor_length". 
           we parse this two coommon fileds here. 
           
           the whole descriptor data fields are also hex dumped here, 
           which may of value especially for customer descriptors.
         */

        /* descriptor_tag */
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "descriptor_tag: 0x%02x => %s", p[0], get_mhp_desc_name_by_id(p[0]));
        node->txt = strdup(txt);
        tnode_attach(root, node);

        /* descriptor_length */        
        n2 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "descriptor_length(byte): %d", p[1]);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);

        n2 = tnode_new(NODE_TYPE_DEFAULT);
        len = snprintf(txt, TXT_BUF_SIZE, "descriptor_data(hex): ");
        for(j = 0; j < p[1]; j ++)
            len += snprintf(txt + len, TXT_BUF_SIZE - len, "%02x ", p[2 + j]);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);

        /* parse the descriptor value */
        switch(p[0]){

            case MHP_DESC_APPLICATION:
                s_parse_mhp_desc_application(p, n2);
                break;
            case MHP_DESC_APPLICATION_NAME:
                s_parse_mhp_desc_application_name(p, n2);   
                break;
            case MHP_DESC_TRANSPORT_PROTOCOL:
                s_parse_mhp_desc_transport_protocol(p, n2);
                break;
            case MHP_DESC_DVB_J_APPLICATION:
                s_parse_mhp_desc_dvb_j_application(p, n2);
                break;
            case MHP_DESC_DVB_J_APPLICATION_LOCATION:
                s_parse_mhp_desc_dvb_j_application_location(p, n2);
                break;
            case MHP_DESC_EXTERNAL_APPLICATION_AUTHORIZATION:
                s_parse_mhp_desc_external_application_authorization(p, n2);
                break;
            case MHP_DESC_IPV4_ROUTING:
                s_parse_mhp_desc_ipv4_routing(p, n2);
                break;
            case MHP_DESC_IPV6_ROUTING:
                s_parse_mhp_desc_ipv6_routing(p, n2);
                break;
            case MHP_DESC_DVB_HTML_APPLICATION:
                s_parse_mhp_desc_dvb_html_application(p, n2);
                break;
            case MHP_DESC_DVB_HTML_APPLICATION_LOCATION:
                s_parse_mhp_desc_dvb_html_application_location(p, n2);
                break;
            case MHP_DESC_DVB_HTML_APPLICATION_BOUNDARY:
                s_parse_mhp_desc_dvb_html_application_boundary(p, n2);
                break;
            case MHP_DESC_APPLICATION_ICONS:
                s_parse_mhp_desc_application_icons(p, n2);
                break;
            case MHP_DESC_PREFETCH:
                s_parse_mhp_desc_prefetch(p, n2);
                break;
            case MHP_DESC_DLL_LOCATION:
                s_parse_mhp_desc_dll_location(p, n2);
                break;
            case MHP_DESC_DELEGATED_APPLICATION:
                  s_parse_mhp_desc_delegated_application(p, n2);
              break;
            case MHP_DESC_PLUG_IN:
                s_parse_mhp_desc_plug_in(p, n2);
                break;
            case MHP_DESC_PRIVATE_DATA_SPECIFIER:
                s_parse_mhp_desc_private_data_specifier(p, n2);
              break;
            default:
                break;
        }

        k += p[1] + 2;
        p += p[1] + 2;
    }

    return i;
}

static void s_parse_mhp_desc_application(u8* p, TNODE* root){
    TNODE  *node, *n2, *n3;
    char   txt[TXT_BUF_SIZE + 1];
    int    descriptor_length, application_profiles_length, profile_nr, transport_protocol_nr, i;

    descriptor_length = p[1];
    
    /* application_profiles_length */
    application_profiles_length = p[2];
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "application_profiles_length: %d", application_profiles_length);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    p += 3;
    
    /* profile_loop */
    profile_nr = application_profiles_length / 5;
    if(profile_nr > 0){
        node = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "application_profiles: %d total", profile_nr);
        node->txt = strdup(txt);
        tnode_attach(root, node);

        for(i = 0; i < profile_nr; i ++){
            n2 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "index: %d", i);
            n2->txt = strdup(txt);
            tnode_attach(node, n2);

            /* application_profile */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "application_profile: 0x%02x%02x", p[0], p[1]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            /* version.major */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "version.major: 0x%02x", p[2]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            /* version.minor */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "version.minor: 0x%02x", p[3]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);

            /* version.micro */
            n3 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "version.micro: 0x%02x", p[4]);
            n3->txt = strdup(txt);
            tnode_attach(n2, n3);
            
            p += 5;
        }
    }

    /* service_bound_flag */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "service_bound_flag: 0x%01x", p[0] >> 7);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* visibility */    
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "visibility: 0x%01x", (p[0] & 0x60)>> 5);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    p += 1;
    /* application_priority */    
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "application_priority: 0x%02x", p[0]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    transport_protocol_nr = descriptor_length - 1 - application_profiles_length - 2;

    p += 1;
    
    /* transport_protocol_number */
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "transport_protocols: %d total", transport_protocol_nr);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    if(transport_protocol_nr > 0){
        for(i = 0; i < transport_protocol_nr; i ++){
            n2 = tnode_new(NODE_TYPE_DEFAULT);
            snprintf(txt, TXT_BUF_SIZE, "transport_protocol_label: 0x%02x", p[0]);
            n2->txt = strdup(txt);
            tnode_attach(node, n2);
            p += 1;
        }
    }
}

static void s_parse_mhp_desc_application_name(u8* p, TNODE* root){
    TNODE  *node, *n2, *n3;
    char   txt[TXT_BUF_SIZE + 1];
    int    descriptor_length, len, application_name_length, i, k;

    descriptor_length = p[1];

    node = tnode_new(NODE_TYPE_DEFAULT);
    node->txt = strdup("languages");
    tnode_attach(root, node);
    p += 2;

    k = 0; /* range guard */
    for(i = 0; k < descriptor_length; i ++){
        n2 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "index: %d", i);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);

        /* iso_639_language_code */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "iso_639_language_code: 0x%02x%02x%02x => \"%c%c%c\"", 
            p[0], p[1], p[2],
            PRINTABLE_CODE(p[0]),
            PRINTABLE_CODE(p[1]),
            PRINTABLE_CODE(p[2]));
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* application_name_length */
        application_name_length = p[3];
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "application_name_length: %d", application_name_length);
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* application_name */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        len = snprintf(txt, TXT_BUF_SIZE, "application_name: \"");
        memcpy(txt + len, p + 4, application_name_length);
        txt[len + application_name_length] = '\"';
        txt[len + application_name_length + 1] = '\0';
        n3 -> txt = strdup(txt);
        tnode_attach(n2, n3);

        p += 4 + application_name_length;
        k += 4 + application_name_length;
    }
}   

static void s_parse_mhp_desc_transport_protocol(u8* p, TNODE* root){
    TNODE  *node, *n2, *n3, *n4;
    char   txt[TXT_BUF_SIZE + 1];
    u16    protocol_id;
    int    descriptor_length, selector_bytes, len, i, j, k;

    descriptor_length = p[1];

    /* protocol_id */
    protocol_id = (u16)(p[2] * 256 + p[3]);
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "protocol_id: 0x%02x%02x => %s", p[2], p[3], get_transport_protocol_id_name_by_id(protocol_id));
    node->txt = strdup(txt);
    tnode_attach(root, node);

    /* transport_protocol_label */    
    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "transport_protocol_label: 0x%02x", p[4]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    p += 5;
    /* selector_bytes */
    selector_bytes = descriptor_length - 3;
    node = tnode_new(NODE_TYPE_DEFAULT);
    len = snprintf(txt, TXT_BUF_SIZE, "selector_bytes(hex):");
    for(i = 0; i < selector_bytes; i ++)
        len += snprintf(txt + len, TXT_BUF_SIZE - len, " %02x", p[i]);
    node->txt = strdup(txt);
    tnode_attach(root, node);

    switch(protocol_id){
        case 0x0001: /* transport via oc */
            {
                u8 remote_connection = p[0] >> 7;
                
                /* remote_connection */
                n2 = tnode_new(NODE_TYPE_DEFAULT);
                snprintf(txt, TXT_BUF_SIZE, "remote_connection: 0x%01x", remote_connection);
                n2->txt = strdup(txt);
                tnode_attach(node, n2);

                p += 1;

                if(remote_connection){
                    /* original_network_id */
                    n2 = tnode_new(NODE_TYPE_DEFAULT);
                    snprintf(txt, TXT_BUF_SIZE, "original_network_id: 0x%02x%02x", p[0], p[1]);
                    n2->txt = strdup(txt);
                    tnode_attach(node, n2);

                    /* transport_stream_id */
                    n2 = tnode_new(NODE_TYPE_DEFAULT);
                    snprintf(txt, TXT_BUF_SIZE, "transport_stream_id: 0x%02x%02x", p[2], p[3]);
                    n2->txt = strdup(txt);
                    tnode_attach(node, n2);

                    /* service_id */
                    n2 = tnode_new(NODE_TYPE_DEFAULT);
                    snprintf(txt, TXT_BUF_SIZE, "service_id: 0x%02x%02x", p[4], p[5]);
                    n2->txt = strdup(txt);
                    tnode_attach(node, n2);

                    p += 6;
                }

                /* component_tag */
                n2 = tnode_new(NODE_TYPE_DEFAULT);
                snprintf(txt, TXT_BUF_SIZE, "component_tag: 0x%02x", p[0]);
                n2->txt = strdup(txt);
                tnode_attach(node, n2);
                
            }
            break;
        case 0x0002: /* transport via ip */
            {
                u8 urls_len, url_len;
                u8 remote_connection = p[0] >> 7;
                
                
                /* remote_connection */
                n2 = tnode_new(NODE_TYPE_DEFAULT);
                snprintf(txt, TXT_BUF_SIZE, "remote_connection: 0x%01x", remote_connection);
                n2->txt = strdup(txt);
                tnode_attach(node, n2);

                p += 1;

                if(remote_connection){
                    /* original_network_id */
                    n2 = tnode_new(NODE_TYPE_DEFAULT);
                    snprintf(txt, TXT_BUF_SIZE, "original_network_id: 0x%02x%02x", p[0], p[1]);
                    n2->txt = strdup(txt);
                    tnode_attach(node, n2);

                    /* transport_stream_id */
                    n2 = tnode_new(NODE_TYPE_DEFAULT);
                    snprintf(txt, TXT_BUF_SIZE, "transport_stream_id: 0x%02x%02x", p[2], p[3]);
                    n2->txt = strdup(txt);
                    tnode_attach(node, n2);

                    /* service_id */
                    n2 = tnode_new(NODE_TYPE_DEFAULT);
                    snprintf(txt, TXT_BUF_SIZE, "service_id: 0x%02x%02x", p[4], p[5]);
                    n2->txt = strdup(txt);
                    tnode_attach(node, n2);

                    p += 6;
                }

                /* alignment_indicator */
                n2 = tnode_new(NODE_TYPE_DEFAULT);
                snprintf(txt, TXT_BUF_SIZE, "alignment_indicator: 0x%01x", p[0] >> 7);
                n2->txt = strdup(txt);
                tnode_attach(node, n2);

                p += 1;

                urls_len = descriptor_length - 3 - 1 - (remote_connection? 6 : 0) - 1; 
                if(urls_len > 0){
                    n2 = tnode_new(NODE_TYPE_DEFAULT);
                    n2->txt = strdup("urls");
                    tnode_attach(node, n2);
                
                    k = 0; /* range guard */
                    for(i = 0; k < urls_len; i ++){
                        n3 = tnode_new(NODE_TYPE_DEFAULT);
                        snprintf(txt, TXT_BUF_SIZE, "index: %d", i);
                        n3->txt = strdup(txt);
                        tnode_attach(n2, n3);

                        /* url_length */
                        url_len = p[0];
                        n4 = tnode_new(NODE_TYPE_DEFAULT);
                        snprintf(txt, TXT_BUF_SIZE, "url_length: %d", url_len);
                        n4->txt = strdup(txt);
                        tnode_attach(n3, n4);

                        /* url_byte */
                        n4 = tnode_new(NODE_TYPE_DEFAULT);
                        len = snprintf(txt, TXT_BUF_SIZE, "url_byte(hex):");
                        for(j = 0; j < url_len; j ++)
                            len += snprintf(txt + len, TXT_BUF_SIZE -len, " %02x", p[j + 1]);
                        len += snprintf(txt + len, TXT_BUF_SIZE - len, " => \"");
                        memcpy(txt + len, p + 1, url_len);
                        txt[len + url_len] = '\"';
                        txt[len + url_len + 1] = '\0';
                        n4->txt = strdup(txt);
                        tnode_attach(n3, n4);

                        p += 1 + url_len;
                        k += 1 + url_len;
                    }
                }
            }
            break;
        case 0x0003: /* transport via interaction channel */
            {
                /* to be done... */
            }
            break;
        default:
            break;
    }
}

/* added(bruin, 2003.12.18) */
static void s_parse_desc_logical_channel(u8* p, TNODE* root){
    TNODE  *node, *n2, *n3;
    char   txt[TXT_BUF_SIZE + 1];
    int    descriptor_length, nr, i;

    descriptor_length = p[1];
    nr = descriptor_length / 4; /* nr of logical channel in the loop */

    node = tnode_new(NODE_TYPE_DEFAULT);
    snprintf(txt, TXT_BUF_SIZE, "number_of_services: %d", nr);
    node->txt = strdup(txt);
    tnode_attach(root, node);
    
    p += 2;
    
    for(i = 0; i < nr; i ++){
        n2 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "index: %d", i);
        n2->txt = strdup(txt);
        tnode_attach(node, n2);

        /* service_id */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "service_id: 0x%04x(%d)", p[0] * 256 + p[1], p[0] * 256 + p[1]);
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* visible_service_flag */
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "visible_service_flag: 0x%01x => %s",  
			(p[2] >> 7), (p[2] >> 7)? "visible" : "invisible");
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);

        /* logical_channel_number */        
        n3 = tnode_new(NODE_TYPE_DEFAULT);
        snprintf(txt, TXT_BUF_SIZE, "logical_channel_number: %d", (p[2] & 0x03) * 256 + p[3]);
        n3->txt = strdup(txt);
        tnode_attach(n2, n3);  

        p += 4;
    }
}

static void s_parse_mhp_desc_dvb_j_application(u8* p, TNODE* root){}
static void s_parse_mhp_desc_dvb_j_application_location(u8* p, TNODE* root){}
static void s_parse_mhp_desc_external_application_authorization(u8* p, TNODE* root){}
static void s_parse_mhp_desc_ipv4_routing(u8* p, TNODE* root){}
static void s_parse_mhp_desc_ipv6_routing(u8* p, TNODE* root){}
static void s_parse_mhp_desc_dvb_html_application(u8* p, TNODE* root){}
static void s_parse_mhp_desc_dvb_html_application_location(u8* p, TNODE* root){}
static void s_parse_mhp_desc_dvb_html_application_boundary(u8* p, TNODE* root){}
static void s_parse_mhp_desc_application_icons(u8* p, TNODE* root){}
static void s_parse_mhp_desc_prefetch(u8* p, TNODE* root){}
static void s_parse_mhp_desc_dll_location(u8* p, TNODE* root){}
static void s_parse_mhp_desc_delegated_application(u8* p, TNODE* root){}
static void s_parse_mhp_desc_plug_in(u8* p, TNODE* root){}
static void s_parse_mhp_desc_private_data_specifier(u8* p, TNODE* root){}

