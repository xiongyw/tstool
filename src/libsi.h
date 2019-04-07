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


#ifndef __LIBSI_H__
#define __LIBSI_H__

#include "si.h"
#include "tree.h"


/* opentv header struct */

typedef struct{
    char  otv_magic[8]; /* "OTV :-) " */
    u8    data_size[4]; /* network byte order */
    u8    *data;        /* data size should be data_size */
}OTV_HEADER;                



#define PID_NODE_ALLOC_INCREMENTAL_STEP         32
#define SECTION_ALLOC_INCREMENTAL_STEP          32

/* struct to hold packets of same pid */
typedef struct _PID_NODE{

    /* elementary data */

    u16     pid;
    u32     packet_nr;
    u32     size;       /* index[] array size; increase by PID_NODE_ALLOC_INCREMENTAL_STEP */
    u32     *index;     /* array of index of each packet of the pid */
    u8      stream_type;

    /* link */

    struct _PID_NODE *pre;
    struct _PID_NODE *next;
}PID_NODE;


typedef struct{
    int               pid_nr;
    PID_NODE          *head;
}PID_LIST;



/*
 * The structure of subtables:
 *
 * Each DVB-SI table is identified by a unique table ID. 
 * 
 * Tables are made up of subtables. A subtable typically describes one object in a table. For
 * example, a Network Information SubTable (NIST) describes a particular network and a
 * Bouquet Association SubTable (BAST) describes a single bouquet.
 * 
 * Each subtable has the same table ID as its table. Depending on the table ID, up to three
 * more IDs uniquely identify the subtable. For example, all BASTs have a table ID of 0x4A,
 * and each individual BAST is identified by its own unique bouquet ID. The NIT needs
 * only a table ID of 0x40 to differentiate it from all other incoming tables (no further IDs
 * are needed), while an EIST requires four: a table ID, an original network ID, a transport
 * stream ID, and a service ID.
 * 
 * The information in the subtable may be augmented by descriptors. 
 */

typedef struct{
    u8   *data;      /* the whole section data, starting from "table_id" */
    int  size;       /* size of data, should equal to "section_length + 3" */
	int  repeat;     /* repeat count of the same section in the stream */
}SECTION;

typedef struct{
    /*
     * table id: for EIT-S, use the first tid to represent the whole range:
     *  - TID_EIT_ACT_SCH (0x50) represent 0x50 - 0x5f (TID_EIT_ACT_SCH_LAST)
     *  - TID_EIT_OTH_SCH (0x60) represent 0x50 - 0x6f (TID_EIT_OTH_SCH_LAST)
     */
    u8        tid;  
    
    /* 
     * sections: dynamically allocated
     */
	int       array_size; // allocated size
    int       section_nr;
    SECTION*  sections;
}TABLE;



#define MAX_PMT_NR    64
typedef struct{
    u16    pmt_nr;
    u16    pmt_pid[MAX_PMT_NR];
    u16    prog_nr[MAX_PMT_NR];
}PMT_LIST;

/* added(bruin, 2003.01.13) */
#define MAX_AIT_NR   64
typedef struct{
    u16   ait_nr;
    u16   ait_pid[MAX_AIT_NR];
    u16   prog_nr[MAX_AIT_NR];
}AIT_LIST;

/* added(bruin, 2003.02.17): dvb-rcs */
typedef struct{
    u16   rmt_pid, sct_pid, fct_pid, tct_pid, spt_pid, cmt_pid, tbtp_pid, pcr_pid, tim_pid;
    TABLE *tbl_rmt, *tbl_sct, *tbl_fct, *tbl_tct, *tbl_spt, *tbl_cmt, *tbl_tbtp, *tbl_pcr, *tbl_tim;
}RCS_TABLES;

/* added(bruin, 2003.01.18): decouple analysis part from UI part, which is
     platform dependent. */
typedef struct{

    /*** basic data about the ts */
	char*          file_path;
    u8*            file_data;      /* point to the beginning of the file */
    u32            file_size;      /* file size to processed */
    u8*            ts_data;        /* point to the beginning of the TS */
    u32            ts_size;    
    u8             is_otv_header;  /* is there otv header */
    OTV_HEADER     otv_header;     /* the otv header */
    u8             packet_size;    /* 188 or 204 */
    u32            packet_nr;      /* total packet nr */

    /*** analysis result */

    /* pid list sorted in increasing order */
    PID_LIST*      pid_list;
    
    /* tables */
    TABLE*         tbl_pat;
    TABLE*         tbl_cat;
    TABLE*         tbl_nit_act;
    TABLE*         tbl_nit_oth;
    TABLE*         tbl_sdt_act;
    TABLE*         tbl_sdt_oth;
    TABLE*         tbl_bat;
    TABLE*         tbl_eit_act;
    TABLE*         tbl_eit_oth;
    TABLE*         tbl_eit_act_sch;
    TABLE*         tbl_eit_oth_sch;
    TABLE*         tbl_tdt;
    TABLE*         tbl_tot;
    TABLE*         tbl_rst;
    TABLE*         tbl_st;

    /* pmt/ait are different: they are arrays of tables */
    PMT_LIST       pmt_list;
    AIT_LIST       ait_list;   
    
    TABLE**        tbl_pmts;
    TABLE**        tbl_aits; 

    /* added(bruin, 2003.02.17) */
    RCS_TABLES     rcs;     /* set to zero by calloc() in "build_tsr_result()" */

    /* a tree ready to be mapped to UI system */
    TNODE*         root;
}TSR_RESULT;




#ifdef __cplusplus
extern "C"{
#endif

PID_LIST* build_pid_list(u8* ts, u32 packet_nr, u8 packet_size);
int delete_pid_list(PID_LIST* pid_list);

TABLE* build_table_with_sections(u16 pid, u8 tid, PID_LIST* pid_list, u8* p_ts, u8 packet_size);
int delete_table(TABLE* tbl);

int set_pmt_list_by_pat_sect(SECTION* pat_sect, PMT_LIST* pmt_list);
int set_ait_list_by_pmts(TABLE** tbl_pmts, int pmt_nr, AIT_LIST* ait_list); /* added(bruin, 2003.01.13) */
int set_rcs_tables_by_pmts(TABLE** tbl_pmts, int pmt_nr, RCS_TABLES* rcs_tbls); /* added(bruin, 2003.02.17) */
    
TSR_RESULT* build_tsr_result(const char* file_path, u8* file_data, u32 file_size, int is_verbose);
int delete_tsr_result(TSR_RESULT* result);

u16 get_packet_offset_and_size(u8 *data, int data_size);
PACKET_HEADER* get_packet_by_index(u8* p_ts, int index, int packet_size);
u32 check_otv_header(u8 *p_file, OTV_HEADER* p_otv_header);

void summarize_result(FILE* fp, TSR_RESULT* result);



#ifdef __cplusplus
}
#endif



#endif /* __LIB_SI__ */

