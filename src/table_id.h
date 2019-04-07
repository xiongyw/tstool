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

/* 
 * created(bruin, 2015/05/19): table id allocation
 */

#ifndef __TABLE_ID_H__
#define __TABLE_ID_H__

#define TID_PAT                                 0x00
#define TID_CAT                                 0x01
#define TID_PMT                                 0x02
                                                /* 0x03: transport_stream_description_section */
                                                /* 0x04 to 0x3f: reserved */
/* 
 * added (bruin, 2015-05-19): ISO/IEC 13818-6:1998(E), Table 9-3 DSM-CC table_id assignments
 */
#define TID_DSM_CC_MPED   0x3A // DSM-CC Sections containing multi-protocol encapsulated data
#define TID_DSM_CC_UNM    0x3B // DSM-CC Sections containing U-N Messages, except Download Data Messages
#define TID_DSM_CC_DDM    0x3C // DSM-CC Sections containing Download Data Messages
#define TID_DSM_CC_SD     0x3D // DSM-CC Sections containing Stream Descriptors
#define TID_DSM_CC_PRIV   0x3E // DSM-CC Sections containing private data


#define TID_NIT_ACT                             0x40
#define TID_NIT_OTH                             0x41
#define TID_SDT_ACT                             0x42
                                                /* 0x43 to 0x45: reserved */
#define TID_SDT_OTH                             0x46
                                                /* 0x47 to 0x49: reserved */
#define TID_BAT                                 0x4a
                                                /* 0x4b to 0x4d: reserved */
#define TID_EIT_ACT                             0x4e
#define TID_EIT_OTH                             0x4f
/* 
 * added(bruin, 2015-05-26): notes about section/segment for EIT-S: 
 *
 * - Each subtable can maximumly has 256 sections, each of which can be 4KiB in size
 * - Each subtable can maximumly convey EIT-S for 4 days (for one service)
 * - For broadcasting more than 4-day EIT-S, use multiple subtables, i.e., multiple table_ids. 
 *   e.g., for 7-day EIT-S, use two tables: 4-day in table_id 0x50 (or 0x60), 3-day in 0x51(0x61).
 * - EIT-S is grouped into segments, each of which convey EIT-S for 3 hours
 * - 4-day (4*24 hours) requires 4*24/3=32 segments
 * - If evenly divided, 256 sections for 32 segments means each segment (3-hour) can use upto 8 sections.
 * - EIT-S subtable can use discontinous section_numbers between segments, while sections for the same segment
 *   should be still continuous. Typically segments start from a section with its section_number equals to i*8, 
 *   where i=(0..31).
 */
 
#define TID_EIT_ACT_SCH                         0x50 /* to 0x5f */
#define TID_EIT_ACT_SCH_LAST                    0x5f
#define TID_EIT_OTH_SCH                         0x60 /* to 0x6f */
#define TID_EIT_OTH_SCH_LAST                    0x6f

#define TID_TDT                                 0x70
#define TID_RST                                 0x71
#define TID_ST                                  0x72
#define TID_TOT                                 0x73
/* 0x74-0x7d: reserved */
/* 0x7e: discontinuity_information_section */
/* 0x7f: selection_information_section */
/* 0x80 to 0xfe: USER DEFINED */
/* 0xff: reserved for stuffing */


/* added(bruin, 2003.01.13): mhp 1.1, table 107: table id on AIT pid */
/* 0x00-0x73: reserved to mhp for future use */
#define TID_AIT                                0x74
/* 0x75-0x7f: reserved to mhp for future use */
/* 0x80-0xff: reserved to private use */


/* added(bruin, 2003.02.17): dvb-rcs table ids (ETSI EN 301 790 v1.2.2 table 10) */
#define TID_RMT                                0x41  /* same as TID_NIT_OTH, but may only appear in specific PID? */
#define TID_SCT                                0xa0  /* superframe composition table */
#define TID_FCT                                0xa1  /* frame compostion table */
#define TID_TCT                                0xa2  /* time-slot composition table */
#define TID_SPT                                0xa3  /* satellite position table */ 
#define TID_CMT                                0xa4  /* correction message table */
#define TID_TBTP                               0xa5  /* terminal burst time plan */
#define TID_PCR                                0xa6  /* pcr packet payload */
#define TID_TIM                                0xb0  /* terminal information msg */



#endif // __TABLE_ID_H__
