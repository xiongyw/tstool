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
 * created(bruin, 2015/05/20): utility for filtering sections
 */

#ifndef __SECTION_FILTER_H__
#define __SECTION_FILTER_H__

#define STMT(stuff)            do { stuff } while(0)

typedef struct {
    PRIV_SECT_HEADER value;
    PRIV_SECT_HEADER mask;
} SECT_FILTER;


#define SETUP_SECT_FILETER(filter, field, val) STMT(\
    filter.value.field = val; \
    filter.mask.field = -1; \
    )

/*
 * added(bruin, 2015-05-19): subtable extra ids:
 *
 *       | table_id_extension |
 *       |    (16 bit)        | payload part
 * ------+--------------------+---------------------------------------
 *  NIT  |  network id        |
 * ------+--------------------+---------------------------------------
 *  BAT  |  bouquet id        |
 * ------+--------------------+---------------------------------------
 *  SDT  |  ts id             | onid (16bit)
 * ------+--------------------+---------------------------------------
 *  EIT  |  svc id            | tsid (16bit) + onid (16bit)
 * ------+--------------------+---------------------------------------
 *
 * ------+--------------------+---------------------------------------
 *  PAT  |  ts id             |
 * ------+--------------------+---------------------------------------
 *  PMT  |  prog_nr           |
 * ------+--------------------+---------------------------------------
 *  AIT  |  app_type          |
 * ------+--------------------+---------------------------------------
 *
 * ------+--------------------+---------------------------------------
 * DSM-CC| transaction id     | if tid=0x3B
 * ------+--------------------+---------------------------------------
 * DSM-CC| module id          | if tid=0x3C
 * ------+--------------------+---------------------------------------
 */

#define SETUP_SECT_FILTER_4_NIT_ACT(filter, nid, ver) STMT( \
	memset(&filter, 0, sizeof(SECT_FILTER)); \
	SETUP_SECT_FILETER(filter, table_id, TID_NIT_ACT); \
	SETUP_SECT_FILETER(filter, table_id_extension_hi, (nid >> 8)); \
	SETUP_SECT_FILETER(filter, table_id_extension_lo, (nid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, version_number, ver); \
	) 

#define SETUP_SECT_FILTER_4_NIT_OTH(filter, nid, ver) STMT( \
	memset(&filter, 0, sizeof(SECT_FILTER)); \
	SETUP_SECT_FILETER(filter, table_id, TID_NIT_OTH); \
	SETUP_SECT_FILETER(filter, table_id_extension_hi, (nid >> 8)); \
	SETUP_SECT_FILETER(filter, table_id_extension_lo, (nid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, version_number, ver); \
	) 

#define SETUP_SECT_FILTER_4_BAT(filter, bid, ver) STMT( \
	memset(&filter, 0, sizeof(SECT_FILTER)); \
	SETUP_SECT_FILETER(filter, table_id, TID_BAT); \
	SETUP_SECT_FILETER(filter, table_id_extension_hi, (bid >> 8)); \
	SETUP_SECT_FILETER(filter, table_id_extension_lo, (bid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, version_number, ver); \
	) 

#define SETUP_SECT_FILTER_4_SDT_ACT(filter, onid, tsid, ver) STMT( \
	memset(&filter, 0, sizeof(SECT_FILTER)); \
	SETUP_SECT_FILETER(filter, table_id, TID_SDT_ACT); \
	SETUP_SECT_FILETER(filter, table_id_extension_hi, (tsid >> 8)); \
	SETUP_SECT_FILETER(filter, table_id_extension_lo, (tsid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, payload_bytes[0], (onid >> 8)); \
	SETUP_SECT_FILETER(filter, payload_bytes[1], (onid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, version_number, ver); \
	) 

#define SETUP_SECT_FILTER_4_SDT_OTH(filter, onid, tsid, ver) STMT( \
	memset(&filter, 0, sizeof(SECT_FILTER)); \
	SETUP_SECT_FILETER(filter, table_id, TID_SDT_OTH); \
	SETUP_SECT_FILETER(filter, table_id_extension_hi, (tsid >> 8)); \
	SETUP_SECT_FILETER(filter, table_id_extension_lo, (tsid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, payload_bytes[0], (onid >> 8)); \
	SETUP_SECT_FILETER(filter, payload_bytes[1], (onid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, version_number, ver); \
	) 

#define SETUP_SECT_FILTER_4_EIT_ACT(filter, onid, tsid, svcid, ver) STMT( \
	memset(&filter, 0, sizeof(SECT_FILTER)); \
	SETUP_SECT_FILETER(filter, table_id, TID_EIT_ACT); \
	SETUP_SECT_FILETER(filter, table_id_extension_hi, (svcid >> 8)); \
	SETUP_SECT_FILETER(filter, table_id_extension_lo, (svcid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, payload_bytes[0], (tsid >> 8)); \
	SETUP_SECT_FILETER(filter, payload_bytes[1], (tsid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, payload_bytes[2], (onid >> 8)); \
	SETUP_SECT_FILETER(filter, payload_bytes[3], (onid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, version_number, ver); \
	) 

#define SETUP_SECT_FILTER_4_EIT_OTH(filter, onid, tsid, svcid, ver) STMT( \
	memset(&filter, 0, sizeof(SECT_FILTER)); \
	SETUP_SECT_FILETER(filter, table_id, TID_EIT_OTH); \
	SETUP_SECT_FILETER(filter, table_id_extension_hi, (svcid >> 8)); \
	SETUP_SECT_FILETER(filter, table_id_extension_lo, (svcid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, payload_bytes[0], (tsid >> 8)); \
	SETUP_SECT_FILETER(filter, payload_bytes[1], (tsid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, payload_bytes[2], (onid >> 8)); \
	SETUP_SECT_FILETER(filter, payload_bytes[3], (onid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, version_number, ver); \
	) 

#define SETUP_SECT_FILTER_4_EIT_ACT_SCH(filter, onid, tsid, svcid, ver) STMT( \
	memset(&filter, 0, sizeof(SECT_FILTER)); \
	SETUP_SECT_FILETER(filter, table_id, TID_EIT_ACT_SCH); \
	SETUP_SECT_FILETER(filter, table_id_extension_hi, (svcid >> 8)); \
	SETUP_SECT_FILETER(filter, table_id_extension_lo, (svcid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, payload_bytes[0], (tsid >> 8)); \
	SETUP_SECT_FILETER(filter, payload_bytes[1], (tsid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, payload_bytes[2], (onid >> 8)); \
	SETUP_SECT_FILETER(filter, payload_bytes[3], (onid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, version_number, ver); \
	) 

#define SETUP_SECT_FILTER_4_EIT_OTH_SCH(filter, onid, tsid, svcid, ver) STMT( \
	memset(&filter, 0, sizeof(SECT_FILTER)); \
	SETUP_SECT_FILETER(filter, table_id, TID_EIT_OTH_SCH); \
	SETUP_SECT_FILETER(filter, table_id_extension_hi, (svcid >> 8)); \
	SETUP_SECT_FILETER(filter, table_id_extension_lo, (svcid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, payload_bytes[0], (tsid >> 8)); \
	SETUP_SECT_FILETER(filter, payload_bytes[1], (tsid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, payload_bytes[2], (onid >> 8)); \
	SETUP_SECT_FILETER(filter, payload_bytes[3], (onid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, version_number, ver); \
	) 


#define SETUP_SECT_FILTER_4_PAT(filter, tsid, ver) STMT( \
	memset(&filter, 0, sizeof(SECT_FILTER)); \
	SETUP_SECT_FILETER(filter, table_id, TID_PAT); \
	SETUP_SECT_FILETER(filter, table_id_extension_hi, (tsid >> 8)); \
	SETUP_SECT_FILETER(filter, table_id_extension_lo, (tsid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, version_number, ver); \
	) 

#define SETUP_SECT_FILTER_4_PMT(filter, progid, ver) STMT( \
	memset(&filter, 0, sizeof(SECT_FILTER)); \
	SETUP_SECT_FILETER(filter, table_id, TID_PMT); \
	SETUP_SECT_FILETER(filter, table_id_extension_hi, (progid >> 8)); \
	SETUP_SECT_FILETER(filter, table_id_extension_lo, (progid & 0x00ff)); \
	SETUP_SECT_FILETER(filter, version_number, ver); \
	) 

#define SETUP_SECT_FILTER_4_AIT(filter, apptype, ver) STMT( \
	memset(&filter, 0, sizeof(SECT_FILTER)); \
	SETUP_SECT_FILETER(filter, table_id, TID_AIT); \
	SETUP_SECT_FILETER(filter, table_id_extension_hi, (apptype >> 8)); \
	SETUP_SECT_FILETER(filter, table_id_extension_lo, (apptype & 0x00ff)); \
	SETUP_SECT_FILETER(filter, version_number, ver); \
	) 


#endif  // __SECTION_FILTER_H__

