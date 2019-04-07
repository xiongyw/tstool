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


#ifndef __13818-1_H__
#define __13818-1_H__



/* stream_id assignments: table 2-19 of iso/iec 13818-1 */

#define STREAM_ID_PROGRAM_STREAM_MAP              0xbc
#define STREAM_ID_PRIVATE_STREAM_1                0xbd
#define STREAM_ID_PADDING_STREAM                  0xbe
#define STREAM_ID_PRIVATE_STREAM_2                0xbf
#define STREAM_ID_11172_AUDIO_START               0xc0
#define STREAM_ID_11172_AUDIO_END                 0xdf
#define STREAM_ID_11172_VIDEO_START               0xe0
#define STREAM_ID_11172_VIDEO_END                 0xef
#define STREAM_ID_ECM                             0xf0
#define STREAM_ID_EMM                             0xf1
#define STREAM_ID_DSMCC                           0xf2
#define STREAM_ID_13522                           0xf3
#define STREAM_ID_H_222_1_A                       0xf4
#define STREAM_ID_H_222_1_B                       0xf5
#define STREAM_ID_H_222_1_C                       0xf6
#define STREAM_ID_H_222_1_D                       0xf7
#define STREAM_ID_H_222_1_E                       0xf8
#define STREAM_ID_ANCILLARY                       0xf9
#define STREAM_ID_PROGRAM_STREAM_DIRECTORY        0xff


/* PES packet header */

#define PACKET_START_CODE_PREFIX                  0x000001
#define PES_HEADER_SIZE                           9
typedef struct{
#ifdef __BIG_ENDIAN__
	u8 packet_start_code_prefix[3]              :8;
	u8 stream_id                                :8;
	u8 pes_packet_length_hi                     :8; /* remaining bytes in the PES */
	u8 pes_packet_length_lo                     :8; /* packet after this field */ 

	/* pes header flags */

	u8                                          :2;
	u8 pes_scrambling_control                   :2;
	u8 pes_priority                             :1;
	u8 data_alignment_indicator                 :1;
	u8 copy_right                               ;1;
	u8 original_or_copy                         :1;

	u8 pts_dts_flags                            :2;
	u8 escr_flag                                :1;
	u8 es_rate_flag                             :1;
	u8 dsm_trick_mode_flag                      :1;
	u8 additional_copy_info_flag                :1;
	u8 pes_crc_flag                             :1;
	u8 pes_extension_flag                       :1;

	/* size of the optional header data fields, the 
	   presence of optional fields is indicated by
	   pes header flags defined above */
	u8 pes_header_data_length                   :8;
#else
	u8 packet_start_code_prefix[3]              :8;
	u8 stream_id                                :8;
	u8 pes_packet_length_hi                     :8;
	u8 pes_packet_length_lo                     :8;

	u8 original_or_copy                         :1;
	u8 copy_right                               ;1;
	u8 data_alignment_indicator                 :1;
	u8 pes_priority                             :1;
	u8 pes_scrambling_control                   :2;
	u8                                          :2;

	u8 pes_extension_flag                       :1;
	u8 pes_crc_flag                             :1;
	u8 additional_copy_info_flag                :1;
	u8 dsm_trick_mode_flag                      :1;
	u8 es_rate_flag                             :1;
	u8 escr_flag                                :1;
	u8 pts_dts_flags                            :2;

	u8 pes_header_data_length                   :8;
#endif
}PES_HEADER;









#endif /* __13818-1_H__ */


