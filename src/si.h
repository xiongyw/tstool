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

/* bruin, 2002/03/27 */

#ifndef __SI_H__
#define __SI_H__

/* only PSI/SI standards related data structure and utility 
   routines are defined within this file. i.e., user defined 
   data structures to facilitate analysing/storing si info 
   are out of the scope of this file.
*/


#include "packet_id.h"
#include "table_id.h"
#include "desc_id.h"
#include "stream_type.h"


#pragma pack(1)

typedef unsigned char                           u8;
typedef unsigned short                          u16;
typedef unsigned int                            u32;


#define CRC_32_SIZE                             4



/* TS packet header */

#define TS_HEADER_LEN                        4
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 sync_byte                            :8;   /* always be 0x47 */
    u8 transport_error_indicator            :1;   
    u8 payload_unit_start_indicator         :1;   /* if a PES-packet starts in the TS-packet */
    u8 transport_priority                   :1;   /* meanless to IRD, can be ignored */
    u8 pid_hi                               :5;
    u8 pid_lo                               :8;
    u8 transport_scrambling_control         :2;   /* 00: no scramble, 01: reserved, 
                                                           10: even key scrambled, 11: odd key scrambled */
    u8 adaptation_field_control             :2;   /* 00: reserved
                                                           01: no adaptation field, payload only
                                                           10: adaptation field only, no payload
                                                           11: adaptation field followed by payload */
    u8 continuity_counter                   :4;
#else
    u8 sync_byte                            :8;
    u8 pid_hi                               :5;
    u8 transport_priority                   :1;
    u8 payload_unit_start_indicator         :1;
    u8 transport_error_indicator            :1;
    u8 pid_lo                               :8;
    u8 continuity_counter                   :4;
    u8 adaptation_field_control             :2;
    u8 transport_scrambling_control         :2;
#endif
}PACKET_HEADER;

/*
 * added(bruin, 2015-05-19): generic private section header
 */
#define PRIVATE_SECT_HEADER_LEN               (8)  // 4 bytes payload is not counted
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 table_id                             :8;
    u8 section_syntax_indicator             :1;
    u8                                      :3;
    u8 section_length_hi                    :4;
    u8 section_length_lo                    :8;
    u8 table_id_extension_hi                :8;
    u8 table_id_extension_lo                :8;
    u8                                      :2;
    u8 version_number                       :5;
    u8 current_next_indicator               :1;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8 payload_bytes[4]; // 4 bytes payload may be used for filtering sections
#else
    u8 table_id                             :8;
    u8 section_length_hi                    :4;
    u8                                      :3;
    u8 section_syntax_indicator             :1;
    u8 section_length_lo                    :8;
    u8 table_id_extension_hi                :8;
    u8 table_id_extension_lo                :8;
    u8 current_next_indicator               :1;
    u8 version_number                       :5;
    u8                                      :2;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8 payload_bytes[4];
#endif
}PRIV_SECT_HEADER;


/* NIT section header */

#define NIT_SECT_HEADER_LEN                  10
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 table_id                             :8;
    u8 section_syntax_indicator             :1;
    u8                                      :3;
    u8 section_length_hi                    :4;
    u8 section_length_lo                    :8;
    u8 network_id_hi                        :8;
    u8 network_id_lo                        :8;
    u8                                      :2;
    u8 version_number                       :5;
    u8 current_next_indicator               :1;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8                                      :4;
    u8 network_descriptors_length_hi        :4;
    u8 network_descriptors_length_lo        :8;
    /* descriptors */
#else
    u8 table_id                             :8;
    u8 section_length_hi                    :4;
    u8                                      :3;
    u8 section_syntax_indicator             :1;
    u8 section_length_lo                    :8;
    u8 network_id_hi                        :8;
    u8 network_id_lo                        :8;
    u8 current_next_indicator               :1;
    u8 version_number                       :5;
    u8                                      :2;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8 network_descriptors_length_hi        :4;
    u8                                      :4;
    u8 network_descriptors_length_lo        :8;
    /* descriptors */
#endif
}NIT_SECT_HEADER;


/* PAT section header */

#define PAT_SECT_HEADER_LEN                  8
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 table_id                             :8;
    u8 section_syntax_indicator             :1;
    u8                                      :3;
    u8 section_length_hi                    :4;
    u8 section_length_lo                    :8;
    u8 transport_stream_id_hi               :8;
    u8 transport_stream_id_lo               :8;
    u8                                      :2;
    u8 version_number                       :5;
    u8 current_next_indicator               :1;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
#else   
    u8 table_id                             :8;
    u8 section_length_hi                    :4;
    u8                                      :3;
    u8 section_syntax_indicator             :1;
    u8 section_length_lo                    :8;
    u8 transport_stream_id_hi               :8;
    u8 transport_stream_id_lo               :8;
    u8 current_next_indicator               :1;
    u8 version_number                       :5;
    u8                                      :2;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
#endif
}PAT_SECT_HEADER;

/* CAT section header */

#define CAT_SECT_HEADER_LEN                  8
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 table_id                             :8;
    u8 section_syntax_indicator             :1;
    u8                                      :3;
    u8 section_length_hi                    :4;
    u8 section_length_lo                    :8;
    u8                                      :8;
    u8                                      :8;
    u8                                      :2;
    u8 version_number                       :5;
    u8 current_next_indicator               :1;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
#else
    u8 table_id                             :8;
    u8 section_length_hi                    :4;
    u8                                      :3;
    u8 section_syntax_indicator             :1;
    u8 section_length_lo                    :8;
    u8                                      :8;
    u8                                      :8;
    u8 current_next_indicator               :1;
    u8 version_number                       :5;
    u8                                      :2;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
#endif
}CAT_SECT_HEADER;
    
/* PMT section header */

#define PMT_SECT_HEADER_LEN                  12
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 table_id                             :8;
    u8 section_syntax_indicator             :1;
    u8                                      :3;
    u8 section_length_hi                    :4;
    u8 section_length_lo                    :8;
    u8 program_number_hi                    :8;
    u8 program_number_lo                    :8;
    u8                                      :2;
    u8 version_number                       :5;
    u8 current_next_indicator               :1;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8                                      :3;
    u8 pcr_pid_hi                           :5;
    u8 pcr_pid_lo                           :8;
    u8                                      :4;
    u8 program_info_length_hi               :4;
    u8 program_info_length_lo               :8;
#else   
    u8 table_id                             :8;
    u8 section_length_hi                    :4;
    u8                                      :3;
    u8 section_syntax_indicator             :1;
    u8 section_length_lo                    :8;
    u8 program_number_hi                    :8;
    u8 program_number_lo                    :8;
    u8 current_next_indicator               :1;
    u8 version_number                       :5;
    u8                                      :2;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8 pcr_pid_hi                           :5;
    u8                                      :3;
    u8 pcr_pid_lo                           :8;
    u8 program_info_length_hi               :4;
    u8                                      :4;
    u8 program_info_length_lo               :8;
#endif
}PMT_SECT_HEADER;


/* BAT section header */

#define BAT_SECT_HEADER_LEN                  10
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 table_id                             :8;
    u8 section_syntax_indicator             :1;
    u8                                      :3;
    u8 section_length_hi                    :4;
    u8 section_length_lo                    :8;
    u8 bouquet_id_hi                        :8;
    u8 bouquet_id_lo                        :8;
    u8                                      :2;
    u8 version_number                       :5;
    u8 current_next_indicator               :1;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8                                      :4;
    u8 bouquet_descriptors_length_hi        :4;
    u8 bouquet_descriptors_length_lo        :8;
#else
    u8 table_id                             :8;
    u8 section_length_hi                    :4;
    u8                                      :3;
    u8 section_syntax_indicator             :1;
    u8 section_length_lo                    :8;
    u8 bouquet_id_hi                        :8;
    u8 bouquet_id_lo                        :8;
    u8 current_next_indicator               :1;
    u8 version_number                       :5;
    u8                                      :2;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8 bouquet_descriptors_length_hi        :4;
    u8                                      :4;
    u8 bouquet_descriptors_length_lo        :8;
#endif
}BAT_SECT_HEADER;


/* SDT section header */

#define SDT_SECT_HEADER_LEN                  11
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 table_id                             :8;
    u8 section_syntax_indicator             :1;
    u8                                      :3;
    u8 section_length_hi                    :4;
    u8 section_length_lo                    :8;
    u8 transport_stream_id_hi               :8;
    u8 transport_stream_id_lo               :8;
    u8                                      :2;
    u8 version_number                       :5;
    u8 current_next_indicator               :1;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8 original_network_id_hi               :8;
    u8 original_network_id_lo               :8;
    u8                                      :8;
#else
    u8 table_id                             :8;
    u8 section_length_hi                    :4;
    u8                                      :3;
    u8 section_syntax_indicator             :1;
    u8 section_length_lo                    :8;
    u8 transport_stream_id_hi               :8;
    u8 transport_stream_id_lo               :8;
    u8 current_next_indicator               :1;
    u8 version_number                       :5;
    u8                                      :2;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8 original_network_id_hi               :8;
    u8 original_network_id_lo               :8;
    u8                                      :8;
#endif
}SDT_SECT_HEADER;


/* EIT section header */

#define EIT_SECT_HEADER_LEN                  14
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 table_id                             :8;
    u8 section_syntax_indicator             :1;
    u8                                      :3;
    u8 section_length_hi                    :4;
    u8 section_length_lo                    :8;
    u8 service_id_hi                        :8;
    u8 service_id_lo                        :8;
    u8                                      :2;
    u8 version_number                       :5;
    u8 current_next_indicator               :1;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8 transport_stream_id_hi               :8;
    u8 transport_stream_id_lo               :8;
    u8 original_network_id_hi               :8;
    u8 original_network_id_lo               :8;
    u8 segment_last_section_number          :8;
    u8 last_table_id                        :8;
#else
    u8 table_id                             :8;
    u8 section_length_hi                    :4;
    u8                                      :3;
    u8 section_syntax_indicator             :1;
    u8 section_length_lo                    :8;
    u8 service_id_hi                        :8;
    u8 service_id_lo                        :8;
    u8 current_next_indicator               :1;
    u8 version_number                       :5;
    u8                                      :2;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8 transport_stream_id_hi               :8;
    u8 transport_stream_id_lo               :8;
    u8 original_network_id_hi               :8;
    u8 original_network_id_lo               :8;
    u8 segment_last_section_number          :8;
    u8 last_table_id                        :8;
#endif
}EIT_SECT_HEADER;


/* TDT section */

typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 table_id                             :8;
    u8 section_syntax_indicator             :1;
    u8                                      :3;
    u8 section_length_hi                    :4;
    u8 section_length_lo                    :8;
    u8 utc_time[5];
#else
    u8 table_id                             :8;
    u8 section_length_hi                    :4;
    u8                                      :3;
    u8 section_syntax_indicator             :1;
    u8 section_length_lo                    :8;
    u8 utc_time[5];
#endif
}TDT_SECTION;


/* TOT section header */

#define TOT_SECT_HEADER_LEN                  10
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 table_id                             :8;
    u8 section_syntax_indicator             :1;
    u8                                      :3;
    u8 section_length_hi                    :4;
    u8 section_length_lo                    :8;
    u8 utc_time[5];
    u8                                      :4;
    u8 descriptors_loop_length_hi           :4;
    u8 descriptors_loop_length_lo           :8;
#else
    u8 table_id                             :8;
    u8 section_length_hi                    :4;
    u8                                      :3;
    u8 section_syntax_indicator             :1;
    u8 section_length_lo                    :8;
    u8 utc_time[5];
    u8 descriptors_loop_length_hi           :4;
    u8                                      :4;
    u8 descriptors_loop_length_lo           :8;
#endif
}TOT_SECT_HEADER;

/* RST section header */

#define RST_SECT_HEADER_LEN                  3
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 table_id                             :8;
    u8 section_syntax_indicator             :1;
    u8                                      :3;
    u8 section_length_hi                    :4;
    u8 section_length_lo                    :8;
#else
    u8 table_id                             :8;
    u8 section_length_hi                    :4;
    u8                                      :3;
    u8 section_syntax_indicator             :1;
    u8 section_length_lo                    :8;
#endif
}RST_SECT_HEADER;

#define RST_OF_EVENT_SIZE                    9;
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 transport_stream_id_hi               :8;
    u8 transport_stream_id_lo               :8;
    u8 original_network_id_hi               :8;
    u8 original_network_id_lo               :8;
    u8 service_id_hi                        :8;
    u8 service_id_lo                        :8;
    u8 event_id_hi                          :8;
    u8 event_id_lo                          :8;
    u8                                      :5;
    u8 running_status                       :3;
#else
    u8 transport_stream_id_hi               :8;
    u8 transport_stream_id_lo               :8;
    u8 original_network_id_hi               :8;
    u8 original_network_id_lo               :8;
    u8 service_id_hi                        :8;
    u8 service_id_lo                        :8;
    u8 event_id_hi                          :8;
    u8 event_id_lo                          :8;
    u8 running_status                       :3;
    u8                                      :5;
#endif
}RST_OF_EVENT;



/* AIT section header */   /* added(bruin, 2003.01.13) */

#define AIT_SECT_HEADER_LEN                  10
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 table_id                             :8;
    u8 section_syntax_indicator             :1;
    u8                                      :3;
    u8 section_length_hi                    :4;
    u8 section_length_lo                    :8;
    u8 application_type_hi                  :8;
    u8 application_type_lo                  :8;
    u8                                      :2;
    u8 version_number                       :5;
    u8 current_next_indicator               :1;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8                                      :4;
    u8 common_descriptors_length_hi         :4;
    u8 common_descriptors_length_lo         :8;
#else   
    u8 table_id                             :8;
    u8 section_length_hi                    :4;
    u8                                      :3;
    u8 section_syntax_indicator             :1;
    u8 section_length_lo                    :8;
    u8 application_type_hi                  :8;
    u8 application_type_lo                  :8;
    u8 current_next_indicator               :1;
    u8 version_number                       :5;
    u8                                      :2;
    u8 section_number                       :8;
    u8 last_section_number                  :8;
    u8 common_descriptors_length_hi         :4;
    u8                                      :4;
    u8 common_descriptors_length_lo         :8;
#endif
}AIT_SECT_HEADER;


                                               
/*** struct of descriptors ***/

/* 13818 descriptors */
typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 multiple_frame_rate_flag             :1;
    u8 frame_rate_code                      :4;
    u8 mpeg_1_only_flag                     :1;
    u8 constrained_parameter_flag           :1;
    u8 still_picture_flag                   :1;
    /* only if(mpeg_1_only_flag == 0) */        
    u8 profile_and_level_indication         :8;
    u8 chroma_format                        :2;
    u8 frame_rate_extension_flag            :1;
    u8                                      :5;
#else
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 still_picture_flag                   :1;
    u8 constrained_parameter_flag           :1;
    u8 mpeg_1_only_flag                     :1;
    u8 frame_rate_code                      :4;
    u8 multiple_frame_rate_flag             :1;
    /* only if(mpeg_1_only_flag == 0) */        
    u8 profile_and_level_indication         :8;
    u8                                      :5;
    u8 frame_rate_extension_flag            :1;
    u8 chroma_format                        :2;
#endif
}VIDEO_STREAM_DESC;

typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 free_format_flag                     :1;
    u8 id                                   :1;
    u8 layer                                :2;
    u8 variable_rate_audio_indicator        :1;
    u8                                      :3;
#else
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8                                      :3;
    u8 variable_rate_audio_indicator        :1;
    u8 layer                                :2;
    u8 id                                   :1;
    u8 free_format_flag                     :1;
#endif
}AUDIO_STREAM_DESC;

typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8                                      :4;
    u8 hierarchy_type                       :4;
    u8                                      :2;
    u8 hierarchy_layer_index                :6;
    u8                                      :2;
    u8 hierarchy_embedded_layer             :6;
    u8                                      :2;
    u8 hierarchy_priority                   :6;
#else
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 hierarchy_type                       :4;
    u8                                      :4;
    u8 hierarchy_layer_index                :6;
    u8                                      :2;
    u8 hierarchy_embedded_layer             :6;
    u8                                      :2;
    u8 hierarchy_priority                   :6;
    u8                                      :2;
#endif
}HIERARCHY_DESC;

typedef struct{
    u8 descriptor_tag;
    u8 descriptor_length;
    u8 format_identifier[4];
}REGISTRATION_DESC_HEADER;

typedef struct{
    u8 descriptor_tag;
    u8 descriptor_length;
    u8 alignment_type;          
}DATA_STREAM_ALIGNMENT_DESC;

typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 horizontal_size_hi                   :8;
    u8 horizontal_size_lo                   :6;
    u8 vertical_size_hi                     :2;
    u8 vertical_size_mi                     :8;
    u8 vertical_size_lo                     :4;
    u8 aspect_ratio_information             :4;
#else
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 horizontal_size_hi                   :8;
    u8 vertical_size_hi                     :2;
    u8 horizontal_size_lo                   :6;
    u8 vertical_size_mi                     :8;
    u8 aspect_ratio_information             :4;
    u8 vertical_size_lo                     :4;
#endif
}TARGET_BACKGROUND_GRID_DESC;

typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 horizontal_offset_hi                 :8;
    u8 horizontal_offset_lo                 :6;
    u8 vertical_offset_hi                   :2;
    u8 vertical_offset_mi                   :8;
    u8 vertical_offset_lo                   :4;
    u8 window_priority                      :4;
#else
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 horizontal_offset_hi                 :8;
    u8 vertical_offset_hi                   :2;
    u8 horizontal_offset_lo                 :6;
    u8 vertical_offset_mi                   :8;
    u8 window_priority                      :4;
    u8 vertical_offset_lo                   :4;
#endif
}VIDEO_WINDOW_DESC;

typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 ca_system_id_hi                      :8;
    u8 ca_system_id_lo                      :8;
    u8                                      :3; 
    u8 ca_pid_hi                            :5;
    u8 ca_pid_lo                            :8;
#else
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 ca_system_id_hi                      :8;
    u8 ca_system_id_lo                      :8;
    u8 ca_pid_hi                            :5;
    u8                                      :3; 
    u8 ca_pid_lo                            :8;
#endif
}CA_DESC_HEADER;

typedef struct{
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
}ISO_639_LANGUAGE_DESC_HEADER;

typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 external_clock_reference_indicator   :1;
    u8                                      :1;
    u8 clock_accuracy_integer               :6;
    u8 clock_accuracy_exponent              :3;
    u8                                      :5;
#else
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 clock_accuracy_integer               :6;
    u8                                      :1;
    u8 external_clock_reference_indicator   :1;
    u8                                      :5;
    u8 clock_accuracy_exponent              :3;
#endif
}SYSTEM_CLOCK_DESC;

typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 bound_valid_flag                     :1;
    u8 ltw_offset_lower_bound_hi            :7;
    u8 ltw_offset_lower_bound_lo            :8;
    u8                                      :1;
    u8 ltw_offset_upper_bound_hi            :7;
    u8 ltw_offset_upper_bound_lo            :8;
#else
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 ltw_offset_lower_bound_hi            :7;
    u8 bound_valid_flag                     :1;
    u8 ltw_offset_lower_bound_lo            :8;
    u8 ltw_offset_upper_bound_hi            :7;
    u8                                      :1;
    u8 ltw_offset_upper_bound_lo            :8;
#endif
}MULTIPLEX_BUFFER_UTILIZATION_DESC;

typedef struct{
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 copyright_identifier[4];
}COPYRIGHT_DESC_HEADER;

typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8                                      :2;
    u8 maximum_bitrate_hi                   :6; /* unit: 50 bps */
    u8 maximum_bitrate_mi                   :8;
    u8 maximum_bitrate_lo                   :8;
#else
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 maximum_bitrate_hi                   :6;
    u8                                      :2;
    u8 maximum_bitrate_mi                   :8;
    u8 maximum_bitrate_lo                   :8;
#endif
}MAXIMUM_BITRATE_DESC;

typedef struct{
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 private_data_indicator[4];
}PRIVATE_DATA_INDICATOR_DESC;

typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8                                      :2;
    u8 sb_leak_rate_hi                      :6;  /* unit: 400 bps */
    u8 sb_leak_rate_mi                      :8;
    u8 sb_leak_rate_lo                      :8;
    u8                                      :2;
    u8 sb_size_hi                           :6;  /* unit: 1 byte */
    u8 sb_size_mi                           :8;
    u8 sb_size_lo                           :8;
#else
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 sb_leak_rate_hi                      :6;  /* unit: 400 bps */
    u8                                      :2;
    u8 sb_leak_rate_mi                      :8;
    u8 sb_leak_rate_lo                      :8;
    u8 sb_size_hi                           :6;  /* unit: 1 byte */
    u8                                      :2;
    u8 sb_size_mi                           :8;
    u8 sb_size_lo                           :8;
#endif
}SMOOTHING_BUFFER_DESC;

typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8                                      :7;
    u8 leak_valid_flag                      :1;
#else
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 leak_valid_flag                      :1;
    u8                                      :7;
#endif
}STD_DESC;

typedef struct{
#ifdef WORDS_BIGENDIAN
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 closed_gop_flag                      :1;
    u8 identical_gop_flag                   :1;
    u8 max_gop_length_hi                    :6;
    u8 max_gop_length_lo                    :8;
#else
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 max_gop_length_hi                    :6;
    u8 identical_gop_flag                   :1;
    u8 closed_gop_flag                      :1;
    u8 max_gop_length_lo                    :8;
#endif
}IBP_DESC;

/* dvb-si descriptors */
/* TBD */




/* opentv private descriptors */

typedef struct{
    u8 descriptor_tag                       :8;
    u8 descriptor_length                    :8;
    u8 track_tag[4];
}OPENTV_TRACK_TAG_DESC;



/* macro to access packet header fields */

#define packet_sync_byte(x)    (((PACKET_HEADER*)(x))->sync_byte)
#define packet_transport_error_indicator(x) (((PACKET_HEADER*)(x))->transport_error_indicator)
#define packet_payload_unit_start_indicator(x)    (((PACKET_HEADER*)(x))->payload_unit_start_indicator)
#define packet_transport_priority(x) (((PACKET_HEADER*)(x))->transport_priority)
#define packet_pid(x) (((PACKET_HEADER*)(x))->pid_hi * 256 + ((PACKET_HEADER*)(x))->pid_lo)
#define packet_transport_scrambling_control(x) (((PACKET_HEADER*)(x))->transport_scrambling_control)
#define packet_adaptation_field_control(x) (((PACKET_HEADER*)(x))->adaptation_field_control)
#define packet_continuity_counter(x) (((PACKET_HEADER*)(x))->continuity_counter)


/* misc routines */

#ifdef __cplusplus
extern "C"{
#endif

const char* get_pid_name_by_id(u16 pid);
const char* get_tid_name_by_id(u8 table_id);
const char* get_desc_name_by_id(u8 desc_id);
const char* get_stream_type_name_by_id(u8 type_id);
const char* get_frame_rate_by_code(u8 code);
const char* get_chroma_format_by_code(u8 code);
const char* get_video_profile_by_code(u8 code);
const char* get_video_level_by_code(u8 code);
const char* get_audio_type_by_code(u8 code);
const char* get_aspect_ratio_information_by_code(u8 code);
const char* get_running_status_by_code(u8 code);
char* get_string_by_utc_time(u8 utc_time[5]);
const char* get_outer_fec_scheme_by_code(u8 code);
const char* get_inner_fec_scheme_by_code(u8 code);
const char* get_cable_modulation_scheme_by_code(u8 code);
const char* get_satellite_modulation_scheme_by_code(u8 code);
const char* get_polariztion_by_code(u8 code);
const char* get_service_type_by_code(u8 code);
const char* get_linkage_type_by_code(u8 code);
const char* get_hand_over_type_by_code(u8 code);
const char* get_content_nibble_name_by_code(u8 code, int is_level_1);
const char* get_minimum_age_by_rating(u8 rating);
const char* get_application_id_name_by_id(u16 id);
const char* get_transport_protocol_id_name_by_id(u16 id);

/* added(bruin, 2003.01.13): mhp 1.1 AIT */
const char* get_application_type_by_code(u16 type); 
const char* get_application_control_code_name(u16 application_type, u8 control_code);

u16 get_pid_of_tid(u8 tid);
int get_minimum_section_size_by_tid(u8 tid);  // 2015-05-26

const char* get_mhp_desc_name_by_id(u8 desc_id);

/* added(bruin, 2003.02.17): dvb-rcs */
const char* get_rcs_desc_name_by_id(u8 desc_id);
const char* get_rcs_tid_name_by_id(u8 tid);

/* added(bruin, 2003.12.19): terrestrial_delivery_system_descriptor */
const char* get_terrestrial_bandwidth_by_code(u8 code);
const char* get_terrestrial_constellation_pattern_by_code(u8 code);
const char* get_terrestrial_hierarchy_information_by_code(u8 code);
const char* get_terrestrial_code_rate_by_code(u8 code);
const char* get_terrestrial_guard_interval_by_code(u8 code);
const char* get_terrestrial_transmission_mode_by_code(u8 code);

#ifdef __cplusplus
}
#endif




#endif   /* __SI_H__ */
