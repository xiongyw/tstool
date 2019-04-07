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

#include <stdio.h>
#include "si.h"


/*** pid name const definition ***/

static const char s_pat_pid_name[] = "PAT";
static const char s_cat_pid_name[] = "CAT";
static const char s_nit_pid_name[] = "NIT";
static const char s_sdt_bat_pid_name[] = "SDT/BAT";
static const char s_eit_pid_name[] = "EIT";
static const char s_rst_pid_name[] = "RST";
static const char s_tdt_tot_pid_name[] = "TDT/TOT";
static const char s_dit_pid_name[] = "DIT";
static const char s_sit_pid_name[] = "SIT";
static const char s_nul_pid_name[] = "NULL";

/*** tid name const definition ***/

static const char s_pat_tbl_name[] = "pat table";
static const char s_cat_tbl_name[] = "cat table";
static const char s_pmt_tbl_name[] = "pmt table";
static const char s_nit_act_tbl_name[] = "nit actual table";
static const char s_nit_oth_tbl_name[] = "nit other table";
static const char s_sdt_act_tbl_name[] = "sdt actual table";
static const char s_sdt_oth_tbl_name[] = "sdt other table";
static const char s_bat_tbl_name[] = "bat table";
static const char s_eit_act_tbl_name[] = "eit actual table";
static const char s_eit_oth_tbl_name[] = "eit other table";
static const char s_eit_act_sch_tbl_name[] = "eit actual schedule table";
static const char s_eit_oth_sch_tbl_name[] = "eit other schedule table";
static const char s_tdt_tbl_name[] = "tdt table";
static const char s_tot_tbl_name[] = "tot table";
static const char s_rst_tbl_name[] = "rst table";
static const char s_st_tbl_name[] = "stuffing table";

/* added(bruin, 2003.01.13) */
static const char s_ait_tbl_name[] = "ait table"; 

/* added(bruin, 2003.02.17) */
static const char s_rmt_tbl_name[] = "rcs maptable";
static const char s_sct_tbl_name[] = "superframe composition table";
static const char s_fct_tbl_name[] = "frame composition table";
static const char s_tct_tbl_name[] = "time-slot composition table";
static const char s_spt_tbl_name[] = "satellite position table";
static const char s_cmt_tbl_name[] = "correction message table";
static const char s_tbtp_tbl_name[] = "terminal burst time plan";
static const char s_rcs_prc_tbl_name[] = "pcr packet payload";
static const char s_tim_tbl_name[] = "terminal information msg";



/*** descriptor name const definition ***/

/* iso/iec 13818-1, section 2.6.1, table 2-40 */

static const char s_desc_0x00_name[] = "reserved_descriptor";
static const char s_desc_0x01_name[] = "reserved_descriptor";
static const char s_desc_0x02_name[] = "video_stream_descriptor";
static const char s_desc_0x03_name[] = "audio_stream_descriptor";
static const char s_desc_0x04_name[] = "hierarchy_descriptor";
static const char s_desc_0x05_name[] = "registration_descriptor";
static const char s_desc_0x06_name[] = "data_stream_alignment_descriptor";
static const char s_desc_0x07_name[] = "target_background_grid_descriptor";
static const char s_desc_0x08_name[] = "video_window_descriptor";
static const char s_desc_0x09_name[] = "ca_descriptor";
static const char s_desc_0x0a_name[] = "iso_639_language_descriptor";
static const char s_desc_0x0b_name[] = "system_clock_descriptor";
static const char s_desc_0x0c_name[] = "multiplex_buffer_utilization_descriptor";
static const char s_desc_0x0d_name[] = "copyright_descriptor";
static const char s_desc_0x0e_name[] = "maximum_bitrate_descriptor";
static const char s_desc_0x0f_name[] = "private_data_indicator_descriptor";
static const char s_desc_0x10_name[] = "smoothing_buffer_descriptor";
static const char s_desc_0x11_name[] = "std_descritpor";
static const char s_desc_0x12_name[] = "ibp_descriptor";
/* added(bruin, 2015-05-13): carousel_identifier_descriptor 0x13 in PMT for DSM-CC DC/OC */
static const char s_desc_0x13_name[] = "carousel_identifier_descriptor";

/* 0x19-0x3f are iso/iec 13818-1 reserved */
static const char s_desc_0x19_name[] = "reserved_descriptor";
static const char s_desc_0x3f_name[] = "reserved_descriptor";

/* dvb-si descriptors, section 6, table 12 of A038 rev1 */

static const char s_desc_0x40_name[] = "network_name_descriptor";
static const char s_desc_0x41_name[] = "service_list_descriptor";
static const char s_desc_0x42_name[] = "stuffing_descriptor";
static const char s_desc_0x43_name[] = "satellite_delivery_system_descriptor";
static const char s_desc_0x44_name[] = "cable_delivery_system_descriptor";
static const char s_desc_0x45_name[] = "vbi_data_descriptor";
static const char s_desc_0x46_name[] = "vbi_teletext_descriptor";
static const char s_desc_0x47_name[] = "bouquet_name_descriptor";
static const char s_desc_0x48_name[] = "service_descriptor";
static const char s_desc_0x49_name[] = "country_availability_descriptor";
static const char s_desc_0x4a_name[] = "linkage_descriptor";
static const char s_desc_0x4b_name[] = "nvod_reference_descriptor";
static const char s_desc_0x4c_name[] = "time_shifted_service_descriptor";
static const char s_desc_0x4d_name[] = "short_event_descriptor";
static const char s_desc_0x4e_name[] = "extended_event_descriptor";
static const char s_desc_0x4f_name[] = "time_shifted_event_descriptor";
static const char s_desc_0x50_name[] = "component_descriptor";
static const char s_desc_0x51_name[] = "mosaic_descriptor";
static const char s_desc_0x52_name[] = "stream_identifier_descriptor";
static const char s_desc_0x53_name[] = "ca_identifier_descriptor";
static const char s_desc_0x54_name[] = "content_descriptor";
static const char s_desc_0x55_name[] = "parental_rating_descriptor";
static const char s_desc_0x56_name[] = "teletext_descriptor";
static const char s_desc_0x57_name[] = "telephone_descriptor";
static const char s_desc_0x58_name[] = "local_time_offset_descriptor";
static const char s_desc_0x59_name[] = "subtitling_descriptor";
static const char s_desc_0x5a_name[] = "terrestrial_delivery_system_descriptor";
static const char s_desc_0x5b_name[] = "multilingual_network_name_descriptor";
static const char s_desc_0x5c_name[] = "multilingual_bouquet_name_descriptor";
static const char s_desc_0x5d_name[] = "multilingual_service_name_descriptor";
static const char s_desc_0x5e_name[] = "multilingual_component_descriptor";
static const char s_desc_0x5f_name[] = "private_data_specifier_descriptor";
static const char s_desc_0x60_name[] = "service_move_descriptor";
static const char s_desc_0x61_name[] = "short_smoothing_buffer_descriptor";
static const char s_desc_0x62_name[] = "frequency_list_descriptor";
static const char s_desc_0x63_name[] = "partial_transport_stream_descriptor";
static const char s_desc_0x64_name[] = "data_broadcast_descriptor";
static const char s_desc_0x65_name[] = "ca_system_descriptor";
static const char s_desc_0x66_name[] = "data_broadcast_id_descriptor";
static const char s_desc_0x67_name[] = "transport_stream_descriptor";
static const char s_desc_0x68_name[] = "dsng_descriptor";
static const char s_desc_0x69_name[] = "pdc_descriptor";
static const char s_desc_0x6a_name[] = "ac-3_descriptor";
static const char s_desc_0x6b_name[] = "ancillary_data_descriptor";
static const char s_desc_0x6c_name[] = "cell_list_descriptor";
static const char s_desc_0x6d_name[] = "cell_frequency_link_descriptor";
static const char s_desc_0x6e_name[] = "announcement_support_descriptor";

/* 0x6f - 0x7f are reserved */
/* 0x80 - 0xfe are user defined */
/* 0xff is forbidden */

/* opentv private descriptors */
static const char s_desc_0x90_name[] = "opentv_module_track_descriptor";
static const char s_desc_0xfe_name[] = "opentv_track_tag_descriptor";

/* added(bruin, 2003.01.15) */
static const char s_desc_0x6f_name[] = "application_signalling_descriptor";
static const char s_desc_0x71_name[] = "service_identifier_descriptor";

/* added(bruin, 2003.12.19): LCN draft */
static const char s_desc_0x83_name[] = "logical_channel_descriptor(draft)";

/* 2003.01.21: mhp 1.1 descriptors */
static const char s_mhp_desc_0x00_name[] = "application_descriptor";
static const char s_mhp_desc_0x01_name[] = "application_name_descriptor";   
static const char s_mhp_desc_0x02_name[] = "transport_protocol_descriptor";
static const char s_mhp_desc_0x03_name[] = "dvb_j_application_descriptor";
static const char s_mhp_desc_0x04_name[] = "dvb_j_application_location_descriptor";
static const char s_mhp_desc_0x05_name[] = "external_application_authorization_descriptor";
static const char s_mhp_desc_0x06_name[] = "ipv4_routing_descriptor";
static const char s_mhp_desc_0x07_name[] = "ipv6_routing_descriptor";
static const char s_mhp_desc_0x08_name[] = "dvb_html_application_descriptor";
static const char s_mhp_desc_0x09_name[] = "dvb_html_application_location_descriptor";
static const char s_mhp_desc_0x0a_name[] = "dvb_html_application_boundary_descriptor";
static const char s_mhp_desc_0x0b_name[] = "application_icons_descriptor";
static const char s_mhp_desc_0x0c_name[] = "prefetch_descriptor";
static const char s_mhp_desc_0x0d_name[] = "dll_location_descriptor";
static const char s_mhp_desc_0x0e_name[] = "delegated_application_descriptor";
static const char s_mhp_desc_0x0f_name[] = "plug_in_descriptor";
static const char s_mhp_desc_0x5f_name[] = "private_data_specifier_descriptor";
static const char s_mhp_desc_name_user_defined[] = "user_defined_descriptor";
static const char s_mhp_desc_name_reserved_for_future_use[] = "reserved_for_future_use_descriptor";


/* added(bruin, 2003.02.17) */
static const char s_desc_0xa7_name[] = "rcs_content_descriptor";

static const char s_rcs_desc_0xa0_name[] = "network_layer_info_descriptor";
static const char s_rcs_desc_0xa1_name[] = "correction_message_descriptor";
static const char s_rcs_desc_0xa2_name[] = "logon_initialize_descriptor";
static const char s_rcs_desc_0xa3_name[] = "acq_assign_descriptor";
static const char s_rcs_desc_0xa4_name[] = "sync_assign_descriptor";
static const char s_rcs_desc_0xa5_name[] = "encrypted_logon_id_descriptor";
static const char s_rcs_desc_0xa6_name[] = "echo_value_descriptor";
static const char s_rcs_desc_0xa8_name[] = "satellite_forward_link_descriptor";
static const char s_rcs_desc_0xa9_name[] = "satellite_return_link_descriptor";
static const char s_rcs_desc_0xaa_name[] = "table_update_descriptor";
static const char s_rcs_desc_0xab_name[] = "contention_control_descriptor";
static const char s_rcs_desc_0xac_name[] = "correction_control_descriptor";

/*** stream type name: iso/iec 13818-1 table 2-36 */

static const char s_stream_type_0x00_name[] = "iso/iec reserved";
static const char s_stream_type_0x01_name[] = "iso/iec 11172 video";
static const char s_stream_type_0x02_name[] = "iso/iec 13818-2 video";
static const char s_stream_type_0x03_name[] = "iso/iec 11172 audio";
static const char s_stream_type_0x04_name[] = "iso/iec 13818-3 audio";
static const char s_stream_type_0x05_name[] = "iso/iec 13818-1 private section";
static const char s_stream_type_0x06_name[] = "iso/iec 13818-1 pes private";
static const char s_stream_type_0x07_name[] = "iso/iec 13522 mheg";
static const char s_stream_type_0x08_name[] = "iso/iec 13818-1 dsm cc";
static const char s_stream_type_0x09_name[] = "itu-t rec h.222.1";
static const char s_stream_type_0x0a_name[] = "iso/iec 13818-6 type a";
static const char s_stream_type_0x0b_name[] = "iso/iec 13818-6 type b (dsm-cc dc/oc)";
static const char s_stream_type_0x0c_name[] = "iso/iec 13818-6 type c";
static const char s_stream_type_0x0d_name[] = "iso/iec 13818-6 type d";
static const char s_stream_type_0x0e_name[] = "iso/iec 13818-1 auxiliary";
/* added(bruin, 2015-04-22) */
static const char s_stream_type_0x0f_name[] = "aac audio";
static const char s_stream_type_0x11_name[] = "mpeg4 audio";
static const char s_stream_type_0x1b_name[] = "h264 video";
static const char s_stream_type_0x42_name[] = "avs video";
static const char s_stream_type_0x81_name[] = "ac3 audio";
static const char s_stream_type_0x82_name[] = "dts audio";
static const char s_stream_type_user_private[] = "user private";


static const char s_user_defined[] = "user defined";
static const char s_reserved_for_future_use[] = "reserved for future use";


const char* get_pid_name_by_id(u16 pid){

    switch(pid){
        case PID_PAT:
            return s_pat_pid_name;
        case PID_CAT:
            return s_cat_pid_name;
        case PID_NIT:
            return s_nit_pid_name;
        case PID_SDT:
            return s_sdt_bat_pid_name;
        case PID_EIT:
            return s_eit_pid_name;
        case PID_RST:
            return s_rst_pid_name;
        case PID_TDT:
            return s_tdt_tot_pid_name;
        case PID_SIT:
            return s_sit_pid_name;
        case PID_NUL:
            return s_nul_pid_name;
        default:
            return 0;
    }
}

const char* get_tid_name_by_id(u8 table_id){
    switch(table_id){
        case TID_PAT:
            return s_pat_tbl_name;
        case TID_CAT:
            return s_cat_tbl_name;
        case TID_PMT:
            return s_pmt_tbl_name;
        case TID_AIT: /* added(bruin, 2003.01.20) */
            return s_ait_tbl_name;
        case TID_NIT_ACT:
            return s_nit_act_tbl_name;
        case TID_NIT_OTH:
            return s_nit_oth_tbl_name;
        case TID_SDT_ACT:
            return s_sdt_act_tbl_name;
        case TID_SDT_OTH:
            return s_sdt_oth_tbl_name;
        case TID_BAT:
            return s_bat_tbl_name;
        case TID_EIT_ACT:
            return s_eit_act_tbl_name;
        case TID_EIT_OTH:
            return s_eit_oth_tbl_name;
        case TID_EIT_ACT_SCH:
            return s_eit_act_sch_tbl_name;
        case TID_EIT_OTH_SCH:
            return s_eit_oth_sch_tbl_name;
        case TID_TDT:
            return s_tdt_tbl_name;
        case TID_TOT:
            return s_tot_tbl_name;
        case TID_RST:
            return s_rst_tbl_name;
        case TID_ST:
            return s_st_tbl_name;
        default:
            return "";
    }
}

const char* get_rcs_tid_name_by_id(u8 tid){
    switch(tid){
        case 0x41: return s_rmt_tbl_name;
        case 0xa0: return s_sct_tbl_name;
        case 0xa1: return s_fct_tbl_name;
        case 0xa2: return s_tct_tbl_name;
        case 0xa3: return s_spt_tbl_name;
        case 0xa4: return s_cmt_tbl_name;
        case 0xa5: return s_tbtp_tbl_name;
        case 0xa6: return s_rcs_prc_tbl_name;
        case 0xb0: return s_tim_tbl_name;
        default: return "";
    }
}

const char* get_mhp_desc_name_by_id(u8 desc_id){
    switch(desc_id){
        case 0x00:
            return s_mhp_desc_0x00_name;
        case 0x01:
            return s_mhp_desc_0x01_name;   
        case 0x02:
            return s_mhp_desc_0x02_name;
        case 0x03:
            return s_mhp_desc_0x03_name;
        case 0x04:
            return s_mhp_desc_0x04_name;
        case 0x05:
            return s_mhp_desc_0x05_name;
        case 0x06:
            return s_mhp_desc_0x06_name;
        case 0x07:
            return s_mhp_desc_0x07_name;
        case 0x08:
            return s_mhp_desc_0x08_name;
        case 0x09:
            return s_mhp_desc_0x09_name;
        case 0x0a:
            return s_mhp_desc_0x0a_name;
        case 0x0b:
            return s_mhp_desc_0x0b_name;
        case 0x0c:
            return s_mhp_desc_0x0c_name;
        case 0x0d:
            return s_mhp_desc_0x0d_name;
        case 0x0e:
            return s_mhp_desc_0x0e_name;
        case 0x0f:
            return s_mhp_desc_0x0f_name;
            
        case 0x5f:
            return s_mhp_desc_0x5f_name;
        default:
            if(desc_id >= 0x80)
                return s_mhp_desc_name_user_defined;
            else
                return s_mhp_desc_name_reserved_for_future_use;
    }

}

/* added(bruin, 2003.02.17): dvb-rcs */
const char* get_rcs_desc_name_by_id(u8 desc_id){
    switch(desc_id){
        case 0xa0: return s_rcs_desc_0xa0_name;
        case 0xa1: return s_rcs_desc_0xa1_name;
        case 0xa2: return s_rcs_desc_0xa2_name;
        case 0xa3: return s_rcs_desc_0xa3_name;
        case 0xa4: return s_rcs_desc_0xa4_name;
        case 0xa5: return s_rcs_desc_0xa5_name;
        case 0xa6: return s_rcs_desc_0xa6_name;
        case 0xa8: return s_rcs_desc_0xa8_name;
        case 0xa9: return s_rcs_desc_0xa9_name;
        case 0xaa: return s_rcs_desc_0xaa_name;
        case 0xab: return s_rcs_desc_0xab_name;
        case 0xac: return s_rcs_desc_0xac_name;
        default: return s_reserved_for_future_use;
    }
}


const char* get_desc_name_by_id(u8 desc_id){
    switch(desc_id){

        case 0x00:
            return s_desc_0x00_name;
        case 0x01:
            return s_desc_0x01_name;
        case 0x02:
            return s_desc_0x02_name;
        case 0x03:
            return s_desc_0x03_name;
        case 0x04:
            return s_desc_0x04_name;
        case 0x05:
            return s_desc_0x05_name;
        case 0x06:
            return s_desc_0x06_name;
        case 0x07:
            return s_desc_0x07_name;
        case 0x08:
            return s_desc_0x08_name;
        case 0x09:
            return s_desc_0x09_name;
        case 0x0a:
            return s_desc_0x0a_name;
        case 0x0b:
            return s_desc_0x0b_name;
        case 0x0c:
            return s_desc_0x0c_name;
        case 0x0d:
            return s_desc_0x0d_name;
        case 0x0e:
            return s_desc_0x0e_name;
        case 0x0f:
            return s_desc_0x0f_name;
        case 0x10:
            return s_desc_0x10_name;
        case 0x11:
            return s_desc_0x11_name;
        case 0x12:
            return s_desc_0x12_name;
        case 0x13:
            return s_desc_0x13_name;

        case 0x40:
            return s_desc_0x40_name;
        case 0x41:
            return s_desc_0x41_name;
        case 0x42:
            return s_desc_0x42_name;
        case 0x43:
            return s_desc_0x43_name;
        case 0x44:
            return s_desc_0x44_name;
        case 0x45:
            return s_desc_0x45_name;
        case 0x46:
            return s_desc_0x46_name;
        case 0x47:
            return s_desc_0x47_name;
        case 0x48:
            return s_desc_0x48_name;
        case 0x49:
            return s_desc_0x49_name;
        case 0x4a:
            return s_desc_0x4a_name;
        case 0x4b:
            return s_desc_0x4b_name;
        case 0x4c:
            return s_desc_0x4c_name;
        case 0x4d:
            return s_desc_0x4d_name;
        case 0x4e:
            return s_desc_0x4e_name;
        case 0x4f:
            return s_desc_0x4f_name;

        case 0x50:
            return s_desc_0x50_name;
        case 0x51:
            return s_desc_0x51_name;
        case 0x52:
            return s_desc_0x52_name;
        case 0x53:
            return s_desc_0x53_name;
        case 0x54:
            return s_desc_0x54_name;
        case 0x55:
            return s_desc_0x55_name;
        case 0x56:
            return s_desc_0x56_name;
        case 0x57:
            return s_desc_0x57_name;
        case 0x58:
            return s_desc_0x58_name;
        case 0x59:
            return s_desc_0x59_name;
        case 0x5a:
            return s_desc_0x5a_name;
        case 0x5b:
            return s_desc_0x5b_name;
        case 0x5c:
            return s_desc_0x5c_name;
        case 0x5d:
            return s_desc_0x5d_name;
        case 0x5e:
            return s_desc_0x5e_name;
        case 0x5f:
            return s_desc_0x5f_name;

        case 0x60:
            return s_desc_0x60_name;
        case 0x61:
            return s_desc_0x61_name;
        case 0x62:
            return s_desc_0x62_name;
        case 0x63:
            return s_desc_0x63_name;
        case 0x64:
            return s_desc_0x64_name;
        case 0x65:
            return s_desc_0x65_name;
        case 0x66:
            return s_desc_0x66_name;
        case 0x67:
            return s_desc_0x67_name;
        case 0x68:
            return s_desc_0x68_name;
        case 0x69:
            return s_desc_0x69_name;
        case 0x6a:
            return s_desc_0x6a_name;
        case 0x6b:
            return s_desc_0x6b_name;
        case 0x6c:
            return s_desc_0x6c_name;
        case 0x6d:
            return s_desc_0x6d_name;
        case 0x6e:
            return s_desc_0x6e_name;

        /* opentv private */
        case 0x90:
            return s_desc_0x90_name;
        case 0xfe:
            return s_desc_0xfe_name;

        /* added(bruin, 2003.01.15) */
        case 0x6f:
            return s_desc_0x6f_name;
        case 0x71:
            return s_desc_0x71_name;


        /* added(bruin, 2003.02.17): rcs */
        case 0xa7:
            return s_desc_0xa7_name;

		/* added(bruin, 2003.12.19): LCN draft */
		case 0x83:
			return s_desc_0x83_name;
            
        case 0xff:
            return 0;

        default:
            return s_desc_0x00_name; /* reserved */
    }
}

const char* get_stream_type_name_by_id(u8 type_id){

    switch(type_id){
        case STREAMTYPE_11172_VIDEO:
            return s_stream_type_0x01_name;
        case STREAMTYPE_13818_VIDEO:
            return s_stream_type_0x02_name;
        case STREAMTYPE_11172_AUDIO:
            return s_stream_type_0x03_name;
        case STREAMTYPE_13818_AUDIO:
            return s_stream_type_0x04_name;
        case STREAMTYPE_13818_PRIVATE:
            return s_stream_type_0x05_name;
        case STREAMTYPE_13818_PES_PRIVATE:
            return s_stream_type_0x06_name;
        case STREAMTYPE_13522_MHPEG:
            return s_stream_type_0x07_name;
        case STREAMTYPE_13818_DSMCC:
            return s_stream_type_0x08_name;
        case STREAMTYPE_ITU_222_1:
            return s_stream_type_0x09_name;
        case STREAMTYPE_13818_A:
            return s_stream_type_0x0a_name;
        case STREAMTYPE_13818_B:
            return s_stream_type_0x0b_name;
        case STREAMTYPE_13818_C:
            return s_stream_type_0x0c_name;
        case STREAMTYPE_13818_D:
            return s_stream_type_0x0d_name;
        case STREAMTYPE_13818_AUX:
            return s_stream_type_0x0e_name;
        /* added(bruin, 2015-04-22) */
        case STREAMTYPE_AAC_AUDIO:
            return s_stream_type_0x0f_name;
        case STREAMTYPE_MPEG4_AUDIO:
            return s_stream_type_0x11_name;
        case STREAMTYPE_H264_VIDEO:
            return s_stream_type_0x1b_name;
        case STREAMTYPE_AVS_VIDEO:
            return s_stream_type_0x42_name;
        case STREAMTYPE_AC3_AUDIO:
            return s_stream_type_0x81_name;
        case STREAMTYPE_DTS_AUDIO:
            return s_stream_type_0x82_name;
        default:
            if(type_id == 0 || (type_id >= 0x0f && type_id <= 0x7f))
                return s_stream_type_0x00_name; /* reserved */
            else
                return s_stream_type_user_private;
    }

    return 0;
}



/* return:
    > 0x1ffff(PID_NUL): error
    others: valid pids
*/
u16 get_pid_of_tid(u8 tid){

    int pid;

    // table id for EIT-S is a range...so handle it specially here
    if (tid >= TID_EIT_ACT_SCH && tid <= TID_EIT_OTH_SCH_LAST) {
        return PID_EIT;
    }
    
    switch(tid){

        case TID_PAT:
            pid = PID_PAT;
            break;
        
        case TID_CAT:
            pid = PID_CAT;
            break;
        
        case TID_NIT_ACT:
        case TID_NIT_OTH:
            pid = PID_NIT;
            break;
        
        case TID_SDT_ACT:
        case TID_SDT_OTH:
        case TID_BAT:
            pid = PID_SDT;
            break;
        
        case TID_EIT_ACT:
        case TID_EIT_OTH:
            pid = PID_EIT;
            break;
        
        case TID_TDT:
        case TID_TOT:
            pid = PID_TDT;
            break;
        
        case TID_RST:
            pid = PID_RST;
            break;

        case TID_PMT:    /* PIDs for these tables are not unique from tid */
        case TID_AIT:
        case TID_DSM_CC_UNM:
        case TID_DSM_CC_DDM:
        default:
            pid = PID_NUL + 1;
            break;
    }

    return pid;
}


int get_minimum_section_size_by_tid(u8 tid)
{
    switch(tid){
        case TID_SDT_ACT:
        case TID_SDT_OTH:
            return (PRIVATE_SECT_HEADER_LEN + 2);
            
         case TID_EIT_ACT:
         case TID_EIT_OTH:
         case TID_EIT_ACT_SCH:
         case TID_EIT_OTH_SCH:
             return (PRIVATE_SECT_HEADER_LEN + 4);

         case TID_PAT: 
         case TID_CAT:
         case TID_PMT:
         case TID_TDT:
         case TID_TOT:
         case TID_RST: // to be checked
         case TID_AIT:
         case TID_DSM_CC_UNM:
         case TID_DSM_CC_DDM:
         case TID_NIT_ACT:
         case TID_NIT_OTH:
         case TID_BAT:
         default:
                return PRIVATE_SECT_HEADER_LEN;
    }
}



const char* get_frame_rate_by_code(u8 code){ 
    
    switch(code & 0x0f){ /* the less significant 4 bits are code */ 
        case 0:
            return "forbidden";
        case 1:
            return "23.976 fps";
        case 2:
            return "24 fps";
        case 3:
            return "25 fps";
        case 4:
            return "29.97 fps";
        case 5:
            return "30 fps";
        case 6:
            return "50 fps";
        case 7:
            return "59.94 fps";
        case 8:
            return "60 fps";
        default:
            return "reserved";
    }
}

const char* get_chroma_format_by_code(u8 code){

    switch(code & 0x03){ /* the less significant 2 bits are code */ 
        case 0:
            return "forbidden";
        case 1:
            return "4:2:0";
        case 2:
            return "4:2:2";
        case 3:
            return "4:4:4";
    }
    return 0; /* prevent compiler warning */
}

/* "code" is 8 bits profile_and_level_indication */
const char* get_video_profile_by_code(u8 code){

    switch((code & 0x7f) >> 4){ /* 6,5,4 are the 3 bits for the profile code */
        case 0:
            return "reserved profile";
        case 1:
            return "high profile";
        case 2:
            return "spatially scalable profile";
        case 3:
            return "snr scalable profile";
        case 4:
            return "main profile";
        case 5:
            return "simple profile";
    }

    return 0; /* prevent compiler warning */
}

/* "code" is 8 bits profile_and_level_indication */
const char* get_video_level_by_code(u8 code){

    switch(code & 0x0f){ 
        case 4:
            return "high level";
        case 6:
            return "high 1440 level";
        case 8:
            return "main level";
        case 10:
            return "low level";
        default:
            return "reserved level";
    }

    return 0; /* prevent compiler warning */
}

const char* get_audio_type_by_code(u8 code){
    switch(code){
        case 1:
            return "clean effects";
        case 2:
            return "hearing impaired";
        case 3:
            return "visual_impaired_commentary";
        default:
            return "reserved";
    }
    return 0; /* prevent compiler warning */
}

const char* get_aspect_ratio_information_by_code(u8 code){
    switch(code){
        case 0:
            return "forbidden";
        case 1:
            return "sample aspect ratio(SAR) 1.0";
        case 2:
            return "display aspect ration(DAR) 3:4";
        case 3:
            return "display aspect ration(DAR) 9:16";
        case 4:
            return "display aspect ration(DAR) 1:2.21";
        default:
            return "reserved";
    }
    return 0; /* prevent compiler warning */
}


char* get_string_by_utc_time(u8 utc_time[5]){

    static char string[32];

    float mjd;
    int y, m, d, k;

    mjd = (float)(utc_time[0] * 256 + utc_time[1]);
    y = (int)((mjd - 15078.2) / 365.25);
    m = (int)((mjd -14956.1 - (int)(y * 365.25)) / 30.6001);
    d = (int)(mjd - 14956 - (int)(y * 365.25) - (int)(m * 30.6001));
    if(m == 14 || m == 15)
        k = 1;
    else 
        k = 0;
    y += k;
    m = m - 1 - k * 12;

    snprintf(string, 32, "%4d/%02d/%02d %02x:%02x:%02x", y + 1900, m, d, utc_time[2], utc_time[3], utc_time[4]);

    return string;
}

const char* get_running_status_by_code(u8 code){

    switch(code){
        case 0:
            return "undefined";
        case 1:
            return "not running";
        case 2:
            return "starts in a few seconds";
        case 3:
            return "pausing";
        case 4:
            return "running";
        default:
            return "reserved";
    }

    return 0; /* prevent compiler warning */    
}

const char* get_outer_fec_scheme_by_code(u8 code){
    switch(code){
        case 0:
            return "not defined";
        case 1:
            return "no outer fec coding";
        case 2:
            return "rs(204/188)";
        default:
            return "reserved";
    }
    return 0; /* prevent compiler warning */    
}
const char* get_inner_fec_scheme_by_code(u8 code){
    switch(code){
        case 0:
            return "not defined";
        case 1:
            return "1/2 conv. code rate";
        case 2:
            return "2/3 conv. code rate";
        case 3:
            return "3/4 conv. code rate";
        case 4:
            return "5/6 conv. code rate";
        case 5:
            return "7/8 conv. code rate";
        case 0xf:
            return "no conv. coding";
        default:
            return "reserved";
    }
    return 0; /* prevent compiler warning */    
}
const char* get_cable_modulation_scheme_by_code(u8 code){
    switch(code){
        case 0:
            return "not defined";
        case 1:
            return "16 QAM";
        case 2:
            return "32 QAM";
        case 3:
            return "64 QAM";
        case 4:
            return "128 QAM";
        case 5:
            return "256 QAM";
        default:
            return "reserved";
    }
    return 0; /* prevent compiler warning */    
}

const char* get_polariztion_by_code(u8 code){
    switch(code){
        case 0:
            return "linear-horizontal";
        case 1:
            return "linear-vertical";
        case 2:
            return "circular-left";
        case 3:
            return "circular-right";
    }
    return 0; /* prevent compiler warning */    
}

const char* get_satellite_modulation_scheme_by_code(u8 code){
    switch(code){
        case 0:
            return "not defined";
        case 1:
            return "QPSK";
        default:
            return "reserved";
    }
    return 0; /* prevent compiler warning */    
}

const char* get_service_type_by_code(u8 code){
    switch(code){
        case 0:
            return "reserved";
        case 1:
            return "digital television service";
        case 2:
            return "digital radio sound service";
        case 3:
            return "teletext service";
        case 4:
            return "nvod reference service";
        case 5:
            return "nvod time-shifted service";
        case 6:
            return "mosaic service";
        case 7:
            return "pal coded signal";
        case 8:
            return "secam coded signal";
        case 9:
            return "d/d2-mac";
        case 0x0a:
            return "FM radio";
        case 0x0b:
            return "ntsc coded signal";
        case 0x0c:
            return "data broadcast service";
        case 0x0d:
            return "reserved for common interface usage";
        case 0x0e:
            return "rcs map";
        case 0x0f:
            return "rcs fls";
        case 0x10:
            return "dvb mhp service";
        default:
            return "reserved or user defined";
    }
    return 0; /* prevent compiler warning */    
}


/* added(bruin, 2003.01.13): mhp 1.1 AIT */
const char* get_application_type_by_code(u16 type){
    switch(type){
        case 0x0000:
            return "reserved";
        case 0x0001:
            return "dvb-j application";
        case 0x0002:
            return "dvb-html application";
        default:
            return "subject to registration with dvb";
    }
}

/* added(bruin, 2003.01.13) */
const char* get_application_control_code_name(u16 application_type, u8 control_code){
    switch(application_type){
        case 0x0001: /* dvb-j */
            switch(control_code){
                case 0x00:
                    return "dvb-j: reserved";
                case 0x01:
                    return "dvb-j: autostart";
                case 0x02:
                    return "dvb-j: present";
                case 0x03:
                    return "dvb-j: destroy";
                case 0x04:
                    return "dvb-j: kill";
                case 0x05:
                    return "dvb-j: reserved";
                case 0x06:
                    return "dvb-j: remote";
                default:
                    return "dvb-j: reserved for future use";
            }
            break;
        case 0x0002: /* dvb-html */
            switch(control_code){
                case 0x00:
                    return "dvb-html: reserved";
                case 0x01:
                    return "dvb-html: autostart";
                case 0x02:
                    return "dvb-html: present";
                case 0x03:
                    return "dvb-html: destroy";
                case 0x04:
                    return "dvb-html: kill";
                case 0x05:
                    return "dvb-html: prefetch";
                case 0x06:
                    return "dvb-html: remote";
                default:
                    return "dvb-html: reserved for future use";
            }
            break;
        default:
            return "unknown application type";
        }
}

const char* get_linkage_type_by_code(u8 code){
    switch(code){
        case 0x00:
            return "reserved for future use";
        case 0x01:
            return "information service";
        case 0x02:
            return "epg service";
        case 0x03:
            return "ca replacement service";
        case 0x04:
            return "ts containing complete network/bouquet si";
        case 0x05:
            return "service replacement service";
        case 0x06:
            return "data broadcast service";
        case 0x07:
            return "rcs map";
        case 0x08:
            return "mobile hand-over";
        default:
            if(code >= 0x80 && code <= 0xfe)
                return "user defined";
            else
                return "reserved for future use";
    }
}

const char* get_hand_over_type_by_code(u8 code){
    switch(code){
        case 0x01:
            return "dvb hand-over to an identical service in a neighbouring country";
        case 0x02:
            return "dvb hand-over to an local variation of the same service";
        case 0x03:
            return "dvb hand-over to an associated service";
        default:
            return "reserved for future use";
    }
}

const char* get_content_nibble_name_by_code(u8 code, int is_level_1){

    u8 level_1, level_2;
    
    level_1 = code >> 4;
    level_2 = code & 0x0f;
    
    switch(level_1){
        case 0x00:
            return "undefined content";
            
        case 0x01:
            if(is_level_1){
                return "movie/drama";
            }
            else{
                switch(level_2){
                    case 0x00:  return "movie/drama (general)";
                    case 0x01:  return "detective/thriller";
                    case 0x02:  return "adventure/western/war";
                    case 0x03:  return "science fiction/fantasy/horror";
                    case 0x04:  return "comedy";
                    case 0x05:  return "soap/melodrama/folkloric";
                    case 0x06:  return "romance";
                    case 0x07:  return "serious/classical/religious/historical movie/drama";
                    case 0x08:  return "adult movie/drama";
                    case 0x09:  
                    case 0x0a:  
                    case 0x0b:  
                    case 0x0c:  
                    case 0x0d:  
                    case 0x0e:  return s_reserved_for_future_use;
                    case 0x0f:  return s_user_defined;
                }
            }
            break;
            
        case 0x02:
            if(is_level_1){
                return "news/current affairs";
            }
            else{
                switch(level_2){
                    case 0x00:  return "news/current affairs (general)";
                    case 0x01:  return "news/weather report";
                    case 0x02:  return "news magazine";
                    case 0x03:  return "documentary";
                    case 0x04:  return "discussion/interview/debate";
                    case 0x05:
                    case 0x06:
                    case 0x07:
                    case 0x08:
                    case 0x09:
                    case 0x0a:
                    case 0x0b:
                    case 0x0c:
                    case 0x0d:
                    case 0x0e:  return s_reserved_for_future_use;
                    case 0x0f:  return s_user_defined;
                }
            }
            break;
            

        case 0x03:
            if(is_level_1){
                return "show/game show";
            }
            else{
                switch(level_2){
                    case 0x00:  return "show/game show (general)";
                    case 0x01:  return "game show/quiz/contest";
                    case 0x02:  return "variety show";
                    case 0x03:  return "talk show";
                    case 0x04:
                    case 0x05:
                    case 0x06:
                    case 0x07:
                    case 0x08:
                    case 0x09:
                    case 0x0a:
                    case 0x0b:
                    case 0x0c:
                    case 0x0d:
                    case 0x0e:  return s_reserved_for_future_use;
                    case 0x0f:  return s_user_defined;
                }
            }
            break;
            

        case 0x04:
            if(is_level_1){
                return "sports";
            }
            else{
                switch(level_2){
                    case 0x00:  return "sports (general)";
                    case 0x01:  return "special events (olympic games, world cup, etc)";
                    case 0x02:  return "sports magazine";
                    case 0x03:  return "football/soccer";
                    case 0x04:  return "tennis/squash";
                    case 0x05:  return "team sports (exculding football)";
                    case 0x06:  return "athletics";
                    case 0x07:  return "motor sport";
                    case 0x08:  return "water sport";
                    case 0x09:  return "winter sports";
                    case 0x0a:  return "equestrain";
                    case 0x0b:  return "martial sports";
                    case 0x0c:
                    case 0x0d:
                    case 0x0e:  return s_reserved_for_future_use;
                    case 0x0f:  return s_user_defined;
                }
            }
            break;
            

        case 0x05:
            if(is_level_1){
                return "children's/younth programmes";
            }
            else{
                switch(level_2){
                    case 0x00:  return "children's/youth programmes (general)";
                    case 0x01:  return "pre-school children's programmes";
                    case 0x02:  return "entertainment programmes for 6 to 14";
                    case 0x03:  return "entertainment programmes for 10 to 16";
                    case 0x04:  return "informational/educational/school programmes";
                    case 0x05:  return "cartoons/puppets";
                    case 0x06:
                    case 0x07:
                    case 0x08:
                    case 0x09:
                    case 0x0a:
                    case 0x0b:
                    case 0x0c:
                    case 0x0d:
                    case 0x0e:  return s_reserved_for_future_use;
                    case 0x0f:  return s_user_defined;
                }
            }
            break;
            

        case 0x06:
            if(is_level_1){
                return "music/ballet/dance";
            }
            else{
                switch(level_2){
                    case 0x00:  return "music/ballet/dance (general)";
                    case 0x01:  return "rock/pop";
                    case 0x02:  return "serious music/classical music";
                    case 0x03:  return "folk/traditional music";
                    case 0x04:  return "jazz";
                    case 0x05:  return "musical/opera";
                    case 0x06:  return "ballet";
                    case 0x07:
                    case 0x08:
                    case 0x09:
                    case 0x0a:
                    case 0x0b:
                    case 0x0c:
                    case 0x0d:
                    case 0x0e:  return s_reserved_for_future_use;
                    case 0x0f:  return s_user_defined;
                }
            }
            break;
            

        case 0x07:
            if(is_level_1){
                return "arts/culture (without music)";
            }
            else{
                switch(level_2){
                    case 0x00:  return "arts/culture (without music, general)";
                    case 0x01:  return "performing arts";
                    case 0x02:  return "fine arts";
                    case 0x03:  return "religion";
                    case 0x04:  return "popular culture/traditional arts";
                    case 0x05:  return "literature";
                    case 0x06:  return "film/cinema";
                    case 0x07:  return "experimental file/video";
                    case 0x08:  return "broadcasting/press";
                    case 0x09:  return "new media";
                    case 0x0a:  return "arts/culture magazine";
                    case 0x0b:  return "fashion";
                    case 0x0c:
                    case 0x0d:
                    case 0x0e:  return s_reserved_for_future_use;
                    case 0x0f:  return s_user_defined;
                }
            }
            break;
            

        case 0x08:
            if(is_level_1){
                return "social/political issues/economics";
            }
            else{
                switch(level_2){
                    case 0x00:  return "social/political issues/economics (general)";
                    case 0x01:  return "magazines/reports/documentary";
                    case 0x02:  return "economics/social advisory";
                    case 0x03:  return "remarkable people";
                    case 0x04:
                    case 0x05:
                    case 0x06:
                    case 0x07:
                    case 0x08:
                    case 0x09:
                    case 0x0a:
                    case 0x0b:
                    case 0x0c:
                    case 0x0d:
                    case 0x0e:  return s_reserved_for_future_use;
                    case 0x0f:  return s_user_defined;
                }
            }
            break;
            

        case 0x09:
            if(is_level_1){
                return "children's/youth programmes: educational/science/factual topics";
            }
            else{
                switch(level_2){
                    case 0x00:  return "educational/science/factual topics (general)";
                    case 0x01:  return "nature/animals/environment";
                    case 0x02:  return "technology/natural sciences";
                    case 0x03:  return "medicine/physiology/psychology";
                    case 0x04:  return "foreign countries/expeditions";
                    case 0x05:  return "social/spiritual sciences";
                    case 0x06:  return "further education";
                    case 0x07:  return "languages";
                    case 0x08:
                    case 0x09:
                    case 0x0a:
                    case 0x0b:
                    case 0x0c:
                    case 0x0d:
                    case 0x0e:  return s_reserved_for_future_use;
                    case 0x0f:  return s_user_defined;
                }
            }
            break;
            

        case 0x0a:
            if(is_level_1){
                return "leisure hobbies";
            }
            else{
                switch(level_2){
                    case 0x00:  return "leisure hobbies (general)";
                    case 0x01:  return "tourism/travel";
                    case 0x02:  return "handicraft";
                    case 0x03:  return "motoring";
                    case 0x04:  return "fitness/health";
                    case 0x05:  return "cooking";
                    case 0x06:  return "advertisement/shopping";
                    case 0x07:  return "gardening";
                    case 0x08:
                    case 0x09:
                    case 0x0a:
                    case 0x0b:
                    case 0x0c:
                    case 0x0d:
                    case 0x0e:  return s_reserved_for_future_use;
                    case 0x0f:  return s_user_defined;
                }
            }
            break;
            

        case 0x0b:
            if(is_level_1){
                return "special characteristics";
            }
            else{
                switch(level_2){
                    case 0x00:  return "original language";
                    case 0x01:  return "black & white";
                    case 0x02:  return "unpublished";
                    case 0x03:  return "live broadcast";
                    case 0x04:
                    case 0x05:
                    case 0x06:
                    case 0x07:
                    case 0x08:
                    case 0x09:
                    case 0x0a:
                    case 0x0b:
                    case 0x0c:
                    case 0x0d:
                    case 0x0e:  return s_reserved_for_future_use;
                    case 0x0f:  return s_user_defined;
                }
            }
            break;
            

        case 0x0c:
        case 0x0d:
        case 0x0e:
            return s_reserved_for_future_use;
            
        case 0x0f:
            return s_user_defined;
    }

	return NULL; /* error occurred */
}


const char* get_minimum_age_by_rating(u8 rating){
    switch(rating){
        case 0x00:  return "undefined";
        case 0x01:  return "minimum age 4";
        case 0x02:  return "minimum age 5";
        case 0x03:  return "minimum age 6";
        case 0x04:  return "minimum age 7";
        case 0x05:  return "minimum age 8";
        case 0x06:  return "minimum age 9";
        case 0x07:  return "minimum age 10";
        case 0x08:  return "minimum age 11";
        case 0x09:  return "minimum age 12";
        case 0x0a:  return "minimum age 13";
        case 0x0b:  return "minimum age 14";
        case 0x0c:  return "minimum age 15";
        case 0x0d:  return "minimum age 16";
        case 0x0e:  return "minimum age 17";
        case 0x0f:  return "minimum age 18";
        default:    return "defined by the broadcaster";
    }
}

const char* get_application_id_name_by_id(u16 id){
    if(id < 0x4000){
        return "unsigned application";
    }
    else if(id < 0x8000){
        return "signed application";
    }
    else if(id < 0xfffe){
        return "reserved for future use by dvb";
    }
    else if(id == 0xfffe){
        return "special wildcard value for signed application of an organization";
    }
    else{ /* 0xffff */
        return "special wildcard value for all application of an organization";
    }
}

const char* get_transport_protocol_id_name_by_id(u16 id){
    switch(id){
        case 0x0000:
            return "reserved";
        case 0x0001:
            return "mhp object carousel";
        case 0x0002:
            return "ip via dvb multiprotocol encapsulation";
        case 0x0003:
            return "transport via http over the interaction channel";
        default:
            if(id < 0x0100)
                return "reserved for use by dvb";
            else
                return "subject to registration in ETR 162";
    }
}

/* added(bruin, 2003.12.19): terrestrial_delivery_system_descriptor */
const char* get_terrestrial_bandwidth_by_code(u8 code){
	switch(code){
		case 0:
			return "8mhz";
		case 1:
			return "7mhz";
		case 2:
			return "6mhz";
		default:
			return "reserved for future use";
	}
}

const char* get_terrestrial_constellation_pattern_by_code(u8 code){
	switch(code){
		case 0:
			return "QPSK";
		case 1:
			return "16-QAM";
		case 2:
			return "64-QAM";
		default:
			return "reserved for future use";
	}
}

const char* get_terrestrial_hierarchy_information_by_code(u8 code){
	switch(code){
		case 0:
			return "non-hierarchy";
		case 1:
			return "alpha=1";
		case 2:
			return "alpha=2";
		case 3:
			return "alpha=4";
		default:
			return "reserved for future use";
	}
}

const char* get_terrestrial_code_rate_by_code(u8 code){
	switch(code){
		case 0:
			return "1/2";
		case 1:
			return "2/3";
		case 2:
			return "3/4";
		case 3:
			return "5/6";
		case 4:
			return "7/8";
		default:
			return "reserved for future use";
	}
}

const char* get_terrestrial_guard_interval_by_code(u8 code){
	switch(code){
		case 0:
			return "1/32";
		case 1:
			return "1/16";
		case 2:
			return "1/8";
		case 3:
			return "1/4";
		default:
			return NULL; /* error occurred */	
	}
}

const char* get_terrestrial_transmission_mode_by_code(u8 code){
	switch(code){
		case 0:
			return "2k mode";
		case 1:
			return "8k mode";
		default:
			return "reserved for future use";
	}
}
