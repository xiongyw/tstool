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
 * created(bruin, 2015/05/19): descriptor id allocation
 */

#ifndef __DESC_ID_H__
#define __DESC_ID_H__

/* iso/iec 13818-1 */
/* 0x00, 0x01, 0x19-0x3f are reserved */
#define DESC_VIDEO_STREAM                       0x02
#define DESC_AUDIO_STREAM                       0x03
#define DESC_HIERARCHY                          0x04
#define DESC_REGISTRATION                       0x05
#define DESC_DATA_STREAM_ALIGNMENT              0x06
#define DESC_TARGET_BACKGROUND_GRID             0x07
#define DESC_VIDEO_WINDOW                       0x08
#define DESC_CA                                 0x09
#define DESC_ISO_639_LANGUAGE                   0x0A
#define DESC_SYSTEM_CLOCK                       0x0B
#define DESC_MULTIPLEX_BUFFER_UTILIZATION       0x0C
#define DESC_COPYRIGHT                          0x0D
#define DESC_MAXIMUM_BITRATE                    0x0E
#define DESC_PRIVATE_DATA_INDICATOR             0x0F
#define DESC_SMOOTHING_BUFFER                   0x10
#define DESC_STD                                0x11
#define DESC_IBP                                0x12
#define DESC_CAROUSEL_IDENTIFIER                0x13 // 2015-05-13

/* dvb-si */
#define DESC_NETWORK_NAME                       0x40
#define DESC_SERVICE_LIST                       0x41
#define DESC_STUFFING                           0x42
#define DESC_SATELLITE_DELIVERY_SYSTEM          0x43
#define DESC_CABLE_DELIVERY_SYSTEM              0x44
#define DESC_VBI_DATA                           0x45
#define DESC_VBI_TELETEXT                       0x46
#define DESC_BOUQUET_NAME                       0x47
#define DESC_SERVICE                            0x48
#define DESC_COUNTRY_AVAILABILITY               0x49
#define DESC_LINKAGE                            0x4a
#define DESC_NVOD_REFERENCE                     0x4b
#define DESC_TIME_SHIFTED_SERVICE               0x4c
#define DESC_SHORT_EVENT                        0x4d
#define DESC_EXTENDED_EVENT                     0x4e
#define DESC_TIME_SHIFTED_EVENT                 0x4f
#define DESC_COMPONENT                          0x50
#define DESC_MOSAIC                             0x51
#define DESC_STREAM_IDENTIFIER                  0x52
#define DESC_CA_IDENTIFIER                      0x53
#define DESC_CONTENT                            0x54
#define DESC_PARENTAL_RATING                    0x55
#define DESC_TELETEXT                           0x56
#define DESC_TELEPHONE                          0x57
#define DESC_LOCAL_TIME_OFFSET                  0x58
#define DESC_SUBTITLING                         0x59
#define DESC_TERRESTRIAL_DELIVERY_SYSTEM        0x5a
#define DESC_MULTILINGUAL_NETWORK_NAME          0x5b
#define DESC_MULTILINGUAL_BOUQUET_NAME          0x5c
#define DESC_MULTILINGUAL_SERVICE_NAME          0x5d
#define DESC_MULTILINGUAL_COMPONENT             0x5e
#define DESC_PRIVATE_DATA_SPECIFIER             0x5f
#define DESC_SERVICE_MOVE                       0x60
#define DESC_SHORT_SMOOTHING_BUFFER             0x61
#define DESC_FREQUENCY_LIST                     0x62
#define DESC_PARTIAL_TRANSPORT_STREAM           0x63
#define DESC_DATA_BROADCAST                     0x64
#define DESC_CA_SYSTEM                          0x65
#define DESC_DATA_BROADCAST_ID                  0x66
#define DESC_TRANSPORT_STREAM                   0x67
#define DESC_DSNG                               0x68
#define DESC_PDC                                0x69
#define DESC_AC_3                               0x6a
#define DESC_ANCILLARY_DATA                     0x6b
#define DESC_CELL_LIST                          0x6c
#define DESC_CELL_FREQUENCY_LINK                0x6d
#define DESC_ANNOUNCEMENT_SUPPORT               0x6e

/* 0x6f - 0x7f are reserved */
/* 0x80 - 0xfe are user defined */
/* 0xff is forbidden */

/* opentv private descriptors */
#define DESC_OPENTV_MODULE_TRACK                0x90
#define DESC_OPENTV_TRACK_TAG                   0xfe

#define DESC_APPLICATION_SIGNALLING             0x6f  /* 2003.01.13: mhp 1.1 table 107 */
#define DESC_SERVICE_IDENTIFIER                 0x71  /* 2003.01.21: mhp 1.1 table 107 */

#define DESC_LOGICAL_CHANNEL                    0x83  /* 2003.12.18: LCN draft from <CSevior@nine.com.au> */

/* ait local descriptors: mhp1.1, table 107 "registry of constant values" */
#define MHP_DESC_APPLICATION                    0x00
#define MHP_DESC_APPLICATION_NAME               0x01
#define MHP_DESC_TRANSPORT_PROTOCOL             0x02
#define MHP_DESC_DVB_J_APPLICATION              0x03
#define MHP_DESC_DVB_J_APPLICATION_LOCATION     0x04
#define MHP_DESC_EXTERNAL_APPLICATION_AUTHORIZATION 0x05
#define MHP_DESC_IPV4_ROUTING                   0x06
#define MHP_DESC_IPV6_ROUTING                   0x07
#define MHP_DESC_DVB_HTML_APPLICATION           0x08
#define MHP_DESC_DVB_HTML_APPLICATION_LOCATION  0x09
#define MHP_DESC_DVB_HTML_APPLICATION_BOUNDARY  0x0a
#define MHP_DESC_APPLICATION_ICONS              0x0b
#define MHP_DESC_PREFETCH                       0x0c
#define MHP_DESC_DLL_LOCATION                   0x0d
#define MHP_DESC_DELEGATED_APPLICATION          0x0e
#define MHP_DESC_PLUG_IN                        0x0f
/* 0x10-0x5e: reserved to mhp futuer use */
#define MHP_DESC_PRIVATE_DATA_SPECIFIER         0x5f
/* 0x60-0x7f: reserved to mhp futuer use */
/* 0x80-0xfe: user defined               */



/* added(bruin, 2003.02.17): dvb-rcs descriptors (ETSI EN 301 790 v1.2.2 table 29) */
#define DESC_NETWORK_LAYER_INFO                 0xa0
#define DESC_CORRECTION_MESSAGE                 0xa1
#define DESC_LOGON_INITIALIZE                   0xa2
#define DESC_ACQ_ASSIGN                         0xa3
#define DESC_SYNC_ASSIGN                        0xa4
#define DESC_ENCRYPTED_LOGON_ID                 0xa5
#define DESC_ECHO_VALUE                         0xa6
/* #define DESC_LINKAGE                         0x4a */ /* private extension to existing dvb descriptor */
#define DESC_RCS_CONTENT                        0xa7    /* in PMT */
#define DESC_SATELLITE_FORWARD_LINK             0xa8
#define DESC_SATELLITE_RETURN_LINK              0xa9
#define DESC_TABLE_UPDATE                       0xaa
#define DESC_CONTENTION_CONTROL                 0xab
#define DESC_CORRECTION_CONTROL                 0xac



#endif // __DESC_ID_H__
