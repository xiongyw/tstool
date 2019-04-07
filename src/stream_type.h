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
 * created(bruin, 2015/05/19): stream type allocation
 */

#ifndef __STREAM_TYPE_H__
#define __STREAM_TYPE_H__

// 0x00-0x09 ITU-T Rec. H.222.0 | ISO/IEC 13818-1 defined
/*** iso/iec 13818-1 table 2-36 ***/
#define STREAMTYPE_11172_VIDEO                  0x01
#define STREAMTYPE_13818_VIDEO                  0x02
#define STREAMTYPE_11172_AUDIO                  0x03
#define STREAMTYPE_13818_AUDIO                  0x04
#define STREAMTYPE_13818_PRIVATE                0x05
#define STREAMTYPE_13818_PES_PRIVATE            0x06
#define STREAMTYPE_13522_MHPEG                  0x07
#define STREAMTYPE_13818_DSMCC                  0x08
#define STREAMTYPE_ITU_222_1                    0x09

// ISO/IEC 13818-6:1998(E): Table 9-4 DSM-CC Stream Types
#define STREAMTYPE_13818_A                      0x0a // DSM-CC Multi-protocol Encapsulation
#define STREAMTYPE_13818_B                      0x0b // DSM-CC U-N Msg (DC/OC stream): http://www.interactivetvweb.org/tutorials/dtv_intro/dsmcc/service_information
#define STREAMTYPE_13818_C                      0x0c // DSM-CC Stream Descriptors
#define STREAMTYPE_13818_D                      0x0d // DSM-CC Sections (any type, including private data)

// 0x0E - 0x7F ITU-T Rec. H.222.0 | ISO/IEC 13818-1 reserved
#define STREAMTYPE_13818_AUX                    0x0e
#define STREAMTYPE_AAC_AUDIO                    0x0f
#define STREAMTYPE_MPEG4_AUDIO                  0x11
#define STREAMTYPE_H264_VIDEO                   0x1b
#define STREAMTYPE_AVS_VIDEO                    0x42

//0x80 - 0xFF User private
#define STREAMTYPE_AC3_AUDIO                    0x81
#define STREAMTYPE_DTS_AUDIO                    0x82


#endif // __STREAM_TYPE_H__
