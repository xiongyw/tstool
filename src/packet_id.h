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
 * created(bruin, 2015/05/19): packet id allocation
 */

#ifndef __PACKET_ID_H__
#define __PACKET_ID_H__

/*** DVB A038 rev,1, May 2000 ***/

/* packet id allocation for SI tables(totally 13):
   4 PSI tables: PAT/CAT/PMT/NIT
   9 SI tables: BAT/SDT/EIT/RST/TDT/TOT/ST/SIT/DIT

   while pid for PMTs are not static, they are specified in PAT;

   noted(bruin, 2003.01.19): for mhp 1.1, we have anther table AIT, whose 
   pid is also not static, but specified in PMT.
   
   pid is a 13-bit nr, with the maximum value 0x1fff for NULL packets 
 */
 
#define PID_PAT                                 0x0000
#define PID_CAT                                 0x0001
#define PID_TSDT                                0x0002
                                                /* 0x0003 to 0x000f: reserved */
#define PID_NIT                                 0x0010
#define PID_SDT                                 0x0011
#define PID_BAT                                 0x0011
#define PID_EIT                                 0x0012
#define PID_RST                                 0x0013
#define PID_TDT                                 0x0014
#define PID_TOT                                 0x0014
                                                /* 0x0015: network synchronization */
                                                /* 0x0016 to 0x001b: reserved */
                                                /* 0x001c: inband signalling (note: sis-12) */
                                                /* 0x001d: measurement (note: sis-10) */
#define PID_DIT                                 0x001e
#define PID_SIT                                 0x001f
#define PID_NUL                                 0x1fff


#endif // __PACKET_ID_H__
