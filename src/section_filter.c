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
#include "si.h"
#include "section_filter.h"


/*
 * compare *buf with *value, masking out bit indicated in *mask.
 * all three buffers should of length 'len'.
 *
 * - buf: the buffer to check
 * - value: the desired the values to compare with
 * - mask: the mask for both buf and value
 * - len: length for 3 buffers (buf,mask,value)
 *
 * return 0 if match, otherwise not match
 */
int filter_buffer(u8* value, u8* buf, u8* mask, int len)
{
    int i;
    
    for (i = 0; i < len; i ++) {
        if ((buf[i] & mask[i]) != (value[i] & mask[i]))
            return 1;
    }

    return 0;
}


#if (0)
    /* 
     * build subtables from sections: 
     * - start from 1st section (i.e., section_number=0) until last_section_number, to form a complete subtable; 
     * - incomplete subtable is discarded.
     *
     * outline of the idea:
     * for each section where section_number=0
     *    - determine the subtbl id combination according to tid
     *    - find out all sections with the same subtbl id combination
     *    - asmbler the those sections into a subtbl
     */
if (tid == TID_SDT_ACT) {
    fprintf(stdout, "tbl->section_nr = %d\n", tbl->section_nr);
    for (i = 0; i < tbl->section_nr; i ++) {
        if (tbl->sections[i].size >= get_minimum_section_size_by_tid(tid)) {
            sect_hdr = (PRIV_SECT_HEADER*)(tbl->sections[i].data);
            if (sect_hdr->section_number == 0) {
                SECT_FILTER fil;
                u8 ver; 
                u16 onid, tsid, svcid;
                switch (tid) {
                    case TID_SDT_ACT:
                        onid = ((SDT_SECT_HEADER*)sect_hdr)->original_network_id_hi * 256 + ((SDT_SECT_HEADER*)sect_hdr)->original_network_id_lo;
                        tsid = ((SDT_SECT_HEADER*)sect_hdr)->transport_stream_id_hi * 256 + ((SDT_SECT_HEADER*)sect_hdr)->transport_stream_id_lo;
                        ver = sect_hdr->version_number;
                        SETUP_SECT_FILTER_4_SDT_ACT(fil, onid,tsid,ver);
                        break;
                    default:
                        break;
                }

                /*
                 * collect all sections
                 */
                // first search the 2nd half
                for (j = i; j < tbl->section_nr; j ++) {
                    if (0 == filter_buffer(&fil.value, tbl->sections[j].data, &fil.mask, get_minimum_section_size_by_tid(tid))) {
                        tbl->subtbls[tbl->subtbl_nr].sects[tbl->subtbls[tbl->subtbl_nr].sect_nr] = tbl->sections + j;
                        tbl->subtbls[tbl->subtbl_nr].sect_nr += 1;
                    }
                }
                // second search the 1st half
                for (j = 0; j < i; j ++) {
                    if (0 == filter_buffer(&fil.value, tbl->sections[j].data, &fil.mask, get_minimum_section_size_by_tid(tid))) {
                        tbl->subtbls[tbl->subtbl_nr].sects[tbl->subtbls[tbl->subtbl_nr].sect_nr] = tbl->sections + j;
                        tbl->subtbls[tbl->subtbl_nr].sect_nr += 1;
                    }
                }

                // debug
                fprintf(stdout, "subtbl_nr = %d, sect_nr = %d\n", tbl->subtbl_nr, tbl->subtbls[tbl->subtbl_nr].sect_nr);
                for(j = 0; j < tbl->subtbls[tbl->subtbl_nr].sect_nr; j ++) {
                    sect_hdr = (PRIV_SECT_HEADER*)(tbl->subtbls[tbl->subtbl_nr].sects[j]->data);
                    fprintf(stdout, "  %d: section_number=%d, last_section_number=%d, version_number=%d, size=%d\n", 
                        j,
                        sect_hdr->section_number,
                        sect_hdr->last_section_number,
                        sect_hdr->version_number,
                        tbl->subtbls[tbl->subtbl_nr].sects[j]->size);
                }
                /*
                 * assemble sections into subtbls
                 */

                
                tbl->subtbl_nr += 1;
            }
        }
    }
}
#endif

