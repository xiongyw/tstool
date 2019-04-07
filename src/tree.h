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

#ifndef __TREE_H__
#define __TREE_H__

/* created(bruin, 2003.01.17): store the ts anaysys result in the tree
     sturctue which is platform (UI lib) independent. this will decouple
     the data from their views. */

typedef enum{
	NODE_TYPE_DEFAULT = 0,
		
	NODE_TYPE_TS_FILE,

	NODE_TYPE_OTV_HINFO,
	
	NODE_TYPE_PSI_SI,
	NODE_TYPE_TABLE,
	NODE_TYPE_SECTION,
	NODE_TYPE_PROGRAM,
	NODE_TYPE_AUDIO_STREAM,
	NODE_TYPE_VIDEO_STREAM,
	NODE_TYPE_PRIVATE_DATA_STREAM,
	
	NODE_TYPE_PIDS,
	NODE_TYPE_PID,
	NODE_TYPE_PACKETS,
	NODE_TYPE_PACKET,

	
	NODE_TYPE_LAST
}node_type_t;

/* tree node */
typedef struct _TNODE{
	struct _TNODE*   dad;   /* parent; null if root */
	struct _TNODE*   sib;   /* right sibling; null if last child */
	struct _TNODE*   kid;   /* first child; null if leaf */
	
	node_type_t      type;
	long             tag;   /* for NODE_TYPE_PACKET, it's the packet index;
	                           for NODE_TYPE_SECTION, it's the pointer to the SECTION (that why it's long--for safe cast) */  
	char*            txt;   /* null terminated string */
}TNODE;


#ifdef __cplusplus
extern "C"{
#endif


TNODE* tnode_new(node_type_t type);
void tnode_free(TNODE* node);
TNODE* tnode_last_sib(TNODE* node);
TNODE* tnode_last_kid(TNODE* node);
TNODE* tnode_left_sib(TNODE* node);
u8 tnode_attach(TNODE* dad, TNODE* node);
void tnode_detach(TNODE* node);
void tnode_delete(TNODE* node);


#ifdef __cplusplus
}
#endif



#endif /* __TREE_H__ */
