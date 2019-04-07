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

#include <stdlib.h>
#include "si.h"
#include "tree.h"

/* allocate a TNODE and initialized to zero */
TNODE* tnode_new(node_type_t type){
    TNODE* node;

    if(type >= NODE_TYPE_LAST)
        return 0;
    
    if(!(node = (TNODE*)calloc(sizeof(TNODE), 1)))
        return 0;
    
    node->type = type;
    return node;
}

void tnode_free(TNODE* node){
    if(!node)
        return;

    if(node->txt)
        free(node->txt);
    free(node);
}
        

TNODE* tnode_last_sib(TNODE* node){
    TNODE* last = node;
    
    if(!node)
        return 0;
    
    while(last->sib)
        last = last->sib;
    return last;
}

TNODE* tnode_last_kid(TNODE* node){
    if(!node)
        return 0;
    else
        return tnode_last_sib(node->kid);
}

TNODE* tnode_left_sib(TNODE* node){
    
    TNODE *dad, *next, *result;
    
    if(!node || !(dad = node->dad))
        return 0;
    
    result = 0;
    next = dad->kid;
    while(next && next != node){
        result = next;
        next = next->sib;
    }
    
    if(!next)
        result = 0;
    
    return result;
}

/* attache a kid node as the last child of the dad node;
   the kid node should not have a kid or sibling node. 
   return 0 if fail; otherwise ok */
u8 tnode_attach(TNODE* dad, TNODE* node){
    if(!dad || !node || node->dad || node->sib)
        return 0;

    node->dad = dad;
    
    if(dad->kid){ /* dad already has some kids */
        tnode_last_sib(dad->kid)->sib = node;
    }
    else{
        dad->kid = node;
    }

    return 1;
}

void tnode_detach(TNODE* node){
    TNODE* dad;

    if(!node)
        return;
    
    dad = node->dad;
    if(dad){
        if(dad->kid == node){
            dad->kid = node->sib;
        }
        else{
            tnode_left_sib(node)->sib = node->sib;
        }
        node->dad = 0;
        node->sib = 0;
    }
}

/* recursive func */
void tnode_delete(TNODE* node){
    TNODE* kid;
    
    if(!node)
        return;

    tnode_detach(node);
    while(NULL != (kid = tnode_last_kid(node)))
        tnode_delete(kid);
    
    tnode_free(node);
}
