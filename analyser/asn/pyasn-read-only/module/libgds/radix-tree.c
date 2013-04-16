// ==================================================================
// @(#)radix-tree.c
//
// A library of function that handles radix-trees intended to store
// IPv4 prefixes.
//
// @author Bruno Quoitin (bruno.quoitin@uclouvain.be)
// @date 21/10/2002
// $Id: radix-tree.c 275 2008-10-13 08:28:02Z bquoitin $
//
// libGDS, library of generic data structures
// Copyright (C) 2002-2008 Bruno Quoitin
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
// 02111-1307  USA
// ==================================================================

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <libgds/memory.h>
#include <libgds/radix-tree.h>
#include <libgds/stack.h>

// ----- structure of a radix-tree node -----------------------------
typedef struct _radix_tree_item_t {
  struct _radix_tree_item_t * left;  // 0
  struct _radix_tree_item_t * right; // 1
  void                      * data;
} _radix_tree_item_t;

// ----- radix_tree_item_create -------------------------------------
/**
 *
 */
_radix_tree_item_t * radix_tree_item_create(void * data)
{
  _radix_tree_item_t * tree_item=
    (_radix_tree_item_t *) MALLOC(sizeof(_radix_tree_item_t));
  tree_item->left= NULL;
  tree_item->right= NULL;
  tree_item->data= data;
  return tree_item;
}

// ----- radix_tree_item_destroy ------------------------------------
/**
 * Remove an item. Remove also all its children if the parameter
 * 'iSingle' is 1.
 */
void radix_tree_item_destroy(_radix_tree_item_t ** ptree_item,
			     FRadixTreeDestroy fDestroy,
			     int iSingle)
{
  gds_stack_t * stack= stack_create(32);
  _radix_tree_item_t * tree_item= *ptree_item;

  while (tree_item != NULL) {

    /* If all children are to be removed, push them onto stack. */
    if (!iSingle) {
      if (tree_item->left != NULL)
	stack_push(stack, tree_item->left);
      if (tree_item->right != NULL)
	stack_push(stack, tree_item->right);
    }

    /* Destroy the item. */
    if ((tree_item->data != NULL) && (fDestroy != NULL)) {
      fDestroy(&tree_item->data);
      tree_item->data= NULL;
    }

    /* If the current item is empty (no child) or if we delete all
       child, then free the item's memory. */
    if (((tree_item->left == NULL) && (tree_item->right == NULL)) ||
	!iSingle) {
      FREE(tree_item);
      *ptree_item= NULL;
    }

    /* Any other child to be removed ? */
    if (stack_depth(stack) > 0)
      tree_item= (_radix_tree_item_t *) stack_pop(stack);
    else
      tree_item= NULL;

  }
  stack_destroy(&stack);
}

// ----- radix_tree_create ------------------------------------------
/**
 *
 */
gds_radix_tree_t * radix_tree_create(uint8_t key_len,
				     FRadixTreeDestroy fDestroy)
{
  gds_radix_tree_t * tree= (gds_radix_tree_t *) MALLOC(sizeof(gds_radix_tree_t));
  tree->root= NULL;
  tree->key_len= key_len;
  tree->fDestroy= fDestroy;
  return tree;
}

// ----- radix_tree_destroy -----------------------------------------
/**
 * Free the whole radix-tree.
 */
void radix_tree_destroy(gds_radix_tree_t ** tree_ref)
{
  if (*tree_ref != NULL) {
    if ((*tree_ref)->root != NULL)
      radix_tree_item_destroy(&(*tree_ref)->root, (*tree_ref)->fDestroy, 0);
    FREE(*tree_ref);
    *tree_ref= NULL;
  }
}

// ----- radix_tree_add ---------------------------------------------
/**
 * Add an 'item' in the radix-tree at 'key/len' position.
 */
int radix_tree_add(gds_radix_tree_t * tree, uint32_t key,
		   uint8_t key_len, void * data)
{
  _radix_tree_item_t ** ptree_item= &tree->root;
  uint8_t uLen= key_len;

  // Go to given 'key/len' position. Create path along the way if
  // required...
  // Warning: '*ptree_item' is used to add new nodes while
  // 'ptree_item' is used to keep track of the current node !!
  while (uLen > 0) {
    if (*ptree_item == NULL)
      *ptree_item= radix_tree_item_create(NULL);
    if (key & (1 << (tree->key_len-(key_len+1-uLen))))
      ptree_item= &(*ptree_item)->right;
    else
      ptree_item= &(*ptree_item)->left;
    uLen--;
  }

  if (*ptree_item == NULL) {
    *ptree_item= radix_tree_item_create(data);
  } else {
    // If a previous value exists, replace it
    if ((*ptree_item)->data != NULL) {
      if (tree->fDestroy != NULL)
	tree->fDestroy(&(*ptree_item)->data);
    }
    // Set new value
    (*ptree_item)->data= data;
  }

  return 0;
}

// ----- radix_tree_remove ------------------------------------------
/**
 * Remove the item at position 'key/Len' as well as all the empty
 * nodes that are on the way.
 *
 * Parameters:
 * - iSingle, if 1 remove a single key otherwise, remove the key and
 *   all the keys under.
 */
int radix_tree_remove(gds_radix_tree_t * tree, uint32_t key,
		      uint8_t key_len, int iSingle)
{
  gds_stack_t * stack= stack_create(tree->key_len);
  uint8_t uLen= key_len;
  _radix_tree_item_t ** ptree_item= &tree->root;
  int iEmpty;
  
  while (uLen > 0) {
    if (*ptree_item == NULL)
      return -1;
    if (key & (1 << (tree->key_len-(key_len+1-uLen)))) {
      if ((*ptree_item)->right != NULL) {
	stack_push(stack, ptree_item);
	ptree_item= &(*ptree_item)->right;
      } else
	return -1;
    } else {
      if ((*ptree_item)->left != NULL) {
	stack_push(stack, ptree_item);
	ptree_item= &(*ptree_item)->left;
      } else
	return -1;
    }
    uLen--;
  }
  if ((*ptree_item == NULL) || ((*ptree_item)->data == NULL))
    return -1;

  /* Keep information on the current key's emptiness. The key is
     considered empty if it has no child and has no item. */
  iEmpty= (((*ptree_item)->left == NULL)
	   && ((*ptree_item)->right == NULL));

  radix_tree_item_destroy(ptree_item, tree->fDestroy, iSingle);

  /* If the current item is empty (no key below, go up towards the
     radix-tree's root and clear keys until a non-empty is found. */
  while (iEmpty && (stack_depth(stack) > 0)) {
    ptree_item= (_radix_tree_item_t **) stack_pop(stack);

    /* If the key is empty (no child and no item), remove it. */
    if (((*ptree_item)->left == NULL) &&
	((*ptree_item)->right == NULL) &&
	((*ptree_item)->data == NULL)) {
      radix_tree_item_destroy(ptree_item, tree->fDestroy, 1);
    } else
      break;
  }
  stack_destroy(&stack);
  return 0;
}

// ----- radix_tree_get_exact ---------------------------------------
/**
 * Return the item exactly at position 'key/len'.
 */
void * radix_tree_get_exact(gds_radix_tree_t * tree,
			    uint32_t key,
			    uint8_t key_len)
{
  uint8_t uLen= key_len;
  _radix_tree_item_t * tree_item= tree->root;

  while (uLen > 0) {
    if (tree_item == NULL)
      return NULL;
    if (key & (1 << (tree->key_len-(key_len+1-uLen)))) {
      if (tree_item->right != NULL)
	tree_item= tree_item->right;
      else
	return NULL;
    } else {
      if (tree_item->left != NULL)
	tree_item= tree_item->left;
      else
	return NULL;
    }
    uLen--;
  }
  if (tree_item != NULL)
    return tree_item->data;
  return NULL;
}

// ----- radix_tree_get_best ----------------------------------------
/**
 * Return the item that best matches position 'key/len'.
 */
void * radix_tree_get_best(gds_radix_tree_t * tree,
			   uint32_t key,
			   uint8_t key_len)
{
  uint8_t uLen= key_len;
  _radix_tree_item_t * tree_item= tree->root;
  void * result= NULL;

  /* If the tree is empty, there is no possible match. */
  if (tree_item == NULL)
    return NULL;

  /* Otherwize, the shortest match corresponds to the root. */
  if (tree_item->data != NULL)
    result= tree_item->data;

  /* Go down the tree, as long as the requested key matches the
     traversed prefixes and as deep as the requested key length... */
  while (uLen > 0) {

    if (key & (1 << (tree->key_len-(key_len+1-uLen)))) {
      // Bit is 1
      if (tree_item->right != NULL)
	tree_item= tree_item->right;
      else
	break;
    } else {
      // Bit is 0
      if (tree_item->left != NULL)
	tree_item= tree_item->left;
      else
	break;
    }
    uLen--;

    if ((tree_item != NULL) && (tree_item->data != NULL))
      result= tree_item->data;
  }
  
  return result;
}

// -----[ _stack_ctx_t ]---------------------------------------------
typedef struct {
  _radix_tree_item_t * tree_item;
  uint32_t             key;
  uint8_t              key_len;
} _stack_ctx_t;

// -----[ _stack_push ]----------------------------------------------
static /*inline*/ void _stack_push(gds_stack_t * stack,
			       _radix_tree_item_t * item,
			       uint8_t key_len,
			       uint32_t key)
{
  _stack_ctx_t * stack_ctx= (_stack_ctx_t *)
    MALLOC(sizeof(_stack_ctx_t));
  stack_ctx->tree_item= item;
  stack_ctx->key_len= key_len;
  stack_ctx->key= key;
  assert(stack_push(stack, stack_ctx) >= 0);
}

// -----[ _stack_pop ]-----------------------------------------------
static /*inline*/ void _stack_pop(gds_stack_t * stack,
			      _radix_tree_item_t ** tree_item,
			      uint8_t * key_len,
			      uint32_t * key)
{
  _stack_ctx_t * stack_ctx= (_stack_ctx_t *) stack_pop(stack);
  *tree_item= stack_ctx->tree_item;
  *key_len= stack_ctx->key_len;
  *key= stack_ctx->key;
  FREE(stack_ctx);
}

// ----- radix_tree_for_each ----------------------------------------
/**
 * Call the 'fForEach' function for each non empty node.
 */
int radix_tree_for_each(gds_radix_tree_t * tree,
			FRadixTreeForEach fForEach,
			void * ctx)
{
  gds_stack_t * stack= stack_create(tree->key_len);
  _radix_tree_item_t * tree_item;
  int result= 0;
  uint32_t key;
  uint8_t key_len;

  tree_item= tree->root;
  key= 0;
  key_len= 0;

  // Depth first search
  while (tree_item != NULL) {
    if (tree_item->data!= NULL) {
      result= fForEach(key, key_len, tree_item->data, ctx);
      if (result != 0)
	return result;
    }
    if (tree_item->left != NULL) {
      if (tree_item->right != NULL)
	_stack_push(stack, tree_item->right, key_len+1,
		    key+(1 << (tree->key_len-key_len-1)));
      tree_item= tree_item->left;
      key_len++;
    } else if (tree_item->right != NULL) {
      tree_item= tree_item->right;
      key= key+(1 << (tree->key_len-key_len-1));
      key_len++;
    } else {
      if (stack_depth(stack) > 0)
	_stack_pop(stack, &tree_item, &key_len, &key);
      else
	break;
    }
  }
  stack_destroy(&stack);
  return 0;
}

// ----- _radix_tree_item_num_nodes ---------------------------------
int _radix_tree_item_num_nodes(_radix_tree_item_t * tree_item, int with_data)
{
  if (tree_item != NULL) {
    return (with_data?(tree_item->data != NULL):1) +
      _radix_tree_item_num_nodes(tree_item->left, with_data) +
      _radix_tree_item_num_nodes(tree_item->right, with_data);
  }
  return 0;
}

// ----- radix_tree_num_nodes ---------------------------------------
/**
 * Count the number of nodes in the tree. The algorithm uses a
 * divide-and-conquer recursive approach.
 */
int radix_tree_num_nodes(gds_radix_tree_t * tree, int with_data)
{
  return _radix_tree_item_num_nodes(tree->root, with_data);
}


/////////////////////////////////////////////////////////////////////
//
// ENUMERATION
//
/////////////////////////////////////////////////////////////////////

// -----[ _enum_ctx_t ]----------------------------------------------
typedef struct {
  gds_radix_tree_t   * tree;
  gds_stack_t        * stack;
  _radix_tree_item_t * tree_item;
  uint32_t             key;
  uint8_t              key_len;
  void               * data;
} _enum_ctx_t;

// -----[ _radix_tree_enum_has_next ]--------------------------------
static int _radix_tree_enum_has_next(void * ctx)
{
  _enum_ctx_t * ectx= (_enum_ctx_t *) ctx;

  // Depth first search
  while ((ectx->data == NULL) && (ectx->tree_item != NULL)) {

    if (ectx->tree_item->data != NULL)
      ectx->data= ectx->tree_item->data;

    // Move to next item
    if (ectx->tree_item->left != NULL) {
      if (ectx->tree_item->right != NULL)
	_stack_push(ectx->stack, ectx->tree_item->right, ectx->key_len+1,
		    ectx->key+(1 << (ectx->tree->key_len-ectx->key_len-1)));
      ectx->tree_item= ectx->tree_item->left;
      ectx->key_len++;
    } else if (ectx->tree_item->right != NULL) {
      ectx->tree_item= ectx->tree_item->right;
      ectx->key= ectx->key+(1 << (ectx->tree->key_len-ectx->key_len-1));
      ectx->key_len++;
    } else {
      if (stack_depth(ectx->stack) > 0)
	_stack_pop(ectx->stack, &ectx->tree_item, &ectx->key_len, &ectx->key);
      else
	ectx->tree_item= NULL;
    }
  }
  return (ectx->data != NULL);
}

// -----[ _radix_tree_enum_get_next ]--------------------------------
static void * _radix_tree_enum_get_next(void * ctx)
{
  _enum_ctx_t * ectx= (_enum_ctx_t *) ctx;
  void * data= NULL;

  if (_radix_tree_enum_has_next(ctx)) {
    data= ectx->data;
    ectx->data= NULL;
  }
  return data;
}

// -----[ _radix_tree_enum_destroy ]---------------------------------
static void _radix_tree_enum_destroy(void * ctx)
{
  _enum_ctx_t * ectx= (_enum_ctx_t *) ctx;
  stack_destroy(&ectx->stack);
  FREE(ectx);
}

// -----[ radix_tree_get_enum ]--------------------------------------
gds_enum_t * radix_tree_get_enum(gds_radix_tree_t * tree)
{
  _enum_ctx_t * ectx=
    (_enum_ctx_t *) MALLOC(sizeof(_enum_ctx_t));
  ectx->tree= tree;
  ectx->stack= stack_create(tree->key_len);
  ectx->tree_item= tree->root;
  ectx->key= 0;
  ectx->key_len= 0;
  ectx->data= NULL;
  return enum_create(ectx,
		     _radix_tree_enum_has_next,
		     _radix_tree_enum_get_next,
		     _radix_tree_enum_destroy);
}
