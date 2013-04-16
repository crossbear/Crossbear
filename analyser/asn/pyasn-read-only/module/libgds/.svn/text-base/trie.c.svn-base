// ==================================================================
// @(#)trie.c
//
// Unibit compact trie implementation.
//
// @author Bruno Quoitin (bruno.quoitin@uclouvain.be)
// @date 17/05/2005
// $Id: patricia-tree.c 275 2008-10-13 08:28:02Z bquoitin $
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
# include <config.h>
#endif

#include <assert.h>
#include <stdio.h>

#include <libgds/array.h>
#include <libgds/memory.h>
#include <libgds/trie.h>
#include <libgds/stack.h>

// -----[ _trie_item_t ]------------------------------------------------
typedef struct _trie_item_t {
  struct _trie_item_t * left;
  struct _trie_item_t * right;
  trie_key_t            key;
  uint8_t               has_data:1,
    key_len :7;
  void                * data;
} _trie_item_t;

// -----[ precomputed masks ]----------------------------------------
static trie_key_t trie_predef_masks[TRIE_KEY_SIZE+1];

// -----[ _trie_init_predef_masks ]----------------------------------
/**
 * This function initializes the array of predifined masks. This allows
 * faster key masking. Generates TRIE_KEY_SIZE+1 entries.
 */
static/*inline*/void _trie_init_predef_masks()
{
  trie_key_len_t index;

  trie_predef_masks[0]= 0;
  for (index= 1; index < TRIE_KEY_SIZE+1; index++)
    trie_predef_masks[index]= (trie_predef_masks[index-1] |
			       (1 << (TRIE_KEY_SIZE-index)));
}

// -----[ _trie_mask_key ]-------------------------------------------
/**
 * Mask key: keep only key-len most significant bits.
 *
 * Precondition: key-len is <= TRIE_KEY_SIZE (32)
 */
static/*inline*/trie_key_t _trie_mask_key(trie_key_t key,
					trie_key_len_t key_len)
{
  assert(key_len <= TRIE_KEY_SIZE);
  return key & trie_predef_masks[key_len];
}

// -----[ _trie_item_create_data ]-----------------------------------
/**
 * Create a new node for the Patricia tree. Note: the function will
 * take care of correctly masking the node's key according to its
 * length.
 */
static /*inline*/
_trie_item_t * _trie_item_create_data(trie_key_t key,
				      trie_key_len_t key_len,
				      void * data)
{
  _trie_item_t * trie_item= (_trie_item_t *) MALLOC(sizeof(_trie_item_t));
  trie_item->left= NULL;
  trie_item->right= NULL;
  trie_item->key= key;
  trie_item->key_len= key_len;
  trie_item->has_data= 1;
  trie_item->data= data;
  return trie_item;
}

// -----[ _trie_item_create_empty ]----------------------------------
static /*inline*/
_trie_item_t * _trie_item_create_empty(trie_key_t key,
				       trie_key_len_t key_len)
{
  _trie_item_t * trie_item= (_trie_item_t *) MALLOC(sizeof(_trie_item_t));
  trie_item->left= NULL;
  trie_item->right= NULL;
  trie_item->key= key;
  trie_item->key_len= key_len;
  trie_item->has_data= 0;
  trie_item->data= NULL;
  return trie_item;
}

// -----[ _longest_common_prefix ]------------------------------------
/**
 * Compute the longest common prefix between two given keys.
 *
 * Pre: (key lenghts <= TRIE_KEY_SIZE) &
 *      (key and key_len are valid pointers)
 */
static /*inline*/
void _longest_common_prefix(trie_key_t key1,
			    trie_key_len_t key_len1,
			    trie_key_t key2,
			    trie_key_len_t key_len2,
			    trie_key_t * key,
			    trie_key_len_t * key_len)
{
  trie_key_t mask= 1 << (TRIE_KEY_SIZE-1);
  trie_key_len_t max_len= ((key_len1 <= key_len2)?
			   key_len1:key_len2);
  *key= 0;
  *key_len= 0;
  while (*key_len < max_len) {
    if ((key1 & mask) != (key2 & mask))
      return;
    *key|= (key1 & mask);
    mask= (mask >> 1);
    (*key_len)++;
  }
}

// -----[ trie_create ]----------------------------------------------
/**
 * Create a new Patricia tree.
 */
gds_trie_t * trie_create(gds_trie_destroy_f destroy)
{
  gds_trie_t * trie= (gds_trie_t *) MALLOC(sizeof(gds_trie_t));
  trie->root= NULL;
  trie->destroy= destroy;
  return trie;
}

// -----[ _trie_insert ]---------------------------------------------
/**
 * Insert a new (key, value) pair into the Patricia tree. This
 * function is only an helper function. The 'trie_insert' function
 * should be used instead.
 *
 * Pre: (key length <= TRIE_KEY_SIZE)
 *
 * Result: 0 on success and -1 on error (duplicate key)
 */
static int _trie_insert(_trie_item_t ** item, trie_key_t key,
			trie_key_len_t key_len, void * data,
			gds_trie_destroy_f destroy, int replace)
{
  trie_key_t prefix;
  trie_key_len_t prefix_len;
  _trie_item_t * new_item;

  // Find the longest common prefix
  _longest_common_prefix((*item)->key, (*item)->key_len,
			 key, key_len, &prefix, &prefix_len);

  // Split, append or recurse ?
  if ((prefix_len == key_len) && (prefix_len == (*item)->key_len)) {

    // Exact location found: replace
    if ((*item)->has_data) {
      if (replace == TRIE_INSERT_OR_REPLACE) {
	if (destroy != NULL)
	  destroy(&(*item)->data);
	(*item)->data= data;
	return TRIE_SUCCESS;
      } else {
	return TRIE_ERROR_DUPLICATE;
      }
    } else {
      (*item)->has_data= 1;
      (*item)->data= data;
      return TRIE_SUCCESS;
    }

  } else if (prefix_len < (*item)->key_len) {

    // Split is required
    new_item= _trie_item_create_empty(prefix, prefix_len);
    if ((*item)->key & (1 << (TRIE_KEY_SIZE-prefix_len-1))) {
      new_item->right= *item;
    } else {
      new_item->left= *item;
    }
    if (prefix_len == key_len) {
      new_item->has_data= 1;
      new_item->data= data;
    } else {
      if (key & (1 << (TRIE_KEY_SIZE-prefix_len-1))) {
	new_item->right= _trie_item_create_data(key, key_len, data);
      } else {
	new_item->left= _trie_item_create_data(key, key_len, data);
      }
    }
    *item= new_item;
    return TRIE_SUCCESS;

  } else {

    if (key & (1 << (TRIE_KEY_SIZE-(*item)->key_len-1))) {
      if ((*item)->right != NULL) {
	// Recurse
	return _trie_insert(&(*item)->right, key, key_len,
			    data, destroy, replace);
      } else {
	// Append
	(*item)->right= _trie_item_create_data(key, key_len, data);
	return TRIE_SUCCESS;
      }
    } else {
      if ((*item)->left != NULL) {
	// Recurse
	return _trie_insert(&(*item)->left, key, key_len,
			    data, destroy, replace);
      } else {
	// Append
	(*item)->left= _trie_item_create_data(key, key_len, data);
	return TRIE_SUCCESS;
      }
    }

  }
}

// -----[ trie_insert ]----------------------------------------------
/**
 * Insert one (key, value) pair into the Patricia tree.
 *
 * PRECONDITION:
 *  key length <= TRIE_KEY_SIZE
 */
int trie_insert(gds_trie_t * trie, trie_key_t key,
		trie_key_len_t key_len, void * data,
		int replace)
{
  key= _trie_mask_key(key, key_len);
  if (trie->root == NULL) {
    trie->root= _trie_item_create_data(key, key_len, data);
    return TRIE_SUCCESS;
  }

  return _trie_insert(&trie->root, key, key_len,
		      data, trie->destroy, replace);
}

// -----[ trie_find_exact ]------------------------------------------
void * trie_find_exact(gds_trie_t * trie, trie_key_t key,
		       trie_key_len_t key_len)
{
  _trie_item_t * tmp;
  trie_key_t prefix;
  trie_key_len_t prefix_len;

  // Mask the given key according to its length
  key= _trie_mask_key(key, key_len);

  if (trie->root == NULL)
    return NULL;
  tmp= trie->root;
  while (tmp != NULL) {

    // requested key is smaller than current => no match found
    if (key_len < tmp->key_len)
      return NULL;

    // requested key has same length
    if (key_len == tmp->key_len) {
      // (keys are equal) <=> match found
      if (key == tmp->key) {
	if (tmp->has_data) {
	  return tmp->data;
	} else {
	  return NULL;
	}
      } else {
	return NULL;
      }
    }

    // requested key is longer => check if common parts match
    if (key_len > tmp->key_len) {
      _longest_common_prefix(tmp->key, tmp->key_len,
			     key, key_len, &prefix, &prefix_len);

      // Current key is too long => no match found
      if (prefix_len < tmp->key_len)
	return NULL;

      if (key & (1 << (TRIE_KEY_SIZE-prefix_len-1)))
	tmp= tmp->right;
      else
	tmp= tmp->left;
    }
  }
  return NULL;
}

// -----[ trie_find_best ]-------------------------------------------
void * trie_find_best(gds_trie_t * trie, trie_key_t key,
		      trie_key_len_t key_len)
{
  _trie_item_t * tmp;
  void * data;
  int data_found= 0;
  trie_key_t prefix;
  trie_key_len_t prefix_len;
  trie_key_t search_key= _trie_mask_key(key, key_len);

  if (trie->root == NULL)
    return NULL;
  tmp= trie->root;
  data= NULL;
  while (tmp != NULL) {

    // requested key is smaller than current => no match found
    if (key_len < tmp->key_len)
      break;

    // requested key has same length
    if (key_len == tmp->key_len) {
      // (keys are equal) <=> match found
      if (search_key == tmp->key) {
	if (tmp->has_data) {
	  return tmp->data;
	} else {
	  return NULL;
	}
      } else
	break;
    }

    // requested key is longer => check if common parts match
    if (key_len > tmp->key_len) {
      _longest_common_prefix(tmp->key, tmp->key_len,
			     search_key, key_len, &prefix, &prefix_len);

      // Current key is too long => no match found
      if (prefix_len < tmp->key_len)
	break;

      if (tmp->has_data) {
	data= tmp->data;
	data_found= 1;
      }

      if (search_key & (1 << (TRIE_KEY_SIZE-prefix_len-1)))
	tmp= tmp->right;
      else
	tmp= tmp->left;
    }
  }
  if (data_found)
    return data;
  return NULL;
}

// -----[ _trie_remove_item ]----------------------------------------
static/*inline*/void _trie_remove_item(_trie_item_t ** item,
				     gds_trie_destroy_f destroy)
{
  _trie_item_t * tmp;

  if (destroy != NULL)
    destroy(&(*item)->data);
  (*item)->has_data= 0;
  
  // Two cases: 2 childs or less
  if (((*item)->left != NULL) &&
      ((*item)->right != NULL)) {
    // Item can not be destroyed
  } else {
    // Item can be destroyed and replaced by the non-null child
    tmp= *item;
    if ((*item)->left != NULL)
      *item= (*item)->left;
    else
      *item= (*item)->right;
    FREE(tmp);
  }
}

// -----[ _trie_remove ]---------------------------------------------
/**
 *
 */
static int _trie_remove(_trie_item_t ** item, const trie_key_t key,
			trie_key_len_t key_len,
			gds_trie_destroy_f destroy)
{
  _trie_item_t * tmp;
  trie_key_t prefix;
  trie_key_len_t prefix_len;
  int result;

  // requested key is smaller than current => no match found
  if (key_len < (*item)->key_len)
    return TRIE_ERROR_NO_MATCH;

  // requested key has same length
  if (key_len == (*item)->key_len) {
    if ((key == (*item)->key) && (*item)->has_data) {
      _trie_remove_item(item, destroy);
      return TRIE_SUCCESS;
    } else
      return TRIE_ERROR_NO_MATCH;
  }

  // requested key is longer => check if common parts match
  if (key_len > (*item)->key_len) {
    _longest_common_prefix((*item)->key, (*item)->key_len,
			   key, key_len, &prefix, &prefix_len);
    
    // Current key is too long => no match found
    if (prefix_len < (*item)->key_len)
      return TRIE_ERROR_NO_MATCH;
    
    if (key & (1 << (TRIE_KEY_SIZE-prefix_len-1))) {
      if ((*item)->right != NULL)
	result= _trie_remove(&(*item)->right, key, key_len, destroy);
      else
	return TRIE_ERROR_NO_MATCH;
    } else {
      if ((*item)->left != NULL)
	result= _trie_remove(&(*item)->left, key, key_len, destroy);
      else
	return TRIE_ERROR_NO_MATCH;
    }

    // Need to propagate removal ?
    if ((result == 0) && !(*item)->has_data) {
      // If the local value does not exist and if the local node has
      // less than 2 childs, it should be removed and replaced by its
      // child (if any).
      if (((*item)->left == NULL) || ((*item)->right == NULL)) {
	tmp= *item;
	if ((*item)->left != NULL)
	  *item= (*item)->left;
	else
	  *item= (*item)->right;
	FREE(tmp);
      }
    }
    return result;
  }  
  return TRIE_ERROR_NO_MATCH;
}

// -----[ trie_remove ]----------------------------------------------
/**
 * Remove the value associated with the given key. Remove any
 * unnecessary nodes in the tree.
 *
 * Pre: (key length < TRIE_KEY_SIZE)
 *
 * RETURNS:
 *   -1 if key does not exist
 *    0 if key has been removed.
 */
int trie_remove(gds_trie_t * trie, trie_key_t key, trie_key_len_t key_len)
{
  if (trie->root == NULL)
    return TRIE_ERROR_NO_MATCH;

  return _trie_remove(&trie->root, _trie_mask_key(key, key_len),
		      key_len, trie->destroy);
}

// -----[ _trie_replace ]--------------------------------------------
static int _trie_replace(_trie_item_t * item, const trie_key_t key,
			 trie_key_len_t key_len, void * data,
			 gds_trie_destroy_f destroy)
{
  trie_key_t prefix;
  trie_key_len_t prefix_len;

  // requested key is smaller than current => no match found
  if (key_len < item->key_len)
    return TRIE_ERROR_NO_MATCH;

  // requested key has same length
  if (key_len == item->key_len) {
    if ((key == item->key) && item->has_data) {
      if (destroy != NULL)
	destroy(&item->data);
      item->data= data;
      return TRIE_SUCCESS;
    } else
      return TRIE_ERROR_NO_MATCH;
  }

  // requested key is longer => check if common parts match
  if (key_len > item->key_len) {
    _longest_common_prefix(item->key, item->key_len,
			   key, key_len, &prefix, &prefix_len);
    
    // Current key is too long => no match found
    if (prefix_len < item->key_len)
      return TRIE_ERROR_NO_MATCH;
    
    if (key & (1 << (TRIE_KEY_SIZE-prefix_len-1))) {
      if (item->right != NULL)
	return _trie_replace(item->right, key, key_len, data, destroy);
      else
	return TRIE_ERROR_NO_MATCH;
    } else {
      if (item->left != NULL)
	return _trie_replace(item->left, key, key_len, data, destroy);
      else
	return TRIE_ERROR_NO_MATCH;
    }
  }
  return TRIE_ERROR_NO_MATCH;
}

// -----[ trie_replace ]---------------------------------------------
/**
 * Replace an existing key. An existing key is a node which has its
 * 'has_data' field equal to '1'.
 *
 * Returns:
 *   TRIE_SUCCESS
 *     if the key was found. In this case, the data 'field' is
 *     replaced with the new data value (can be NULL).
 *   TRIE_ERROR_NO_MATCH
 *     if no matching key was found.
 */
int trie_replace(gds_trie_t * trie, trie_key_t key,
		 trie_key_len_t key_len, void * data)
{
  if (trie->root == NULL)
    return TRIE_ERROR_NO_MATCH;

  return _trie_replace(trie->root, _trie_mask_key(key, key_len),
		       key_len, data, trie->destroy);
}

// -----[ _trie_destroy ]--------------------------------------------
static void _trie_destroy(_trie_item_t ** item, gds_trie_destroy_f destroy)
{
  if (*item != NULL) {
    // Destroy content of data item
    if ((*item)->has_data)
      if (destroy != NULL)
	destroy(&(*item)->data);

    // Recursive descent (left, then right)
    if ((*item)->left != NULL)
      _trie_destroy(&(*item)->left, destroy);
    if ((*item)->right != NULL)
      _trie_destroy(&(*item)->right, destroy);

    FREE(*item);
  }
}

// -----[ trie_destroy ]---------------------------------------------
void trie_destroy(gds_trie_t ** trie_ref)
{
  if (*trie_ref != NULL) {
    _trie_destroy(&(*trie_ref)->root, (*trie_ref)->destroy);
    FREE(*trie_ref);
    *trie_ref= NULL;
  }
}

// -----[ _trie_item_for_each ]--------------------------------------
static int _trie_item_for_each(_trie_item_t * item,
			       gds_trie_foreach_f foreach, void * ctx)
{
  int result;

  if (item->left != NULL) {
    result= _trie_item_for_each(item->left, foreach, ctx);
    if (result != 0)
      return result;
  }
  if (item->right != NULL) {
    result= _trie_item_for_each(item->right, foreach, ctx);
    if (result != 0)
      return result;
  }

  if (item->has_data)
    return foreach(item->key, item->key_len, item->data, ctx);
  else
    return 0;
}

// -----[ trie_for_each ]--------------------------------------------
int trie_for_each(gds_trie_t * trie, gds_trie_foreach_f foreach, void * ctx)
{
  if (trie->root != NULL)
    return _trie_item_for_each(trie->root, foreach, ctx);
  return 0;
}

// -----[ _trie_num_nodes ]------------------------------------------
static int _trie_num_nodes(_trie_item_t * item, int with_data)
{
  if (item != NULL) {
    if (!with_data || item->has_data)
      return (1 +
	      _trie_num_nodes(item->left, with_data) +
	      _trie_num_nodes(item->right, with_data));
    else
      return (_trie_num_nodes(item->left, with_data) +
	      _trie_num_nodes(item->right, with_data));
  }
  return 0;
}

// -----[ trie_num_nodes ]-------------------------------------------
/**
 * Count the number of nodes in the trie. The algorithm uses a
 * divide-and-conquer recursive approach.
 */
int trie_num_nodes(gds_trie_t * trie, int with_data)
{
  return _trie_num_nodes(trie->root, with_data);
}

// -----[ trie_to_graphviz ]-----------------------------------------
void trie_to_graphviz(gds_stream_t * stream, gds_trie_t * trie)
{
  gds_stack_t * stack= stack_create(32);
  _trie_item_t * item;
  
  stream_printf(stream, "digraph trie {\n");

  if (trie->root != NULL)
    stack_push(stack, trie->root);
  
  while (!stack_is_empty(stack)) {
    item= (_trie_item_t *) stack_pop(stack);

    stream_printf(stream, "  \"%u/%u\" ", item->key, item->key_len);
    stream_printf(stream, "[label=\"%u/%u\\n", item->key, item->key_len);
    if (item->has_data)
      stream_printf(stream, "data=%p", item->data);
    stream_printf(stream, "\"]");
    stream_printf(stream, " ;\n");
    
    if (item->left != NULL) {
      stack_push(stack, item->left);
      stream_printf(stream, "  \"%u/%u\" -> \"%u/%u\" ;\n",
		    item->key, item->key_len,
		    item->left->key, item->left->key_len);
    }
    if (item->right != NULL) {
      stack_push(stack, item->right);
      stream_printf(stream, "  \"%u/%u\" -> \"%u/%u\" ;\n",
		    item->key, item->key_len,
		    item->right->key, item->right->key_len);
    }
  }
  
  stream_printf(stream, "}\n");

  stack_destroy(&stack);
}

/////////////////////////////////////////////////////////////////////
//
// ENUMERATION
//
/////////////////////////////////////////////////////////////////////

// -----[ _trie_get_array_for_each ]---------------------------------
static int _trie_get_array_for_each(uint32_t key, uint8_t key_len,
				    void * data, void * ctx)
{
  ptr_array_t * array= (ptr_array_t *) ctx;
  if (ptr_array_append(array, data) < 0)
    return -1;
  return 0;
}

// -----[ _trie_get_array ]-------------------------------------------
static ptr_array_t * _trie_get_array(gds_trie_t * trie)
{
  ptr_array_t * array= ptr_array_create_ref(0);
  if (trie_for_each(trie,
		    _trie_get_array_for_each,
		    array)) {
    ptr_array_destroy(&array);
    array= NULL;
  }
  return array;
}

// ----- _enum_ctx_t -------------------------------------------
typedef struct {
  ptr_array_t * array;
  gds_enum_t  * enu;
} _enum_ctx_t;

// -----[ _trie_get_enum_has_next ]----------------------------------
static int _trie_get_enum_has_next(void * ctx)
{
  _enum_ctx_t * ectx= (_enum_ctx_t *) ctx;
  return enum_has_next(ectx->enu);
}

// -----[ _trie_get_enum_get_next ]----------------------------------
static void * _trie_get_enum_get_next(void * ctx)
{
  _enum_ctx_t * ectx= (_enum_ctx_t *) ctx;
  return enum_get_next(ectx->enu);
}

// -----[ _trie_get_enum_destroy ]-----------------------------------
static void _trie_get_enum_destroy(void * ctx)
{
  _enum_ctx_t * ectx= (_enum_ctx_t *) ctx;
  enum_destroy(&ectx->enu);
  ptr_array_destroy(&ectx->array);
  FREE(ectx);
}

// -----[ trie_get_enum ]--------------------------------------------
gds_enum_t * trie_get_enum(gds_trie_t * trie)
{
  _enum_ctx_t * ectx=
    (_enum_ctx_t *) MALLOC(sizeof(_enum_ctx_t));
  ectx->array= _trie_get_array(trie);
  ectx->enu= _array_get_enum((array_t *) ectx->array);

  return enum_create(ectx,
		     _trie_get_enum_has_next,
		     _trie_get_enum_get_next,
		     _trie_get_enum_destroy);
}

/////////////////////////////////////////////////////////////////////
//
// INITIALIZATION PART
//
/////////////////////////////////////////////////////////////////////

// -----[ _trie_init ]-----------------------------------------------
void _trie_init()
{
  _trie_init_predef_masks();
}
