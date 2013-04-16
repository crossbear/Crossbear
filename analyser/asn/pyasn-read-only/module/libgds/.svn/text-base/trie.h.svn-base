// ==================================================================
// @(#)trie.h
//
// Unibit compact trie implementation.
//
// @author Bruno Quoitin (bruno.quoitin@uclouvain.be)
// @date 17/05/2005
// $Id: patricia-tree.h 275 2008-10-13 08:28:02Z bquoitin $
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

/**
 * \file
 * Provide data structures and functions to manage a unibit compact
 * trie.
 */

#ifndef __GDS_TRIE_H__
#define __GDS_TRIE_H__

#include <libgds/array.h>
#include <libgds/stream.h>

/** Trie key data type. */
typedef uint32_t trie_key_t;
/** Trie key length data type. */
typedef uint8_t trie_key_len_t;

#define TRIE_SUCCESS          0
#define TRIE_ERROR_DUPLICATE -1
#define TRIE_ERROR_NO_MATCH  -2

#define TRIE_INSERT_OR_REPLACE 1

#define TRIE_KEY_SIZE (sizeof(trie_key_t)*8)

/** Callback function to traverse whole trie. */
typedef int  (*gds_trie_foreach_f) (trie_key_t key, trie_key_len_t key_len,
				    void * data, void * ctx);

/** Callback function to destroy a trie item. */
typedef void (*gds_trie_destroy_f) (void ** data);

// -----[ gds_trie_t ]-----------------------------------------------
/**
 * Trie data structure.
 */
typedef struct gds_trie_t {
  struct _trie_item_t * root;
  gds_trie_destroy_f    destroy;
} gds_trie_t;

#ifdef __cplusplus
extern "C" {
#endif
  
  // -----[ trie_create ]--------------------------------------------
  /**
   * Create a trie.
   *
   * \param destroy is an optional item destroy callback function
   *   (can be NULL).
   * \retval a new trie.
   */
  gds_trie_t * trie_create(gds_trie_destroy_f destroy);

  // -----[ trie_destroy ]-------------------------------------------
  /**
   * Destroy a trie.
   *
   * If a destroy callback function was assigned to \c trie_create,
   * The \c trie_destroy function will call this callback for each
   * item in the trie.
   *
   * \param trie_ref is a pointer to the trie to be destroyed.
   */
  void trie_destroy(gds_trie_t ** trie_ref);

  // -----[ trie_find_exact ]----------------------------------------
  /**
   * Perform an exact match lookup in a trie.
   *
   * \param trie    is the trie.
   * \param key     is the searched key.
   * \param key_len is the length of the searched key.
   * \retval the pointer associated to the given key if it exists,
   *   or NULL otherwise.
   */
  void * trie_find_exact(gds_trie_t * trie, trie_key_t key,
			 trie_key_len_t key_len);

  // -----[ trie_find_best ]-----------------------------------------
  /**
   * Perform a best match lookup in a trie.
   *
   * The best match is also known as a longest-match.
   *
   * \param trie is the trie.
   * \param key is the searched key.
   * \param key_len is the length of the searched key.
   * \retval the pointer associated to the best matching key if it
   *   exists, or NULL otherwise.
   */
  void * trie_find_best(gds_trie_t * trie, trie_key_t key,
			trie_key_len_t key_len);

  // -----[ trie_insert ]--------------------------------------------
  /**
   * Insert data in a trie.
   *
   * \param trie    is the trie.
   * \param key     is the insertion key.
   * \param key_len is the length of the key.
   * \param data    is the data pointer associated to the key.
   * \param replace selects wether or not the new data must replace
   *   the old one.
   * \retval TRIE_SUCCESS if the key could be successfully inserted,
   *   or TRIE_ERROR_DUPLICATE if replacement was not allowed and the
   *   key already exists.
   */
  int trie_insert(gds_trie_t * trie, trie_key_t key,
		  trie_key_len_t key_len, void * data,
		  int replace);

  // -----[ trie_remove ]--------------------------------------------
  /**
   * Remove a key from a trie.
   *
   * \param trie    is the trie.
   * \param key     is the key to be removed.
   * \param key_len is the length of the key.
   * \retval 0 in case of success (key existed),
   *   or <0 in case of failure (key does not exist).
   */
  int trie_remove(gds_trie_t * trie, trie_key_t key,
		  trie_key_len_t key_len);

  // -----[ trie_replace ]-------------------------------------------
  /**
   * Replace an existing key in a trie.
   *
   * \param trie    is the trie.
   * \param key     is the key to be replaced.
   * \param key_len is the length of the key.
   * \param data    is the new data.
   * \retval TRIE_SUCCESS in case the key could be replaced (it
   *   existed), or TRIE_ERROR_NO_MATCH if the key could not be
   *   found.
   */
  int trie_replace(gds_trie_t * trie, trie_key_t key,
		   trie_key_len_t key_len, void * data);

  // -----[ trie_for_each ]------------------------------------------
  /**
   * Traverse a whole trie.
   *
   * For each non empty node in the trie, the provided \a foreach
   * callback function will be called.
   *
   * \param trie is the trie.
   * \param foreach is the callbeck function.
   * \param ctx is the callback context pointer. This pointer will
   *   be passed to the \a foreach callback function each time it is
   *   called.
   * \retval 0 in case all calls to \a foreach succeeded, or <0
   *   if at least one call th \a foreach failed (returned <0).
   */
  int trie_for_each(gds_trie_t * trie, gds_trie_foreach_f foreach,
		    void * ctx);

  // -----[ trie_get_array ]-----------------------------------------
  /**
   * Return an array with the items in the trie.
   */
  ptr_array_t * trie_get_array(gds_trie_t * trie);

  // -----[ trie_get_enum ]------------------------------------------
  /**
   * Return an enumeration for items in the trie.
   */
  gds_enum_t * trie_get_enum(gds_trie_t * trie);

  // -----[ trie_num_nodes ]-----------------------------------------
  /**
   * Return the number of nodes in the trie.
   *
   * \param trie is the trie.
   * \param with_data selects wether or not the function will count
   *   the empty nodes. If \a with_data equals 1, only the nodes
   *   with data are counted. Otherwise, all the nodes are counted.
   * \retval the number of nodes in the trie.
   */
  int trie_num_nodes(gds_trie_t * trie, int with_data);

  // -----[ trie_to_graphviz ]-----------------------------------------
  /**
   * \internal
   */
  void trie_to_graphviz(gds_stream_t * stream, gds_trie_t * trie);

  // -----[ _trie_init ]---------------------------------------------
  /**
   * \internal
   */
  void _trie_init();
  
#ifdef __cplusplus
}
#endif

#endif /* __GDS_TRIE_H__ */
