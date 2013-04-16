// ==================================================================
// @(#)array.c
//
// @author Bruno Quoitin (bruno.quoitin@uclouvain.be)
// @date 10/04/2003
// $Id: array.c 294 2009-03-27 11:46:56Z bquoitin $
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
#include <string.h>

#include <libgds/array.h>
#include <libgds/enumerator.h>
#include <libgds/memory.h>
#include <libgds/types.h>

#define _array_elt_pos(A,i) (((char *) A->data)+ \
			    (i)*((_array_t *) A)->elt_size)
#define _array_size(A) ((_array_t *) A)->elt_size* \
                       ((_array_t *) A)->size

typedef struct {
  gds_array_cmp_f     cmp;
  gds_array_destroy_f destroy;
} _array_ops_t;

typedef struct {
  uint8_t      ** data;
  unsigned int    size;
  unsigned int    elt_size;
  uint8_t         options;
  _array_ops_t    ops;
  const void    * destroy_ctx;
} _array_t;

// ----- _array_compare ---------------------------------------------
/**
 * \brief Compare two elements of an array.
 *
 * @param pItem1 the first element.
 * @param pItem2 the second element.
 * @param elt_size the elements'size.
 */
GDS_EXP_DECL
int _array_compare(const void * item1, const void * item2,
		   unsigned int elt_size)
{
  return memcmp(item1, item2, elt_size);
}

// ----- _array_create ----------------------------------------------
/**
 *
 */
GDS_EXP_DECL
array_t * _array_create(unsigned int elt_size,
			unsigned int size,
			uint8_t options,
			gds_array_cmp_f cmp,
			gds_array_destroy_f destroy,
			const void * destroy_ctx)
{
  _array_t * real_array= (_array_t *) MALLOC(sizeof(_array_t));
  real_array->size= size;
  real_array->elt_size= elt_size;
  if (size > 0)
    real_array->data= (uint8_t **) MALLOC(elt_size*size);
  else
    real_array->data= NULL;
  real_array->options= options;
  real_array->ops.cmp= cmp;
  real_array->ops.destroy= destroy;
  real_array->destroy_ctx= destroy_ctx;
  return (array_t *) real_array;
}

// ----- _array_set_fdestroy -----------------------------------------
GDS_EXP_DECL
void _array_set_fdestroy(array_t * array, gds_array_destroy_f destroy,
			 const void * destroy_ctx)
{
  _array_t * real_array = (_array_t *)array;

  real_array->ops.destroy = destroy;
  real_array->destroy_ctx= destroy_ctx;
}

// ----- _array_destroy ----------------------------------------------
/**
 *
 */
GDS_EXP_DECL
void _array_destroy(array_t ** array)
{
  _array_t ** real_array=
    (_array_t **) array;
  unsigned int index;

  if (*real_array != NULL) {
    if ((*real_array)->size > 0) {
      if ((*real_array)->ops.destroy != NULL)
	for (index= 0; index < (*real_array)->size; index++)
	  (*real_array)->ops.destroy(_array_elt_pos((*real_array), index),
				     (*real_array)->destroy_ctx);
      FREE((*real_array)->data);
    }
    FREE(*real_array);
    *real_array= NULL;
  }
}

// ----- _array_resize_if_required ----------------------------------
/**
 * Change the size of an array. Re-allocate memory accordingly.
 */
static /*inline*/
void _array_resize_if_required(array_t * array,
			       unsigned int new_length)
{
  _array_t * real_array= (_array_t *) array;

  if (new_length != real_array->size) {
    if (real_array->size == 0) {
      real_array->data=
	(uint8_t **) MALLOC(new_length*real_array->elt_size);
    } else if (new_length == 0) {
      FREE(real_array->data);
      real_array->data= NULL;
    } else {
      real_array->data=
	(uint8_t **) REALLOC(real_array->data,
			     new_length*real_array->elt_size);
    }
    real_array->size= new_length;
  }
}

// ----- _array_length -----------------------------------------------
/**
 * Return the length of the array.
 */
GDS_EXP_DECL
unsigned int _array_length(array_t * array)
{
  return ((_array_t *) array)->size;
}

// ----- _array_set_length ------------------------------------------
/**
 * Set the length of an array. If the new size is smaller than the
 * original size, data will be lost.
 */
GDS_EXP_DECL
void _array_set_length(array_t * array, unsigned int new_length)
{
  _array_resize_if_required(array, new_length);
}

// ----- array_set_at -----------------------------------------------
/**
 * Set the value of the element at the given index in the array.
 *
 * RETURNS:
 *   >=0 (index) in case of success
 *    -1 in case of failure (index >= length)
 */
GDS_EXP_DECL
int _array_set_at(array_t * array, unsigned int index, void * data_ref)
{
  if (index >= ((_array_t *) array)->size)
    return -1;
  memcpy(_array_elt_pos(array, index), data_ref,
  	 ((_array_t *) array)->elt_size);
  return index;
}

// ----- array_get_at -----------------------------------------------
/**
 * Return the value at the given index in the array.
 *
 * RETURNS:
 *    0 in case of success
 *   -1 in case of failure (index >= length)
 */
GDS_EXP_DECL
int _array_get_at(array_t * array, unsigned int index, void * data_ref)
{
  if (index >= ((_array_t *) array)->size)
    return -1;

  memcpy(data_ref, _array_elt_pos(array, index),
	 ((_array_t *) array)->elt_size);
  return 0;
}

// ----- _array_sorted_find_index -----------------------------------
/**
 * Find the index of an element in a sorted array (using the compare
 * function)
 *
 * RETURNS:
 *    0 in case of success (the index of the element is returned)
 *   -1 in case of failure (the index where this element would be
 *                          placed is returned)
 */
GDS_EXP_DECL
int _array_sorted_find_index(array_t * array, void * data,
			     unsigned int * index)
{
  unsigned int offset= 0;
  unsigned int size= ((_array_t *) array)->size;
  unsigned int pos= size/2;
  int iCompareResult;

  while (size > 0) {
    iCompareResult=
      (((_array_t *) array)->ops.cmp(_array_elt_pos(array, pos),
				     data,
				     ((_array_t *) array)->elt_size));
    if (!iCompareResult) {
      *index= pos;
      return 0;
    } else if (iCompareResult > 0) {
      if (pos > offset) {
	size= pos-offset;
	pos= offset+size/2;
      } else
	break;
    } else {
      if (offset+size-pos > 0) {
	size= offset+size-pos-1;
	offset= pos+1;
	pos= offset+size/2;
      } else
	break;
    }
  }
  *index= pos;
  return -1;
}

// ----- _array_insert_at -------------------------------------------
/**
 * Insert an element in the array at the specified index.
 *
 * RETURNS:
 *   >= 0 in case of success
 *     -1 in case of failure
 *          (index >= length)
 */
GDS_EXP_DECL
int _array_insert_at(array_t * array, unsigned int index, void * data)
{
  unsigned int offset;
  _array_t * real_array= (_array_t *) array;

  if (index > ((_array_t *) array)->size)
    return -1;
  _array_resize_if_required(array, ((_array_t *) array)->size+1);
  for (offset= real_array->size-1; offset > index; offset--) {
    memcpy(_array_elt_pos(array, offset),
	   _array_elt_pos(array, offset-1),
	   real_array->elt_size);
  }
  return _array_set_at(array, index, data);
}

// ----- _array_add -------------------------------------------------
/**
 * Add an element to the array.
 * 1). If the array is sorted, the element is inserted according to
 *     the ordering defined by the compare function.
 * 2). If the array is not sorted, the element is inserted at the end
 *     of the array
 *
 * RETURNS:
 *   >= 0 in case of success
 *     -1 in case of failure
 *          if (sorted && ARRAY_OPTION_UNIQUE && value exists)
 */
GDS_EXP_DECL
int _array_add(array_t * array, void * data_ref)
{
  unsigned int index;

  if (((_array_t *) array)->options & ARRAY_OPTION_SORTED) {
    if (_array_sorted_find_index(array, data_ref, &index) < 0) {
      return _array_insert_at(array, index, data_ref);
    } else {
      if (((_array_t *) array)->options & ARRAY_OPTION_UNIQUE)
	return -1;
      else
	return _array_set_at(array, index, data_ref);
    }
  } else
    return _array_append(array, data_ref);
}

// ----- array_append -----------------------------------------------
/**
 * Append en element at the end of the array. Note that this function
 * should not be used with sorted arrays.
 *
 * RETURNS:
 *   >=0 insertion index
 */
GDS_EXP_DECL
int _array_append(array_t * array, void * data)
{
  assert((((_array_t *) array)->options & ARRAY_OPTION_SORTED) == 0);

  _array_resize_if_required(array, ((_array_t *) array)->size+1);

  _array_set_at(array, ((_array_t *) array)->size-1, data);
  return ((_array_t *) array)->size-1;
}

// ----- _array_for_each --------------------------------------------
/**
 * Execute the given callback function for each element in the array.
 * The callback function must return 0 in case of success and !=0 in
 * case of failure. In the later case, the array traversal will stop
 * and the error code of the callback is returned.
 *
 * RETURNS:
 *     0 in case of success
 *   !=0 in case of failure
 */
GDS_EXP_DECL
int _array_for_each(array_t * array, gds_array_foreach_f foreach,
		    const void * ctx)
{
  unsigned int index;
  int result;
  
  for (index= 0; index < _array_length(array); index++) {
    result= foreach(_array_elt_pos(array, index), ctx);
    if (result != 0)
      return result;
  }
  return 0;
}

// ----- _array_copy ------------------------------------------------
/**
 * Make a copy of an entire array.
 *
 * RETURNS:
 *   a pointer to the copy
 */
GDS_EXP_DECL
array_t * _array_copy(array_t * array)
{
  array_t * new_array= _array_create(((_array_t *) array)->elt_size,
				     ((_array_t *) array)->size,
				     ((_array_t *) array)->options,
				     ((_array_t *) array)->ops.cmp,
				     ((_array_t *) array)->ops.destroy,
				     ((_array_t *) array)->destroy_ctx);
  // TBR _array_set_length(new_array, ((_array_t *)array)->size);
  memcpy(new_array->data, array->data, _array_size(array));
  return new_array;
}

// ----- _array_remove_at -------------------------------------------
/**
 * Remove the element at the given index in the array.
 *
 * RETURNS:
 *    0 un case of success
 *   -1 in case index is not valid
 */
GDS_EXP_DECL
int _array_remove_at(array_t * array, unsigned int index)
{
  _array_t * real_array= (_array_t *) array;
  unsigned int offset;

  if (index >= real_array->size)
    return -1;

  // Free item at given position if required
  if (real_array->ops.destroy != NULL)
    real_array->ops.destroy(_array_elt_pos(real_array, index),
			    real_array->destroy_ctx);
  
  // Since (index >= 0), then (real_array->size >= 1) and then
  // there is no problem with the unsigned variable uOffset.
  for (offset= index; offset < real_array->size-1; offset++) {
    memcpy(_array_elt_pos(array, offset),
	   _array_elt_pos(array, offset+1),
	   real_array->elt_size);
  }
  _array_resize_if_required(array, real_array->size-1);
  return 0;
}

// ----- _array_sub -------------------------------------------------
/**
 * Extract a sub-array from the given array.
 *
 * PRECONDITION: (iFirst <= iLast) AND (iLast < length(ARRAY))
 */
GDS_EXP_DECL
array_t * _array_sub(array_t * array, unsigned int first, unsigned int last)
{
  _array_t * sub_array;
  assert((first <= last) && (last < _array_length(array)));

  sub_array= (_array_t *)
    _array_create(((_array_t *) array)->elt_size,
		  last-first+1,
		  ((_array_t *) array)->options,
		  ((_array_t *) array)->ops.cmp,
		  ((_array_t *) array)->ops.destroy,
		  ((_array_t *) array)->destroy_ctx);
  // TBR sub_array->size= last-first+1;
  // TBR sub_array->data= (uint8_t **) MALLOC(sub_array->elt_size*sub_array->size);
  memcpy(sub_array->data, _array_elt_pos(array, first),
	 sub_array->elt_size*sub_array->size);
  return (array_t *) sub_array;
}

// ----- _array_add_array -------------------------------------------
/**
 * Add a whole array to another array.
 */
GDS_EXP_DECL
void _array_add_array(array_t * array, array_t * src_array)
{
  unsigned int size= ((_array_t *) array)->size;

  assert(((_array_t *) array)->elt_size ==
	 ((_array_t *) src_array)->elt_size);
  _array_resize_if_required(array,
			    size+((_array_t *) src_array)->size);
  memcpy(_array_elt_pos(array, size),
	 _array_elt_pos(src_array, 0),
	 _array_size(src_array));
}

// ----- _array_trim ------------------------------------------------
/**
 *
 */
GDS_EXP_DECL
void _array_trim(array_t * array, unsigned max_length)
{
  assert(max_length <= ((_array_t *) array)->size);
  _array_resize_if_required(array, max_length);
}

#define _array_elt_copy_to(A, i, d) memcpy(_array_elt_pos(A, i), d, \
                                           ((_array_t *) A)->elt_size)
#define _array_elt_copy_from(A, d, i) memcpy(d, _array_elt_pos(A, i), \
                                             ((_array_t *) A)->elt_size)
#define _array_elt_copy(A, i, j) memcpy(_array_elt_pos(A, i), \
                                        _array_elt_pos(A, j), \
                                        ((_array_t *) A)->elt_size)

// ----- _array_sort ------------------------------------------------
/**
 * Simple selection-sort.
 */
GDS_EXP_DECL
int _array_sort(array_t * array, gds_array_cmp_f cmp)
{
  unsigned int index, index2;
  void * pTemp= MALLOC(((_array_t *) array)->elt_size);

  for (index= 0; index < _array_length(array); index++)
    for (index2= index; index2 > 0; index2--)
      if (cmp(_array_elt_pos(array, index2-1),
	      _array_elt_pos(array, index2),
	      ((_array_t *) array)->elt_size) > 0) {
	_array_elt_copy_from(array, pTemp, index2);
	_array_elt_copy(array, index2, index2-1);
	_array_elt_copy_to(array, index2-1, pTemp);
      }

  FREE(pTemp);
  ((_array_t*) array)->options|= ARRAY_OPTION_SORTED;
  ((_array_t*) array)->ops.cmp= cmp;
  return 0;
}

// ----- _array_quicksort -------------------------------------------
/**
 * Nonrecursive quicksort implementation.
 *
 * Note:
 *   - quicksort is not stable (does not preserve previous order)
 *   - complexity of quicksort is O(N.log(N))
 *   - the stack depth should remain under log(N) thanks to pushing
 *     the largest subfiles first on the stack
 */
GDS_EXP_DECL
int _array_quicksort(array_t * array, gds_array_cmp_f cmp)
{
  // NOT YET IMPLEMENTED
  return -1;
}


/////////////////////////////////////////////////////////////////////
//
// ENUMERATION
//
/////////////////////////////////////////////////////////////////////

typedef struct {
  unsigned int   index;
  array_t      * array;
} _enum_ctx_t;

// -----[ _enum_has_next ]-------------------------------------------
static int _enum_has_next(void * ctx)
{
  _enum_ctx_t * enum_ctx= (_enum_ctx_t *) ctx;
  return (enum_ctx->index < _array_length(enum_ctx->array));
}

// -----[ _enum_get_next ]-------------------------------------------
static void * _enum_get_next(void * ctx)
{
  _enum_ctx_t * enum_ctx= (_enum_ctx_t *) ctx;
  return *((void **) _array_elt_pos(enum_ctx->array, enum_ctx->index++));
}

// -----[ _enum_destroy ]--------------------------------------------
static void _enum_destroy(void * ctx)
{
  _enum_ctx_t * enum_ctx= (_enum_ctx_t *) ctx;
  FREE(enum_ctx);
}

// -----[ _array_get_enum ]------------------------------------------
GDS_EXP_DECL
gds_enum_t * _array_get_enum(array_t * array)
{
  _enum_ctx_t * ctx= (_enum_ctx_t *) MALLOC(sizeof(_enum_ctx_t));
  ctx->array= array;
  ctx->index= 0;
  return enum_create(ctx,
		     _enum_has_next,
		     _enum_get_next,
		     _enum_destroy);
}
