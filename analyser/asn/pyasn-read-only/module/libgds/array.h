// ==================================================================
// @(#)array.h
//
// @author Bruno Quoitin (bruno.quoitin@uclouvain.be)
// @date 10/04/2003
// $Id: array.h 294 2009-03-27 11:46:56Z bquoitin $
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
 * Provide data structures and functions to manage generic dynamic
 * arrays. These arrays are dynamic as their memory footprint will be
 * adjusted automatically to fit their needs (at the expense of some
 * additional CPU time). They are generic in the sense that they
 * don't care what data types they are working with. All you need to
 * do is to specify the size of a single cell. You can optionally
 * specify how cells are compared (for sorted arrays), how cells are
 * freed and how cells are copied.
 *
 * Specific data structures are provided to work with simple scalar
 * data types such as int's, unsigned int's, char's, and so on. It is
 * easy to build arrays for custom data types by using the array
 * template macro GDS_ARRAY_TEMPLATE.
 *
 * The following example shows how to define an array of doubles by
 * using the array templates (note that this array type is already
 * defined in \c libgds/array.h). This will define a new type
 * \c double_array_t and the corresponding functions which will all
 * be prefixed by \c double_array_.
 *
 * \code
 * GDS_ARRAY_TEMPLATE(double_array, double, 0, _array_compare, NULL, NULL)
 * \endcode
 *
 * The \c double_array_t type is then used as follows:
 *
 * \code
 * unsigned int index;
 * double_array_t * array= double_array_create(100);
 * for (index= 0; index < double_array_size(array); index++)
 *   array->data[index]= ((double) 0.1) * index;
 * double_array_destroy(&array);
 * \endcode
 */

#ifndef __GDS_ARRAY_H__
#define __GDS_ARRAY_H__

#include <stdlib.h>

#include <libgds/enumerator.h>
#include <libgds/types.h>

/** Option: array will be sorted. */
#define ARRAY_OPTION_SORTED 0x01

/** Option: array will reject duplicate values. */
#define ARRAY_OPTION_UNIQUE 0x02

// -----[ gds_array_cmp_f ]------------------------------------------
/** Comparison callback function. */
typedef int (*gds_array_cmp_f)(const void * item1,
			       const void * item2,
			       unsigned int item_size);

// -----[ gds_array_destroy_f ]--------------------------------------
/** Cell de-allocation callback function. */
typedef void (*gds_array_destroy_f)(void * item, const void * ctx);

// -----[ gds_array_foreach_f ]--------------------------------------
/** Array traversal callback function. */
typedef int (*gds_array_foreach_f)(const void * item, const void * ctx);

// -----[ gds_array_clone_f ]----------------------------------------
/** Cell value copy callback function. */
typedef void * (*gds_array_clone_f)(const void * item);

typedef struct array_t {
  char * data;
} array_t;

#ifdef __cplusplus
extern "C" {
#endif

  // ----- _array_create --------------------------------------------
  /**
   * Create a dynamic array.
   *
   * \param elt_size    is the size of a single cell.
   * \param size        is the array size.
   * \param options     is a set of array options.
   * \param cmp         is the cell comparison callback function.
   * \param destroy     is the cell de-allocation callback function.
   * \param destroy_ctx is a context pointer for the \a destroy
   *   function.
   * \retval the newly created array.
   */
  GDS_EXP_DECL array_t * _array_create(unsigned int elt_size,
				       unsigned int size,
				       uint8_t options,
				       gds_array_cmp_f cmp,
				       gds_array_destroy_f destroy,
				       const void * destroy_ctx);

  // ----- _array_destroy -------------------------------------------
  /**
   * Destroy a dynamic array.
   *
   * \param array_ref is a pointer to the array to be destroyed.
   */
  GDS_EXP_DECL void _array_destroy(array_t ** array_ref);

  // ----- _array_set_fdestroy --------------------------------------
  GDS_EXP_DECL void _array_set_fdestroy(array_t * array,
					gds_array_destroy_f destroy,
					const void * destroy_ctx);

  // ----- _array_length --------------------------------------------
  /**
   * Get the length of an array.
   *
   * \param array is the array.
   * \retval the length of the array (number of cells).
   */
  GDS_EXP_DECL unsigned int _array_length(array_t * array);

  // ----- _array_set_length ----------------------------------------
  GDS_EXP_DECL void _array_set_length(array_t * array,
				      unsigned int size);

  // ----- _array_set_at --------------------------------------------
  /**
   * Set the value of a cell in an array.
   *
   * \param array    is the array.
   * \param index    is the cell index.
   * \param data_ref is a pointer to the value to be stored.
   * \retval the insertion index in case of success,
   *   or <0 in case of failure (index >= length).
   *
   * \attention
   * This function should not be used with sorted arrays as it
   * changes the array cell directly. Use \c _array_add with sorted
   * arrays.
   */
  GDS_EXP_DECL int _array_set_at(array_t * array, unsigned int index,
				 void * data_ref);

  // -----[ _array_get_at ]--------------------------------------------
  /**
   * Get the value of a cell in an array.
   *
   * \param array    is the array.
   * \param index    is the cell index.
   * \param data_ref is a pointer to the value to be retrieved.
   * \retval 0 in case of success,
   *   or <0 in case of failure (index >= length).
   */
  GDS_EXP_DECL int _array_get_at(array_t * array, unsigned int index,
				 void * data_ref);

  // -----[ _array_sorted_find_index ]-------------------------------
  /**
   * Find the index of a value in an array.
   *
   * \param array is the array.
   * \param data_ref is a pointer to the searched value.
   * \param index    is a pointer to the searched index.
   * \retval 0 in case of success (value found),
   *   or <0 in case of failure (value not found).
   *
   * Note that if the value is not found, the function still
   * copies in \a index the location where the value would be
   * stored in the array (according to the \p cmp function).
   */
  GDS_EXP_DECL int _array_sorted_find_index(array_t * array,
					    void * data_ref,
					    unsigned int * index);

  // -----[ _array_add ]---------------------------------------------
  /**
   * Add a value to an array.
   *
   * This function behaves differently if the array is sorted or not.
   *
   * \li If the array is sorted (see ARRAY_OPTION_SORTED), the
   * function will find the correct insertion index (with the \p cmp
   * function) and add the new value at that location. If the
   * ARRAY_OPTION_UNIQUE option is set, and if a similar value exists
   * (according th the \p cmp function), an error will be returned.
   *
   * \li If the array is not sorted, the value is appended at the end
   * of the array (the array size is expanded if needed).
   *
   * \param array    is the array.
   * \param data_ref is the data to be inserted.
   * \retval the insertion index in case of success,
   *   or <0 in case of error (duplicate value).
   */
  GDS_EXP_DECL int _array_add(array_t * array, void * data_ref);

  // ----- _array_append --------------------------------------------
  /**
   * Add a value to an array.
   *
   * Add a value at the end of an array. The array will be expanded
   * if needed.
   *
   * \param array is the array.
   * \param data_ref is a pointer to the new value.
   * \retval the insertion index.
   */
  GDS_EXP_DECL int _array_append(array_t * array, void * data_ref);

  // ----- _array_insert_at -----------------------------------------
  /**
   * Insert a value in an array.
   *
   * \param array is the array.
   * \param index is the insertion index.
   * \param data_ref is a pointer to the value to be inserted.
   * \retval the insertion index in case of success,
   *   or <0 in case of failure (index > size).
   */
  GDS_EXP_DECL int _array_insert_at(array_t * array, unsigned int index,
				    void * data);

  // ----- _array_remove_at -----------------------------------------
  /**
   * Remove a value from an array.
   *
   * \param array is the array.
   * \param index is the removal index.
   * \retval 0 in case of success,
   *   or <0 in case of failure (index >= size).
   */
  GDS_EXP_DECL int _array_remove_at(array_t * array, unsigned int index);

  // ----- _array_for_each ------------------------------------------
  GDS_EXP_DECL int _array_for_each(array_t * array,
				   gds_array_foreach_f foreach,
				   const void * ctx);

  // ----- _array_copy ----------------------------------------------
  GDS_EXP_DECL array_t * _array_copy(array_t * array);

  // ----- _array_compare -------------------------------------------
  GDS_EXP_DECL int _array_compare(const void * item1, const void * item2,
				  unsigned int elt_size);

  // ----- _array_sub -----------------------------------------------
  GDS_EXP_DECL array_t * _array_sub(array_t * array, unsigned int first,
				    unsigned int last);

  // ----- _array_add_array -----------------------------------------
  GDS_EXP_DECL void _array_add_array(array_t * array, array_t * src_array);

  // ----- _array_trim ----------------------------------------------
  GDS_EXP_DECL void _array_trim(array_t * array, unsigned max_length);

  // ----- _array_sort ----------------------------------------------
  GDS_EXP_DECL int _array_sort(array_t * array, gds_array_cmp_f cmp);

  // ----- _array_get_enum ------------------------------------------
  GDS_EXP_DECL gds_enum_t * _array_get_enum(array_t * array);
  
#ifdef __cplusplus
}
#endif

// ------------------------------------------------------------------
// ARRAY DECLARATION TEMPLATE:
// ------------------------------------------------------------------
// Use as follows:
//   GDS_ARRAY_DEFINE(net_ifaces, net_iface_t *, 0, NULL, NULL, NULL)
//
// This will create the following typedef and functions:
//   typedef struct net_ifaces_t {
//     net_iface_t ** data;
//   } net_ifaces_t;
//   static/*inline*/net_ifaces_t * net_ifaces_create() {
//     return (net_ifaces_t *) _array_create(sizeof(net_iface_t *),
//                                           0, NULL, NULL, NULL);
//   }
//   static/*inline*/void net_ifaces_destroy(net_ifaces_t ** array_ref) {
//     _array_destroy((array_t **) array_ref);
//   }
//   (...)
// ------------------------------------------------------------------

#define GDS_ARRAY_TEMPLATE_TYPE(N,T)					\
  typedef struct N##_t {						\
    T * data;								\
  } N##_t;

#define GDS_ARRAY_TEMPLATE_OPS(N,T,OPT,FC,FD,FDC)			\
  static/*inline*/N##_t * N##_create(unsigned int size) {			\
    return (N##_t *) _array_create(sizeof(T),size,OPT,FC,FD,FDC);	\
  }									\
  static/*inline*/N##_t * N##_create2(unsigned int size,			\
				    uint8_t options) {			\
    return (N##_t *) _array_create(sizeof(T),size,options,FC,FD,NULL);	\
  }									\
  static/*inline*/void N##_destroy(N##_t ** ref) {			\
    _array_destroy((array_t **) ref);					\
  }									\
  static/*inline*/unsigned int N##_size(N##_t * array) {			\
    return _array_length((array_t *) array);				\
  }									\
  static/*inline*/void N##_set_size(N##_t * array, unsigned int size) {	\
    _array_set_length((array_t *) array, size);				\
  }									\
  static/*inline*/int N##_add(N##_t * array, T data) {			\
    return _array_add((array_t *) array, &data);			\
  }									\
  static/*inline*/int N##_append(N##_t * array, T data) {			\
    return _array_append((array_t *) array, &data);			\
  }									\
  static/*inline*/int N##_remove_at(N##_t * array, unsigned int index) {	\
    return _array_remove_at((array_t *) array, index);			\
  }									\
  static/*inline*/int N##_index_of(N##_t * array,				\
				 T data,				\
				 unsigned int * index) {		\
    return _array_sorted_find_index((array_t *) array, &data, index);	\
  }									\
  static/*inline*/int N##_for_each(N##_t * array,				\
				 gds_array_foreach_f foreach,		\
				 void * ctx) {				\
    return _array_for_each((array_t *) array, foreach, ctx);		\
  }									\
  static/*inline*/gds_enum_t * N##_get_enum(N##_t * array) {		\
    return _array_get_enum((array_t *) array);				\
  }									\
  static/*inline*/N##_t * N##_copy(N##_t * array) {			\
    return (N##_t *) _array_copy((array_t *) array);			\
  }									\
  static/*inline*/int N##_insert_at(N##_t * array,			\
				  unsigned int index,			\
				  T * data) {				\
    return _array_insert_at((array_t *) array, index, data);		\
  }									\
  static/*inline*/int N##_sort(N##_t * array,				\
			     gds_array_cmp_f cmp) {			\
    return _array_sort((array_t *) array, cmp);			\
  }									\
  static/*inline*/N##_t * N##_sub(N##_t * array,				\
				unsigned int first,			\
				unsigned int last) {			\
    return (N##_t *) _array_sub((array_t *) array, first, last);	\
  }									\
  static/*inline*/void N##_trim(N##_t * array, unsigned int size) {	\
    _array_trim((array_t *) array, size);				\
  }									\
  static/*inline*/void N##_add_array(N##_t * array, N##_t * add_array) {	\
    _array_add_array((array_t *) array, (array_t *) add_array);		\
  }

#define GDS_ARRAY_TEMPLATE(NAME,TYPE,OPT,FC,FD,FDC)			\
  GDS_ARRAY_TEMPLATE_TYPE(NAME,TYPE);					\
  GDS_ARRAY_TEMPLATE_OPS(NAME,TYPE,OPT,FC,FD,FDC);

typedef struct ptr_array_t {
  void ** data;
} ptr_array_t;

#define ptr_array_create_ref(O)				\
  (ptr_array_t *) _array_create(sizeof(void *), 0, O,	\
				_array_compare, NULL, NULL)
#define ptr_array_create(O, FC, FD, FDC)				\
  (ptr_array_t *) _array_create(sizeof(void *), 0, O, FC, FD, FDC)
#define ptr_array_length(A) _array_length((array_t *) A)
#define ptr_array_set_length(A, L) _array_set_length((array_t *) A, L)
#define ptr_array_sorted_find_index(A, D, I)		\
  _array_sorted_find_index((array_t *) A, D, I)
#define ptr_array_add(A, D) _array_add((array_t *) A, D)
#define ptr_array_append(A, D) _array_append((array_t *) A, &D)
#define ptr_array_remove_at(A, I) _array_remove_at((array_t *) A, I)
#define ptr_array_get_at(A, I, E) _array_get_at((array_t *) A, I, E)
#define ptr_array_set_fdestroy(A, F, FDC)	\
  _array_set_fdestroy((array_t *)A, F, FDC)

#define ARRAY_DESTROY_TEMPLATE(P, T)			\
 /*inline*/static void P##_array_destroy(T ** array) {	\
    _array_destroy((array_t **) array); }

ARRAY_DESTROY_TEMPLATE(ptr, ptr_array_t)
  
#undef ARRAY_DESTROY_TEMPLATE
  
GDS_ARRAY_TEMPLATE(int_array, int, 0, _array_compare, NULL, NULL)
GDS_ARRAY_TEMPLATE(uint32_array, uint32_t, 0, _array_compare, NULL, NULL)
GDS_ARRAY_TEMPLATE(uint16_array, uint16_t, 0, _array_compare, NULL, NULL)
GDS_ARRAY_TEMPLATE(double_array, double, 0, _array_compare, NULL, NULL)
  
#endif /* __GDS_ARRAY_H__ */
