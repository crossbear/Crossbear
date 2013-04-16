// ==================================================================
// @(#)enumerator.h
//
// List enumerator object.
//
// @author Bruno Quoitin (bruno.quoitin@uclouvain.be)
// @date 10/08/2005
// $Id: enumerator.h 305 2009-03-27 11:55:49Z bquoitin $
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
 * Provide a data structure and functions to manage enumerators.
 * Enumerators are a generic way to traverse data structures. They
 * are available for some of the data structures provided by libGDS.
 */

#ifndef __GDS_ENUMERATOR_H__
#define __GDS_ENUMERATOR_H__

#include <libgds/types.h>

typedef int    (*gds_enum_has_next_f)(void * ctx);
typedef void * (*gds_enum_get_next_f)(void * ctx);
typedef void   (*gds_enum_destroy_f) (void * ctx);

typedef struct {
  gds_enum_has_next_f  has_next;
  gds_enum_get_next_f  get_next;
  gds_enum_destroy_f   destroy;
} enum_ops_t;

typedef struct {
  void       * ctx;
  enum_ops_t   ops;
} gds_enum_t;

#ifdef __cplusplus
extern "C" {
#endif

  // ----- enum_create ------------------------------------------------
  /**
   * Create an enumerator.
   *
   * \param ctx
   *   is the enumerator context (typically another data structure)
   * \param has_next
   *   is a callback function that tests if there is a next element.
   * \param get_next
   *   is a callback function that returns the next element.
   * \param destroy
   *   is a callback function that frees the enumerator's  internal
   *   state.
   */
  GDS_EXP_DECL gds_enum_t * enum_create(void * ctx,
					gds_enum_has_next_f has_next,
					gds_enum_get_next_f get_next,
					gds_enum_destroy_f destroy);
  // ----- enum_destroy -----------------------------------------------
  /**
   * Destroy an enumerator.
   *
   * \param enum_ref is a pointer to the enumerator.
   */
  GDS_EXP_DECL void enum_destroy(gds_enum_t ** enum_ref);
  
#ifdef __cplusplus
}
#endif

// ----- enum_has_next ----------------------------------------------
/**
 * Test if there is a next element.
 *
 * \param enu is the target enumerator.
 * \retval 0 if no more element is available,
 *         or not 0 if more element(s) are available
 */
static /*inline*/ int enum_has_next(gds_enum_t * enu)
{
  return enu->ops.has_next(enu->ctx);
}

// ----- enum_get_next ----------------------------------------------
/**
 * Return the next element.
 *
 * \param enu is the target enumerator.
 * \retval the next element.
 */
static /*inline*/ void * enum_get_next(gds_enum_t * enu)
{
  return enu->ops.get_next(enu->ctx);
}

#define GDS_ENUM_TEMPLATE_TYPE(N,T)					\
  typedef gds_enum_t N##_t;						\
  typedef T (*N##_get_next_func)(void * ctx);

#define GDS_ENUM_TEMPLATE_OPS(N,T)					\
  static inline N##_t * N##_create(void * ctx,				\
				   gds_enum_has_next_f has_next,	\
				   N##_get_next_func get_next,		\
				   gds_enum_destroy_f destroy) {	\
    return enum_create(ctx, has_next,					\
		       (gds_enum_get_next_f) get_next,			\
		       destroy);					\
  }									\
  static inline void N##_destroy(N##_t ** enu) {			\
    enum_destroy(enu);							\
  }									\
  static inline int N##_has_next(N##_t * enu) {				\
    return enum_has_next(enu);						\
  }									\
  static inline T N##_get_next(N##_t * enu) {				\
    return ((N##_get_next_func) enu->ops.get_next)(enu->ctx);		\
  }

#endif /* __GDS_ENUMERATOR_H__ */
