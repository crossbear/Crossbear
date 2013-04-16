// ==================================================================
// @(#)memory.h
//
// @author Bruno Quoitin (bruno.quoitin@uclouvain.be)
// @date 17/05/2005
// $Id: memory.h 280 2008-12-10 14:01:41Z bquoitin $
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
 * Provide a simple wrapper for heap memory allocation that can
 * optionally track memory allocation/de-allocation/re-allocation
 * and find memory leaks.
 */

#pragma warning(disable:4996) 

#ifndef __GDS_MEMORY_H__
#define __GDS_MEMORY_H__

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libgds/gds.h>
#include <libgds/types.h>

#ifdef GDS_MEMORY_DEBUG

/** Location of caller (file name + line number). Only defined if
 * GDS_MEMORY_DEBUG is defined. */
#define __MEMORY_DEBUG_INFO__ , const char * filename, int line_num
/** Allocate memory. Wrapper for \c malloc. */
#define MALLOC(s) memalloc(s, __FILE__, __LINE__)
/** Re-allocate memory. Wrapper for \c realloc. */
#define REALLOC(p, s) memrealloc(p, s, __FILE__, __LINE__)
/** De-allocate memory. Wrapper for \c free. */
#define FREE(p) memfree(p, __FILE__, __LINE__)

#else /* GDS_MEMORY_DEBUG */

/** Location of caller (file name + line number). Only defined if
 * GDS_MEMORY_DEBUG is defined. */
#define __MEMORY_DEBUG_INFO__
/** Allocate memory. Wrapper for \c malloc. */
#define MALLOC(s) memalloc(s)
/** Re-allocate memory. Wrapper for \c realloc. */
#define REALLOC(p, s) memrealloc(p, s)
/** De-allocate memory. Wrapper for \c free. */
#define FREE(p) memfree(p)

#endif /* GDS_MEMORY_DEBUG */


#ifdef __cplusplus
extern "C" {
#endif

  // -----[ _mem_alloc_count_inc ]-----------------------------------
  void _mem_alloc_count_inc(const char * filename, int line_num);
  // -----[ _mem_alloc_count_dec ]-----------------------------------
  void _mem_alloc_count_dec(const char * filename, int line_num);
  // -----[ _mem_alloc_count_get ]-----------------------------------
  long int _mem_alloc_count_get();

  // -----[ mem_flag_set ]-------------------------------------------
  void mem_flag_set(uint8_t flag, int state);
  // -----[ mem_flag_get ]-------------------------------------------
  int mem_flag_get(uint8_t flag);
  
  // -----[ _memory_init ]-------------------------------------------
  void _memory_init();
  // -----[ _memory_destroy ]----------------------------------------
  void _memory_destroy();

#ifdef __cplusplus
}
#endif

// -----[ memalloc ]-----------------------------------------------
/**
 * Allocate a block of memory.
 *
 * This is a wrapper for stdio's malloc() function. If libGDS
 * was compiled with the GDS_MEMORY_DEBUG symbol, it will
 * perform additional checks an track the location of the caller
 * (file name and line number). In addition, if \c malloc fails
 * and returns a NULL pointer, the program will be aborted with
 * a fatal error.
 *
 * \attention
 * It is more convenient to call this function through the
 * \c MALLOC macro.
 *
 * \param size is the size of the requested memory block.
 * \param __MEMORY_DEBUG_INFO__
 *             is the location of the caller (file name + line number).
 *             It is only defined if the GDS_MEMORY_DEBUG symbol is
 *             defined.
 */
static /*inline*/ void * memalloc(size_t size
		__MEMORY_DEBUG_INFO__)
{
  void * new_ptr= malloc(size);
  if (new_ptr == NULL)
    gds_fatal("Memory allocation failed (%s)", strerror(errno));

#ifdef GDS_MEMORY_DEBUG
  _mem_alloc_count_inc();
  memory_debug_track_alloc(new_ptr, size, filename, line_num);
#endif /* GDS_MEMORY_DEBUG */
  
  return new_ptr;
}

// -----[ memrealloc ]---------------------------------------------
/**
 * Re-allocate a block of memory.
 *
 * This is a wrapper to stdio's \c realloc() function. If libGDS
 * was compiled with the GDS_MEMORY_DEBUG symbol, it will
 * perform additional checks and track the location of the caller
 * (file name and line number). In addition, if \c realloc fails
 * and returns a NULL pointer, the program will be aborted with
 * a fatal error.
 *
 * \attention
 * It is more convenient to call this function through the
 * \c REALLOC macro.
 *
 * \param ptr  is the pointer to the block of memory to re-allocate.
 * \param size is the new requested size.
 * \param __MEMORY_DEBUG_INFO__
 *             is the location of the caller (file name + line number).
 *             It is only defined if the GDS_MEMORY_DEBUG symbol is
 *             defined.
 */
static /*inline*/ void * memrealloc(void * ptr,
				size_t size
				__MEMORY_DEBUG_INFO__)
{
  void * new_ptr= realloc(ptr, size);
  if (new_ptr == NULL)
    gds_fatal("Memory reallocation failed (%s)", strerror(errno));
    
#ifdef GDS_MEMORY_DEBUG
  memory_debug_track_realloc(new_ptr, ptr, size, filename, line_num);
#endif /* GDS_MEMORY_DEBUG */

  return new_ptr;
}

// -----[ memfree ]------------------------------------------------
/**
 * Free a block of memory.
 *
 * This is a wrapper for stdio's \c free() function. If libGDS is
 * compiled with the GDS_MEMORY_DEBUG parameter, this function
 * will perform some additional checks.
 * \li First, it will track the de-allocation of memory and keep
 *     the name and line of the file where the de-allocation was
 *     performed.
 * \li Second, it will check that the de-allocation is for a valid
 *     block of memory (prealably allocated through \c memalloc.
 *
 * \attention
 * It is more convenient to call this function through the \c FREE
 * macro. The macro will be defined according to the setting of
 * GDS_MEMORY_DEBUG to keep the filename (__FILE__) and the line
 * number (__LINE__) of the caller.
 *
 * \param ptr is the pointer to the memory block to de-allocate.
 * \param __MEMORY_DEBUG_INFO__
 *            is the location of the caller (file name + line number).
 *            It is only defined if the GDS_MEMORY_DEBUG symbol is
 *            defined.
 */
static /*inline*/
void memfree(void * ptr
	     __MEMORY_DEBUG_INFO__)
{
#ifdef GDS_MEMORY_DEBUG
  memory_debug_track_free(ptr, filename, line_num);
  mem_alloc_count_dec();
#endif /* GDS_MEMORY_DEBUG */

  free(ptr);
}

#endif /* __GDS_MEMORY_H__ */
