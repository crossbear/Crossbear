// ==================================================================
// @(#)memory_debug.h
//
// @author Bruno Quoitin (bruno.quoitin@uclouvain.be)
// @date 04/01/2007
// $Id$
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

#ifndef __GDS_MEMODY_DEBUG_H__
#define __GDS_MEMORY_DEBUG_H__

#include <stdlib.h>

#define MEM_FLAG_WARN_LEAK  0x01 /* Display a warning in case of memory
				    leak when the memory.o object is
				    destroyed (note that memory.o must
				    be the last object in the .DTOR
				    list) */
#define MEM_FLAG_TRACK_LEAK 0x02

#ifdef __cplusplus
extern "C" {
#endif

  // -----[ memory_debug_track_alloc ]-------------------------------
  void memory_debug_track_alloc(void * new_ptr, size_t size,
				const char * filename, int line_num);
  // -----[ memory_debug_track_realloc ]-----------------------------
  void memory_debug_track_realloc(void * new_ptr, void * ptr,
				  size_t size,
				  const char * filename, int line_num);
  // -----[ memory_debug_track_free ]--------------------------------
  void memory_debug_track_free(void * ptr, const char * filename,
			       int line_num);
  // -----[ memory_debug_init ]--------------------------------------
  void memory_debug_init(int track);
  // -----[ memory_debug_destroy ]-----------------------------------
  void memory_debug_destroy();

#ifdef __cplusplus
}
#endif

#endif /* __GDS_MEMORY_DEBUG_H__ */
