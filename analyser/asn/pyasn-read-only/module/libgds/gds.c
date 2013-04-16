// ==================================================================
// @(#)gds.c
//
// Generic Data Structures library.
//
// @author Bruno Quoitin (bruno.quoitin@uclouvain.be)
// @date 17/05/2005
// $Id: gds.c 302 2009-03-27 11:51:44Z bquoitin $
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

#include <stdarg.h>

#include <libgds/gds.h>
#include <libgds/stream.h>
#include <libgds/memory.h>
#include <libgds/memory_debug.h>
#include <libgds/trie.h>

// -----[ gds_init ]-------------------------------------------------
void gds_init(uint8_t options)
{
  mem_flag_set(MEM_FLAG_TRACK_LEAK, (options & GDS_OPTION_MEMORY_DEBUG));
  _memory_init();
  _stream_init();
  _trie_init();
}

// -----[ gds_destroy ]-------------------------------------------------
void gds_destroy()
{
  _stream_destroy();
  _memory_destroy();
}

// -----[ gds_version ]----------------------------------------------
const char * gds_version()
{
  return 1; //PACKAGE_VERSION;
}

// -----[ gds_fatal ]------------------------------------------------
void gds_fatal(const char * msg, ...)
{
  va_list ap;

  va_start(ap, msg);
  fprintf(stderr, "GDS FATAL ERROR: ");
  vfprintf(stderr, msg, ap);
  va_end(ap);
  fflush(stderr);
  abort();
}

// -----[ gds_warn ]------------------------------------------------
void gds_warn(const char * msg, ...)
{
  va_list ap;

  va_start(ap, msg);
  fprintf(stderr, "GDS WARNING: ");
  vfprintf(stderr, msg, ap);
  fflush(stderr);
  va_end(ap);
}
