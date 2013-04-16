// ==================================================================
// @(#)types.h
//
// @author Bruno Quoitin (bruno.quoitin@uclouvain.be)
// @date 24/11/2002
// $Id: types.h 297 2009-03-27 11:48:31Z bquoitin $
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
 * Provide some conditionnally defined preprocessor symbols.
 */

#ifndef __TYPES_H__
#define __TYPES_H__

#ifdef CYGWIN
# define GDS_EXP_DECL __declspec(dllexport)
#else
# define GDS_EXP_DECL
#endif

/* `inttypes.h' vs. `stdint.h' (quoting from the GNU autoconf manual)
 *
 * Paul Eggert notes that: ISO C 1999 says that `inttypes.h' includes
 * `stdint.h', so there's no need to include `stdint.h' separately in
 * a standard environment. Many implementations have `inttypes.h' but
 * not `stdint.h' (e.g., Solaris 7), but I don't know of any
 * implementation that has `stdint.h' but not `inttypes.h'. Nor do I
 * know of any free software that includes `stdint.h'; `stdint.h'
 * seems to be a creation of the committee. */
//#if HAVE_INTTYPES_H
//#include <inttypes.h>
//#else
//#if HAVE_STDINT_H
//#include <stdint.h>
//#else
//#error "no HAVE_INTTYPES_H or HAVE_STDINT_H"
//#endif
//#endif

#ifdef _MSC_VER
// C99 types 
 typedef signed char     int8_t;
 typedef signed char     int_least8_t;
 typedef signed char     int_fast8_t;
 typedef unsigned char   uint8_t;
 typedef unsigned char   uint_least8_t;
 typedef unsigned char   uint_fast8_t;

 typedef short           int16_t;
 typedef short           int_least16_t;
 typedef short           int_fast16_t;
 typedef unsigned short  uint16_t;
 typedef unsigned short  uint_least16_t;
 typedef unsigned short  uint_fast16_t;



 typedef long            int32_t;
 typedef long            int_least32_t;
 typedef long            int_fast32_t;
 typedef unsigned long   uint32_t;
 typedef unsigned long   uint_least32_t;
 typedef unsigned long   uint_fast32_t;

#else
#include <inttypes.h>
#endif


#include <limits.h>

#define MAX_UINT16_T 65536U
#define MAX_UINT32_T 4294967295U

#endif
