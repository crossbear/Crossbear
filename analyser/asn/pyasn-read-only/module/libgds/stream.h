// ==================================================================
// @(#)stream.h
//
// @author Bruno Quoitin (bruno.quoitin@uclouvain.be)
// @author Sebastien Tandel
// @date 17/05/2005
// $Id: log.h 273 2008-08-21 10:00:30Z bquoitin $
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
 * Provides a generic output stream framework. Can write to files,
 * stdio streams, callbacks (and more), using the same API.
 *
 * Example:
 * \verbatim
   gds_stream_t * stream= stream_create_file("/tmp/mylog");
   stream_printf(stream, "Writes a single number: %u\n", 123);
   stream_destroy(&stream);
   \endverbatim
 */

#ifndef __GDS_STREAM_H__
#define __GDS_STREAM_H__

#include <stdarg.h>
#include <stdio.h>

#include <libgds/types.h>

// -----[ stream_level_t ]-------------------------------------------
typedef enum {
  STREAM_LEVEL_EVERYTHING,
  STREAM_LEVEL_DEBUG,
  STREAM_LEVEL_INFO,
  STREAM_LEVEL_WARNING,
  STREAM_LEVEL_SEVERE,
  STREAM_LEVEL_FATAL,
  STREAM_LEVEL_MAX
} stream_level_t;

// -----[ stream_type_t ]--------------------------------------------
typedef enum {
  STREAM_TYPE_STREAM,
  STREAM_TYPE_FILE,
  STREAM_TYPE_CALLBACK,
  STREAM_TYPE_CMD,
  STREAM_TYPE_PROCESS,
} stream_type_t ;

// -----[ gds_stream_cb_f ]------------------------------------------
/**
 * The gds_stream_cb_f function prototype allows the user to
 * implement arbitrary GDS streams that will be compatible with the
 * GDS stream API.
 *
 * \internal
 * NOTE: The main motivation for defining such a callback was to
 * send the stream data to a Java application through the Java Native
 * Interface (JNI).
 */
typedef int (*gds_stream_cb_f)(void * ctx, char * output);

// -----[ gds_stream_cb_t ]------------------------------------------
/**
 *
 */
typedef struct {
  gds_stream_cb_f callback;
  void * context;
} gds_stream_cb_t;

struct gds_stream_t;

// -----[ gds_stream_ops_t ]-----------------------------------------
/**
 * \internal
 * Virtual methods (kind of) of the stream.
 */
typedef struct {
  /** Method used to destroy the stream (destructor) */
  void (*destroy)(struct gds_stream_t * stream);
  /** Method used to flush the stream */
  int  (*flush)  (struct gds_stream_t * stream);
  /** Method used to print to the stream */
  int  (*vprintf)(struct gds_stream_t * stream, const char * format,
		  va_list ap);
} gds_stream_ops_t;

// -----[ gds_stream_t ]---------------------------------------------
/**
 * The gds_stream_t data structure holds all the data related to a
 * GDS stream.
 */
typedef struct gds_stream_t {
  /** This is the stream type. */
  stream_type_t      type;
  /** This is the current stream level. */
  stream_level_t     level;
  /** \internal This is the set of "virtual" methods of the stream. */
  gds_stream_ops_t   ops;
  /** \internal This it the callback context. */
  void             * ctx;
  union {
    FILE            * stream;
    gds_stream_cb_t   callback;
  };
} gds_stream_t;

// -----[ standard log streams ]-------------------------------------
/** gdsdebug is initialized to send its output on stderr. */
extern gds_stream_t * gdsdebug;

/** gdserr is initialized to send its output on stderr. */
extern gds_stream_t * gdserr;

/** gdsout is initialized to send its output on stdout. */
extern gds_stream_t * gdsout;

#ifdef __cplusplus
extern "C" {
#endif

  // -----[ stream_create ]------------------------------------------
  /**
   * Create a GDS stream that writes to an stdio stream.
   *
   * \param stream is the stdio stream.
   */
  gds_stream_t * stream_create(FILE * stream);

  // -----[ stream_create_file ]-------------------------------------
  /**
   * Create a GDS stream that writes to a file.
   *
   * The file will be open for writing.
   * \param filename is the name of the output file.
   */
  gds_stream_t * stream_create_file(const char * filename);

  // -----[ stream_create_callback ]---------------------------------
  /**
   * Create a GDS stream that writes to a callback function.
   *
   * \param cb  is the callback function.
   * \param ctx is the callback function's context pointer. It
   *            will be passed to the callback each time it is
   *            called.
   */
  gds_stream_t * stream_create_callback(gds_stream_cb_f cb,
					void * ctx);

  // -----[ stream_create_proc ]-------------------------------------
  /**
   * Create a GDS stream that writes to a process.
   *
   * \param cmd is the shell command line.
   */
  gds_stream_t * stream_create_proc(const char * cmd);

  // -----[ stream_destroy ]-----------------------------------------
  /**
   * Destroy an existing GDS stream.
   *
   * \param stream_ref is a pointer to the stream.
   */
  void stream_destroy(gds_stream_t ** stream_ref);

  // -----[ stream_printf ]------------------------------------------
  /**
   * Write to a GDS stream.
   *
   * \param stream is the target stream.
   * \param format is the format specifier (similar to stdio's
   *               printf function)
   * \param ...    is a variable list of arguments that will be
   *               written to the stream according to the format
   *               specifier.
   */
  int stream_printf(gds_stream_t * stream,
		    const char * format,
		    ...);

  // -----[ stream_vprintf ]-----------------------------------------
  /**
   * Write to a GDS stream using a va_list.
   *
   * \param stream is the target stream.
   * \param format is the format specifier.
   * \param ap     is the va_list (variable argument list, see
   *               stdarg.h)
   */
  int stream_vprintf(gds_stream_t * stream,
		     const char * format,
		     va_list ap);

  // -----[ stream_perror ]------------------------------------------
  /**
   * Write a message followed by the current standard error to a GDS
   * stream.
   *
   * \param stream is the target stream.
   * \param format is a format specifier for the message.
   * \param ...    is a variable list of arguments.
   */
  void stream_perror(gds_stream_t * stream,
		     const char * format,
		     ...);

  // -----[ stream_flush ]-------------------------------------------
  /**
   * Flush a GDS stream.
   *
   * \param stream is the target stream.
   */
  void stream_flush(gds_stream_t * stream);

  // -----[ stream_set_level ]---------------------------------------
  /**
   * Set the current level of a GDS stream.
   *
   * \param stream is the target stream.
   * \param level  is the new level.
   */
  void stream_set_level(gds_stream_t * stream, stream_level_t level);

  // -----[ stream_str2level ]---------------------------------------
  /**
   * Convert a textual description of a GDS stream level to a level.
   * 
   * \param str is the textual representation of the stream level.
   */
  stream_level_t stream_str2level(const char * str);

  // -----[ stream_enabled ]-----------------------------------------
  /**
   * Test if a GDS stream is enabled for the given level.
   */
  int stream_enabled(gds_stream_t * stream, stream_level_t level);

  ///////////////////////////////////////////////////////////////////
  // INITIALIZATION AND FINALIZATION FUNCTIONS
  ///////////////////////////////////////////////////////////////////

  // -----[ _stream_init ]-------------------------------------------
  void _stream_init();
  // -----[ _stream_destroy ]----------------------------------------
  void _stream_destroy();

#ifdef __cplusplus
}
#endif



/////////////////////////////////////////////////////////////////////
//
// LOG MACROS
//
/////////////////////////////////////////////////////////////////////

/* Note about variadic macros:
 * ---------------------------
 * Old versions of CPP, the C preprocessor, only support named
 * variable argument (args...).
 *
 * However, newer C99 conforming applications may only support
 * __VA_ARGS__.
 */
#ifdef __STDC_VERSION__
#if (__STDC_VERSION__ >= 199901L)
#define __VARIADIC_ELLIPSIS__
#endif
#endif

#define STREAM_DEBUG_ENABLED(LEVEL) \
  if (stream_enabled(gdsdebug, LEVEL))
#define STREAM_ERR_ENABLED(LEVEL) \
  if (stream_enabled(gdserr, LEVEL))
#define STREAM_OUT_ENABLED(LEVEL) \
  if (stream_enabled(gdsout, LEVEL))

#ifdef _MSC_VER //__VARIADIC_ELLIPSIS__

#define STREAM_DEBUG(LEVEL, ...) \
  if (stream_enabled(gdsdebug, LEVEL)) stream_printf(gdsdebug, __VA_ARGS__)
#define STREAM_ERR(LEVEL, ...) \
  if (stream_enabled(logerr, LEVEL)) stream_printf(gdserr, __VA_ARGS__)
#define STREAM_OUT(LEVEL, ...) \
  if (stream_enabled(logout, LEVEL)) stream_printf(gdsout, __VA_ARGS__)

# else /* __VARIADIC_ELLIPSIS__ */

#define STREAM_DEBUG(LEVEL, args...) \
  if (stream_enabled(gdsdebug, LEVEL)) stream_printf(gdsdebug, args)
#define STREAM_ERR(LEVEL, args...) \
  if (stream_enabled(gdserr, LEVEL)) stream_printf(gdserr, args)
#define STREAM_OUT(LEVEL, args...) \
  if (stream_enabled(gdsout, LEVEL)) stream_printf(gdsout, args)

#endif /* __VARIADIC_ELLIPSIS__ */

#endif /* __GDS_STREAM_H__ */
