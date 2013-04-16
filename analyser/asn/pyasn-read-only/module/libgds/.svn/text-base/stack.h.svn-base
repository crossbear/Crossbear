// ==================================================================
// @(#)stack.h
//
// Stack
//
// @author Bruno Quoitin (bruno.quoitin@uclouvain.be)
// @date 21/03/2003
// $Id: stack.h 293 2009-03-27 11:46:04Z bquoitin $
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
 * Provide a data structure and functions to manage stacks (LIFO
 * queues).
 */

#ifndef __STACK_H__
#define __STACK_H__

typedef struct {
  int    max_depth;
  int    depth;
  void * items[0];
} gds_stack_t;

#ifdef __cplusplus
extern "C" {
#endif
  
  // ----- stack_create ---------------------------------------------
  /**
   * Create a stack.
   *
   * \param max_depth is the maximum depth.
   */
  gds_stack_t * stack_create(int max_depth);

  // ----- stack_destroy --------------------------------------------
  /**
   * Destroy a stack.
   *
   * \param stack_ref is a pointer to the stack to be destroyed.
   */
  void stack_destroy(gds_stack_t ** stack_ref);

  // ----- stack_push -----------------------------------------------
  /**
   * Push an item onto the stack.
   *
   * \param stack is the target stack.
   * \param data is the item to be pushed.
   * \retval 0 in case of success,
   *         or < 0 in case of failure (stack is full).
   */
  int stack_push(gds_stack_t * stack, void * data);

  // ----- stack_pop ------------------------------------------------
  /**
   * Pop an item from teh stack.
   *
   * \param stack is the source stack.
   * \retval the latest item pushed,
   *         or NULL if the stack is empty.
   */
  void * stack_pop(gds_stack_t * stack);

  // ----- stack_top ------------------------------------------------
  /**
   * Return the top of stack item (don't pop).
   *
   * \param stack is the source stack.
   * \retval the top item, or NULL if the stack is empty.
   */
  void * stack_top(gds_stack_t * stack);

  // ----- stack_get_at ---------------------------------------------
  void * stack_get_at(gds_stack_t * stack, unsigned int index);

  // ----- stack_depth ----------------------------------------------
  /**
   * Return the depth of the stack.
   *
   * \param stack is the target stack.
   * \retval the stack's depth.
   */
  int stack_depth(gds_stack_t * stack);

  // ----- stack_is_empty -------------------------------------------
  /**
   * Test if the stack is empty.
   *
   * \param stack is the source stack.
   * \retval 1 if the stack is empty, or 0 if it is not.
   */
  int stack_is_empty(gds_stack_t * stack);

  // ----- stack_copy -----------------------------------------------
  gds_stack_t * stack_copy(gds_stack_t * stack);

  // ----- stack_equal ----------------------------------------------
  int stack_equal(gds_stack_t * stack1, gds_stack_t * stack2);

#ifdef __cplusplus
}
#endif

#endif /* __STACK_H__ */
