/*
 * ITVal: The IPTables Firewall Validator Copyright (C) 2004 Robert
 * Marmorstein
 * 
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. A full-text
 * version is located in the LICENSE file distributed with this utility.
 * 
 * You may contact the author at rmmarm@wm.edu or by sending mail to:
 * 
 * Robert Marmorstein Department of Computer Science College of William
 * and Mary Williamsburg, VA 23185 
 */

#ifndef FDDL_CACHES_H
#   define FDDL_CACHES_H 1
#   include <FDDL/mddtypes.h>
#   define INIT_SIZE 1009

typedef class cache {
	class   cache_node {
	 public:
		node_idx p;
		node_idx q;
		node_idx s;

		node_idx r;
		cache_node *next;
		        cache_node() {
			p = -1;
			q = -1;
			s = -1;
			r = -1;
			next = NULL;
	}};

	cache_node **list;
	int     size;

 public:
	cache() {
		list = new cache_node *[INIT_SIZE];
		size = INIT_SIZE;
		for (int i = 0; i < size; i++)
			list[i] = NULL;
	}
	~cache() {
/*		for (int i = 0; i < size; i++) {
			if (list[i] != NULL)
				delete  list[i];
		}
*/
		Clear();
		delete[] list;
	}
	node_idx Hit(node_idx p);
	node_idx Hit(node_idx p, node_idx q);
	node_idx Hit(node_idx p, node_idx q, node_idx s);
	void    Add(node_idx p, node_idx r);
	void    Add(node_idx p, node_idx q, node_idx r);
	void    Add(node_idx p, node_idx q, node_idx s, node_idx r);
	void    Clear();
};

typedef class tuple_cache {
	class   cache_node {
	 public:
		node_idx p;
		node_idx *vals;
                int numvals;
		node_idx r;
		cache_node *next;
		        cache_node() {
			next = NULL;
	}};

	cache_node **list;
	int     size;

 public:
	tuple_cache() {
		list = new cache_node *[INIT_SIZE];
		size = INIT_SIZE;
		for (int i = 0; i < size; i++) {
			list[i] = NULL;
		}
	}

	~tuple_cache() {
		Clear();
/*		for (int i = 0; i < size; i++) {
			if (list[i] != NULL)
				delete  list[i];
		}
*/
		delete[]list;
	}

	node_idx Hit(node_idx *vals, int numvals);
	node_idx Hit(node_idx p, node_idx *vals, int numvals);
	void    Add(node_idx p, node_idx *vals, int numvals, node_idx r);
	void    Add(node_idx *vals, int numvals, node_idx r);
	void    Clear();
};
#endif
