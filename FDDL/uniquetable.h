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
#ifndef FDDL_UNIQUE_TABLE_H
#   define FDDL_UNIQUE_TABLE_H 1

#   include <FDDL/mddtypes.h>
#   include <FDDL/dynarray.h>

#   define TABLE_SIZE 1009
class   uniquetable {

	unsigned int (*hashfunc) (level, node_idx);
	int     (*compare) (level, node_idx, node_idx);
	class   table_node {
	 public:
		level   k;
		node_idx p;
		table_node *next;
		        table_node() {
			next = NULL;
	}};

	table_node ***table;
	int     numlevels;

 public:
	uniquetable(int K, unsigned int (*h) (level, node_idx),
					int (*c) (level, node_idx, node_idx)) {
		numlevels = K + 1;
		table = new table_node **[numlevels];
		for (int i = 0; i < numlevels; i++) {
			table[i] = new table_node *[TABLE_SIZE];
			for (int j = 0; j < TABLE_SIZE; j++) {
				table[i][j] = NULL;
			}
		}
		hashfunc = h;
		compare = c;
	}
	~uniquetable() {
		table_node *cur;

		for (int i = 0; i < numlevels; i++) {
			for (int j = 0; j < TABLE_SIZE; j++) {
				while (table[i][j] != NULL) {
					cur = table[i][j];
					table[i][j] = cur->next;
					delete  cur;
				}
			}
			delete[]table[i];
		}
		delete[]table;
	}
	int     LookUp(level k, node_idx p);
	int     Add(level k, node_idx p);
	int     Delete(level k, node_idx p);
	int     Remap(level k, dynarray < node_idx >*transTable);
};
#endif
