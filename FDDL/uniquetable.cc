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
#include "uniquetable.h"

int
uniquetable::LookUp(level k, node_idx p)
{
	table_node *cur;
	unsigned int idx;

	idx = hashfunc(k, p) % TABLE_SIZE;
	cur = table[k][idx];
	while (cur != NULL) {
		if (compare(k, p, cur->p) == 1) {
			return cur->p;
		}
		cur = cur->next;
	}
	return -1;
}

int
uniquetable::Add(level k, node_idx p)
{
	node_idx r;
	table_node *newNode;
	unsigned int idx;

	r = LookUp(k, p);
	if (r != -1)
		return r;

	idx = hashfunc(k, p) % TABLE_SIZE;

	newNode = new table_node;
	newNode->k = k;
	newNode->p = p;
	newNode->next = table[k][idx];
	table[k][idx] = newNode;
	return p;
}

int
uniquetable::Delete(level k, node_idx p)
{
	table_node *cur;
	table_node *prev;
	unsigned int idx;

	idx = hashfunc(k, p) % TABLE_SIZE;

	prev = NULL;
	cur = table[k][idx];

	while (cur != NULL) {
		if (compare(k, p, cur->p) == 1) {
			if (prev == NULL) {
				table[k][idx] = cur->next;
				delete cur;
			}
			else {
				prev->next = cur->next;
				delete cur;
			}
			return 1;
		}
		prev = cur;
		cur = cur->next;
	}
	return 0;
}

int
uniquetable::Remap(level k, dynarray < node_idx >*transTable)
{
	int i;
	table_node *cur;
	node_idx newP;

	for (i = 0; i < TABLE_SIZE; i++) {
		cur = table[k][i];
		while (cur != NULL) {
			newP = (*(*transTable)[cur->p]);
			cur->p = newP;
			cur = cur->next;
		}
	}
}
