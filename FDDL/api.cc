/*
FDDL: A Free Decision Diagram Library
Copyright (C) 2004 Robert Marmorstein

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
A full-text version is located in the LICENSE file distributed with this
utility.

You may contact the author at rmmarm@wm.edu or by sending mail to:

Robert Marmorstein
Department of Computer Science
College of William and Mary
Williamsburg, VA 23185
*/

#include <stdio.h>
#include <assert.h>
#include <FDDL/mdd.h>

#define MAX(a, b) (a>b ? a : b)
#define MIN(a, b) (a<b ? a : b)

#define NON_DEBUG 1


int
fddl_forest::MakeMDDFromTuple(int *low, int *high, mdd_handle & ref)
{
	node_idx child, top;
	arc_idx s;
	level k;

#ifdef BRIEF_DEBUG
printf("MakeMDDFromTuple:\n");
printf("\t");
for (k=K;k>=0;k--){
   printf("%d-%d ", low[k], high[k]);
}
printf("\n");
#endif

	child = high[0];
	if (child > maxVals[0]) {
		printf("%d out of range at level %d\n", high[k], k);
		assert(0);
		return TUPLE_OUT_OF_BOUNDS;
	}
	for (k = 1; k <= K; k++) {
		if (high[k] > maxVals[k]) {
			DeleteNode(k - 1, child);
			printf("%d out of range at level %d\n", high[k], k);
			assert(0);
			return TUPLE_OUT_OF_BOUNDS;
		}
		top = NewNode(k);
		for (s = low[k]; s <= high[k]; s++) {
			SetArc(k, top, s, child);
		}
		child = CheckIn(k, top);
	}
	if (ref.index != child) {
		ReallocHandle(ref);
		Attach(ref, child);
	}
#ifdef BRIEF_DEBUG
printf("MakeMDDFromTuple:\n");
printf("\tIndex: %d\n", ref.index);
#endif
	return SUCCESS;
}

int 
fddl_forest::Assign(mdd_handle root, int *low, int *high, mdd_handle & result)
{
	level   k;
	node_idx child, newNode;
	arc_idx s;

#ifdef BRIEF_DEBUG
printf("MDD Assign: %d\n", root.index);
printf("\t");
for (k=K;k>=0;k--){
   printf("%d-%d ", low[k], high[k]);
}
printf("\n");
#endif

	child = high[0];
	if (child > maxVals[0]) {
		printf("%d out of range at level %d\n", child, k);
		assert(0);
		return TUPLE_OUT_OF_BOUNDS;
	}

	if (root.index < 0) {
		return MakeMDDFromTuple(low, high, result);
	}
	for (k = 1; k <= K; k++) {
		if (high[k] > maxVals[k]) {
			if (FDDL_NODE(k - 1, child).in == 1)
				DeleteDownstream(k - 1, child);
			printf("%d out of range at level %d\n", high[k], k);
			assert(0);
			return TUPLE_OUT_OF_BOUNDS;
		}
		newNode = NewNode(k);
		for (s = low[k]; s <= high[k]; s++) {
			SetArc(k, newNode, s, child);
		}
		newNode = CheckIn(k, newNode);
		child = newNode;
	}
	newNode = InternalRestrict(K, root.index, child);
	if (newNode != child)
		DeleteDownstream(K, child);
	if (result.index != newNode) {
		ReallocHandle(result);
		Attach(result, newNode);
	}
#ifdef BRIEF_DEBUG
printf("Assign Result: %d\n", result.index);
#endif
	return SUCCESS;
}

int
fddl_forest::LessThan(mdd_handle root, int value, mdd_handle & result)
{
	if (root.index < 0)
		return INVALID_MDD;
	node_idx newresult;

	for (level k = K; k > 0; k--)
		LessThanCache[k]->Clear();
	newresult = InternalLessThan(K, root.index, value);
	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
	return SUCCESS;
}

int
fddl_forest::Apply(mdd_handle* roots, int num_roots, node_idx (*func)(node_idx *, int), mdd_handle& result){

        node_idx* indices;	
        node_idx newresult;
        if (num_roots < 1)
           return INVALID_MDD;

        indices = new node_idx[num_roots];

        for (int i=0;i<num_roots;i++){
           indices[i] = roots[i].index;
           if (roots[i].index < 0){
               delete[] indices;
               return INVALID_MDD;
           }
        }

	for (level k = K; k > 0; k--)
	   ApplyCache[k]->Clear();

	newresult = InternalApply(K, indices, num_roots, func);
	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
        delete[] indices;
	return SUCCESS;
}

int
fddl_forest::ValRestrict(mdd_handle root, int value, mdd_handle & result)
{
	if (root.index < 0)
		return INVALID_MDD;
	node_idx newresult;

	newresult = InternalValRestrict(K, root.index, value);
	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
	return SUCCESS;
}

int
fddl_forest::Select(mdd_handle root, int num_chains, mdd_handle * all_roots, mdd_handle & result)
{
	node_idx *child_array;
	node_idx newresult;

	child_array = new node_idx[num_chains];

	if (root.index < 0)
		return INVALID_MDD;
	for (int i = 0; i < num_chains; i++) {
		child_array[i] = all_roots[i].index;
		if (child_array[i] < 0) {
			delete[]child_array;
			return INVALID_MDD;
		}
	}
	newresult = InternalSelect(K, root.index, num_chains, child_array);
	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
	return SUCCESS;
}

int 
fddl_forest::Replace(mdd_handle p, mdd_handle q, bool strict, 
		mdd_handle & result) { 

   node_idx newresult;

   for (level k = K; k > 0; k--) {
		ReplaceCache[k]->Clear();
		ReplaceStrictCache[k]->Clear();
	}
	if (p.index < 0)
		return INVALID_MDD;
	if (q.index < 0)
		return INVALID_MDD;

	if (strict) {
		newresult = InternalReplaceStrict(K, p.index, q.index);
	}
	else {
		newresult = InternalReplace(K, p.index, q.index);
	}
	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
	return SUCCESS;
}

int 
fddl_forest::ProjectOnto(mdd_handle p, mdd_handle q, mdd_handle & result)
{ 

   node_idx newresult;

   for (level k = K; k > 0; k--) {
		ProjectOntoCache[k]->Clear();
	}
	if (p.index < 0)
		return INVALID_MDD;

	if (q.index < 0)
		return INVALID_MDD;

        newresult = InternalProjectOnto(K, p.index, q.index);
   
	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
	return SUCCESS;
}

int
fddl_forest::Combine(mdd_handle root, mdd_handle root2, int chain_index, 
		mdd_handle & result)
{
	if (root.index < 0)
		return INVALID_MDD;
	if (root2.index < 0)
		return INVALID_MDD;
	node_idx newresult;

	newresult = InternalCombine(K, root.index, root2.index, chain_index);
	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
	return SUCCESS;
}

node_idx 
fddl_forest::InternalLessThan(level k, node_idx p, int value)
{
	arc_idx i;
	node_idx result, u;
	node   *victim;
	int psize;

	if (k == 0) {
		if (p < value)
			return p;
		return 0;
	};

	if (p == 0) {
		return 0;
	}

	result = LessThanCache[k]->Hit(p, value);
	if (result >= 0)
		return result;

	result = NewNode(k);
	victim = &FDDL_NODE(k, p);
	psize = victim->size;
	for (i = 0; i < psize; i++) {
		u = InternalLessThan(k - 1, FULL_ARC(k, victim, i), value);
		SetArc(k, result, i, u);
	}
	result = CheckIn(k, result);
	LessThanCache[k]->Add(p, value, result);
	return result;
}

node_idx 
fddl_forest::InternalApply(level k, node_idx* roots, int num_roots, 
node_idx (*func)(node_idx *, int))
{
	node_idx i;
	arc_idx j;
	node_idx result, u;
	node_idx *indices;

	if (k == 0) {
           return func(roots, num_roots);
	};

	result = ApplyCache[k]->Hit(roots, num_roots);
	if (result >= 0)
           return result;

	result = NewNode(k);

        indices = new node_idx[num_roots];
         
        for (j=0;j<=maxVals[k];j++){
           for (i=0;i<num_roots;i++){
              node* nodeP;
              nodeP = &FDDL_NODE(k,roots[i]);
              if (j<nodeP->size){
                 indices[i] = FDDL_ARC(k,nodeP, j);
              }
              else
                 indices[i] = 0;
           }
	   u = InternalApply(k - 1, indices, num_roots, func);
	   SetArc(k, result, j, u);
        }
	result = CheckIn(k, result);
	ApplyCache[k]->Add(roots, num_roots, result);
        delete[] indices;
	return result;
}

node_idx 
fddl_forest::InternalValRestrict(level k, node_idx p, int value)
{
	arc_idx i;
	node_idx result, u;
	node   *victim;
	int psize;
	arc_idx *ptemp;

	if (k == 0) {
		if (p == value)
			return p;
		return 0;
	};

	result = ValRestrictCache[k]->Hit(p, value);
	if (result >= 0)
		return result;

	result = NewNode(k);
	if (p == 0) {
		return 0;
	}
	victim = &FDDL_NODE(k, p);
	if (IS_SPARSE(victim)) {	  //If node <k.p> is stored sparsely, unpack it into a static array of appropriate size
		psize = UnpackNode(k, p, ptemp);
	}
	else {
		psize = victim->size;
		ptemp = new node_idx[psize];

		for (i = 0; i < psize; i++)
			ptemp[i] = FULL_ARC(k, victim, i);
	}
	for (i = 0; i < psize; i++) {
		u = InternalValRestrict(k - 1, ptemp[i], value);
		SetArc(k, result, i, u);
	}
	result = CheckIn(k, result);
	ValRestrictCache[k]->Add(p, value, result);
	delete[]ptemp;
	return result;
}

node_idx 
fddl_forest::InternalSelect(level k, node_idx p, int num_chains, 
		node_idx *child_array)
{

	if (p == 0) {
		return p;
	}

	if (k == 0) {
		while (p > 4) {
			assert(p - 4 < num_chains);
			p = child_array[p - 4];
		}
		return p;
	}

	node_idx r;

	r = SelectCache[k]->Hit(p, child_array, num_chains);
	if (r >= 0)
		return r;

	node   *nodeP;
	node   *nodeR;

	r = NewNode(k);
	nodeP = &FDDL_NODE(k, p);
	nodeR = &FDDL_NODE(k, r);

	for (int i = 0; i < nodeP->size; i++) {
		node_idx u;
		node_idx *grandchild_array;
		grandchild_array = new node_idx[num_chains];

		for (int j = 0; j < num_chains; j++) {
			node   *nodeJ;

			nodeJ = &FDDL_NODE(k, child_array[j]);
			grandchild_array[j] = FDDL_ARC(k, nodeJ, i);
		}
		u = InternalSelect(k - 1, FDDL_ARC(k, nodeP, i), num_chains,
								 grandchild_array);
		delete[]grandchild_array;
		//Do I need to union what's already there with what's coming?
		SetArc(k, r, i, u);
		//No.
	}
	r = CheckIn(k, r);
	SelectCache[k]->Add(p, child_array, num_chains, r);
	return r;
}

node_idx 
fddl_forest::InternalReplace(level k, node_idx p, node_idx q)
{

	if (p == 0 || p == q)
		return q;

	if (q == 0) {
		return p;
	}

	if (k == 0) {
		/*
		 * if (p == 0)
		 * return 0;
		 * if (q == 0)
		 * return p;
		 */
		return q;
	}

	node_idx r;

	r = ReplaceCache[k]->Hit(p, q);
	if (r >= 0)
		return r;

	node   *nodeP;
	node   *nodeQ;
	node   *nodeR;

	nodeP = &FDDL_NODE(k, p);
	nodeQ = &FDDL_NODE(k, q);

	r = NewNode(k);
	nodeR = &FDDL_NODE(k, r);

	for (int i = 0; i < MAX(nodeP->size, nodeQ->size); i++) {
		node_idx u;

		u = InternalReplace(k - 1,
								  i < nodeP->size ? FDDL_ARC(k, nodeP, i) : 0,
								  i < nodeQ->size ? FDDL_ARC(k, nodeQ, i) : 0);
		SetArc(k, r, i, u);
	}
	r = CheckIn(k, r);
	ReplaceCache[k]->Add(p, q, r);
	return r;
}

node_idx 
fddl_forest::InternalProjectOnto(level k, node_idx p, node_idx q)
{

	if (q == 0) 
           return 0;

	if (p == 0) {
	   return q;
	}

	if (k == 0) 
           return p;

	node_idx r;

	r = ProjectOntoCache[k]->Hit(p, q);
	if (r >= 0)
		return r;

	node   *nodeP;
	node   *nodeQ;
	node   *nodeR;

	nodeP = &FDDL_NODE(k, p);
	nodeQ = &FDDL_NODE(k, q);

	r = NewNode(k);
	nodeR = &FDDL_NODE(k, r);

	for (int i = 0; i < MAX(nodeP->size, nodeQ->size); i++) {
		node_idx u;

                u = InternalProjectOnto(k - 1, i < nodeP->size ?
                FDDL_ARC(k, nodeP, i) : 0, i < nodeQ->size ? FDDL_ARC(k,
                nodeQ, i) : 0);

		SetArc(k, r, i, u);
	}
	r = CheckIn(k, r);
	ProjectOntoCache[k]->Add(p, q, r);
	return r;
}

node_idx 
fddl_forest::InternalReplaceStrict(level k, node_idx p, node_idx q)
{
	if (p == 0) {
		return 0;
	}

	if (q == 0) {
		return p;
	}

	if (k == 0) {
		return q;
	}

	node_idx r;

	r = ReplaceStrictCache[k]->Hit(p, q);
	if (r >= 0) {
		return r;
	}

	node   *nodeP;
	node   *nodeQ;
	node   *nodeR;

	nodeP = &FDDL_NODE(k, p);
	nodeQ = &FDDL_NODE(k, q);

	r = NewNode(k);
	nodeR = &FDDL_NODE(k, r);

	for (int i = 0; i < MAX(nodeP->size, nodeQ->size); i++) {
		node_idx u;

		u = InternalReplaceStrict(k - 1,
										  i < nodeP->size ? FDDL_ARC(k, nodeP,
																			  i) : 0,
										  i < nodeQ->size ? FDDL_ARC(k, nodeQ, i) : 0);
		SetArc(k, r, i, u);
	}
	r = CheckIn(k, r);
	ReplaceStrictCache[k]->Add(p, q, r);
	return r;
}

node_idx 
fddl_forest::InternalCombine(level k, node_idx p, node_idx q, int chain_index)
{
	arc_idx i;
	node_idx result, u;
	node   *nodeP, *nodeQ;
	int     psize, qsize;
	int     dummy;
	arc_idx *ptemp;
	arc_idx *qtemp;

	if (p == 0)
		return 0;
	if (q == 0)
		return p;
	if (k == 0) {
		if (p == chain_index + 4) {
			return q;
		}
		return p;
	}
	dummy = 1;
	result = CombineCache[k]->Hit(p, q, chain_index);
	if (result >= 0)
		return result;

	result = NewNode(k);
	nodeP = &FDDL_NODE(k, p);
	nodeQ = &FDDL_NODE(k, q);

	if (IS_SPARSE(nodeP)) {		  //If node <k.p> is stored sparsely, unpack it into a static array of appropriate size
		psize = UnpackNode(k, p, ptemp);
	}
	else {
		psize = nodeP->size;
		ptemp = new node_idx[psize];

		for (i = 0; i < psize; i++)
			ptemp[i] = FULL_ARC(k, nodeP, i);
	}
	if (IS_SPARSE(nodeQ)) {		  //If node <k.q> is stored sparsely, unpack it into a static array of appropriate size
		qsize = UnpackNode(k, q, qtemp);
	}
	else {
		qsize = nodeQ->size;
		qtemp = new node_idx[qsize];

		for (i = 0; i < qsize; i++)
			qtemp[i] = FULL_ARC(k, nodeQ, i);
	}
	for (i = 0; i < psize; i++) {
		u = InternalCombine(k - 1, ptemp[i], i < qsize ? qtemp[i] : 0,
								  chain_index);
		SetArc(k, result, i, u);
	}
	delete[]qtemp;
	delete[]ptemp;
	result = CheckIn(k, result);
	CombineCache[k]->Add(p, q, chain_index, result);
	return result;
}

int
fddl_forest::Max(mdd_handle a, mdd_handle b, mdd_handle & result)
{
	if (a.index < 0 || b.index < 0)
		return MAX_FAILED;
	node_idx newresult;

	newresult = InternalMax(K, a.index, b.index);
	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
	return SUCCESS;
}

int
fddl_forest::Min(mdd_handle a, mdd_handle b, mdd_handle & result)
{
	if (a.index < 0 || b.index < 0)
		return MIN_FAILED;
	node_idx newresult;

	newresult = InternalMin(K, a.index, b.index);
	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
	return SUCCESS;
}

int
fddl_forest::Equals(mdd_handle a, mdd_handle b, mdd_handle & result)
{
	if (a.index < 0 || b.index < 0)
		return MIN_FAILED;
	node_idx newresult;

	newresult = InternalEquals(K, a.index, b.index);
	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
	return SUCCESS;
}

int fddl_forest::Complement(mdd_handle a, mdd_handle & result)
{
	if (a.index < 0)
		return COMPLEMENT_FAILED;
	node_idx newresult;

	newresult = InternalComplement(K, a.index);
	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
	return SUCCESS;
}

int
fddl_forest::BinaryComplement(mdd_handle a, mdd_handle & result)
{
	if (a.index < 0)
		return COMPLEMENT_FAILED;
	node_idx newresult;

	newresult = InternalBComplement(K, a.index);
	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
	return SUCCESS;
}

//Simple Recursive Minimum of <k,p> and <k,q>
node_idx 
fddl_forest::InternalMin(level k, node_idx p, node_idx q)
{
	//Easy Terminal Cases
	if (p == 0 || q == 0)
		return 0;
	if (p == q)
		return q;
	if (k == 0)
		return p > q ? q : p;

	//Check for an entry in the Cache.
	node_idx result;

	result = MinCache[k]->Hit(p, q);
	if (result >= 0) {
		if (!(FDDL_NODE(k, result).flags & DELETED))
			return result;
		return CheckIn(k, result);
	}

	result = NewNode(k);
	node   *nodeP = &FDDL_NODE(k, p);
	node   *nodeQ = &FDDL_NODE(k, q);

	int psize = nodeP->size;
	int qsize = nodeQ->size;

	//If neither node is sparse, do things the easy way.
	if (!IS_SPARSE(nodeP) && !IS_SPARSE(nodeQ)) {
		for (arc_idx i = 0; i < (psize > qsize ? psize : qsize); i++) {
			node_idx u =
				InternalMin(k - 1, i < psize ? FULL_ARC(k, nodeP, i) : 0,
								i < qsize ? FULL_ARC(k, nodeQ, i) : 0);

			SetArc(k, result, i, u);
		}
	}
	else if (IS_SPARSE(nodeP) && IS_SPARSE(nodeQ)) {
		//If both nodes are sparse, do things the fast way!
		//Scan from left to right.  If i is the smaller value, put it in the
		//node.  If j is the smaller value, put it in the node.  If i==j, put
		//the union of i and j in the node.  

		for (arc_idx i = 0, j = 0; i < psize && j < qsize;) {
			arc_idx pdx = SPARSE_INDEX(k, nodeP, i);
			node_idx pval = SPARSE_ARC(k, nodeP, i);
			arc_idx qdx = SPARSE_INDEX(k, nodeQ, j);
			node_idx qval = SPARSE_ARC(k, nodeQ, j);

			if (pdx < qdx) {
				SetArc(k, result, pdx, 0);
				i++;
			}
			else if (qdx < pdx) {
				SetArc(k, result, qdx, 0);
				j++;
			}
			else {
				SetArc(k, result, pdx, InternalMin(k - 1, pval, qval));
				i++;
				j++;
			}
		}
	}
	else {
		if (IS_SPARSE(nodeP) && !IS_SPARSE(nodeQ)) {
			int j = 0;

			for (int i = 0; i < nodeP->size && j < nodeQ->size;) {
				int idx = SPARSE_INDEX(k, nodeP, i);
				int ival = SPARSE_ARC(k, nodeP, i);
				int jval = FULL_ARC(k, nodeQ, j);

				if (j < idx) {
					SetArc(k, result, j, 0);
					j++;
				}
				else if (idx < j) {
					SetArc(k, result, idx, 0);
					i++;
				}
				else {
					SetArc(k, result, j, InternalMin(k - 1, ival, jval));
					i++;
					j++;
				}
			}
		}
		else if (IS_SPARSE(nodeQ) && !IS_SPARSE(nodeP)) {
			int i = 0;

			for (int j = 0; j < nodeQ->size && i < nodeP->size;) {
				int jdx = SPARSE_INDEX(k, nodeQ, j);
				int jval = SPARSE_ARC(k, nodeQ, j);
				int ival = FULL_ARC(k, nodeP, i);

				if (i < jdx) {
					SetArc(k, result, i, 0);
					i++;
				}
				else if (jdx < i) {
					SetArc(k, result, jdx, 0);
					j++;
				}
				else {
					SetArc(k, result, i, InternalMin(k - 1, ival, jval));
					i++;
					j++;
				}
			}

		}
	}

	node_idx newresult = CheckIn(k, result);

//	if (k > 0 && newresult)
//		FDDL_NODE(k, newresult).flags |= CHECKED_IN;
	MinCache[k]->Add(p, q, newresult);
	MinCache[k]->Add(q, p, newresult);
	MinCache[k]->Add(p, newresult, newresult);
	MinCache[k]->Add(q, newresult, newresult);
	return newresult;
}

node_idx 
fddl_forest::InternalEquals(level k, node_idx p, node_idx q)
{
	//Easy Terminal Cases
	if (p * q == 0)
 	   return 0;

	if (k == 0){
	   return p == q ? 0 : p;
	}

	//Check for an entry in the Cache.
	node_idx result;

	result = EqualsCache[k]->Hit(p, q);
	if (result >= 0) {
		if (!(FDDL_NODE(k, result).flags & DELETED))
			return result;
		return CheckIn(k, result);
	}

	result = NewNode(k);
	node   *nodeP = &FDDL_NODE(k, p);
	node   *nodeQ = &FDDL_NODE(k, q);

	int psize = nodeP->size;
	int qsize = nodeQ->size;

	//If neither node is sparse, do things the easy way.
	if (!IS_SPARSE(nodeP) && !IS_SPARSE(nodeQ)) {
		for (arc_idx i = 0; i < (psize > qsize ? psize : qsize); i++) {
			node_idx u =
				InternalEquals(k - 1, i < psize ? FULL_ARC(k, nodeP, i) : 0,
								i < qsize ? FULL_ARC(k, nodeQ, i) : 0);

			SetArc(k, result, i, u);
		}
	}
	else if (IS_SPARSE(nodeP) && IS_SPARSE(nodeQ)) {
		//If both nodes are sparse, do things the fast way!
		//Scan from left to right.  If i is the smaller value, put it in the
		//node.  If j is the smaller value, put it in the node.  If i==j, put
		//the union of i and j in the node.  

		for (arc_idx i = 0, j = 0; i < psize && j < qsize;) {
			arc_idx pdx = SPARSE_INDEX(k, nodeP, i);
			node_idx pval = SPARSE_ARC(k, nodeP, i);
			arc_idx qdx = SPARSE_INDEX(k, nodeQ, j);
			node_idx qval = SPARSE_ARC(k, nodeQ, j);

			if (pdx < qdx) {
				SetArc(k, result, pdx, 0);
				i++;
			}
			else if (qdx < pdx) {
				SetArc(k, result, qdx, 0);
				j++;
			}
			else {
				SetArc(k, result, pdx, InternalEquals(k - 1, pval, qval));
				i++;
				j++;
			}
		}
	}
	else {
		if (IS_SPARSE(nodeP) && !IS_SPARSE(nodeQ)) {
			int j = 0;

			for (int i = 0; i < nodeP->size && j < nodeQ->size;) {
				int idx = SPARSE_INDEX(k, nodeP, i);
				int ival = SPARSE_ARC(k, nodeP, i);
				int jval = FULL_ARC(k, nodeQ, j);

				if (j < idx) {
					SetArc(k, result, j, 0);
					j++;
				}
				else if (idx < j) {
					SetArc(k, result, idx, 0);
					i++;
				}
				else {
					SetArc(k, result, j, InternalEquals(k - 1, ival, jval));
					i++;
					j++;
				}
			}
		}
		else if (IS_SPARSE(nodeQ) && !IS_SPARSE(nodeP)) {
			int i = 0;

			for (int j = 0; j < nodeQ->size && i < nodeP->size;) {
				int jdx = SPARSE_INDEX(k, nodeQ, j);
				int jval = SPARSE_ARC(k, nodeQ, j);
				int ival = FULL_ARC(k, nodeP, i);

				if (i < jdx) {
					SetArc(k, result, i, 0);
					i++;
				}
				else if (jdx < i) {
					SetArc(k, result, jdx, 0);
					j++;
				}
				else {
					SetArc(k, result, i, InternalEquals(k - 1, ival, jval));
					i++;
					j++;
				}
			}

		}
	}

	node_idx newresult = CheckIn(k, result);

//	if (k > 0 && newresult)
//		FDDL_NODE(k, newresult).flags |= CHECKED_IN;
	EqualsCache[k]->Add(p, q, newresult);
	EqualsCache[k]->Add(q, p, newresult);
	EqualsCache[k]->Add(p, newresult, newresult);
	EqualsCache[k]->Add(q, newresult, newresult);
	return newresult;
}

//Simple Recursive Complement of <k,p> and <k,q>

node_idx 
fddl_forest::InternalComplement(level k, node_idx p)
{
	//Easy Terminal Cases
	if (k == 0) {
		return maxVals[0] - p;
	}
	//Check for an entry in the Cache.
	node_idx result;

	result = ComplementCache[k]->Hit(p);
	if (result >= 0) {
		if (!(FDDL_NODE(k, result).flags & DELETED))
			return result;
		return CheckIn(k, result);
	}

	node_idx newresult;

	//`Tricky' zero case

	if (p == 0) {
		result = NewNode(k);
		for (int i = 0; i <= maxVals[k]; i++)
			SetArc(k, result, i, InternalComplement(k - 1, 0));
		newresult = CheckIn(k, result);
		ComplementCache[k]->Add(p, newresult);
		ComplementCache[k]->Add(newresult, p);
		return newresult;
	}

	result = NewNode(k);

	node   *nodeP = &FDDL_NODE(k, p);

	int psize = nodeP->size;

	//If the node is not sparse, do things the easy way.
	if (!IS_SPARSE(nodeP)) {
		for (arc_idx i = 0; i <= maxVals[k]; i++) {
			node_idx u = i < psize ? InternalComplement(k - 1,
																	  FULL_ARC(k, nodeP,
																				  i)) :
				InternalComplement(k - 1, 0);
			SetArc(k, result, i, u);
		}

		newresult = CheckIn(k, result);

//		if (k > 0 && newresult)
//			FDDL_NODE(k, newresult).flags |= CHECKED_IN;

		ComplementCache[k]->Add(p, 1, newresult);
		ComplementCache[k]->Add(newresult, 1, p);
	}
	else {
		//If the node is sparse, do things the fast way!
		int i = 0;
		int ival, idx;

		while (i < psize) {
			ival = SPARSE_INDEX(k, nodeP, i);
			idx = SPARSE_ARC(k, nodeP, i);
			SetArc(k, result, ival, InternalComplement(k - 1, idx));
			i++;
		}
		for (i = 0; i <= maxVals[k]; i++) {
			if (FULL_ARC(k, &FDDL_NODE(k, result), i) == 0)
				SetArc(k, result, i, InternalComplement(k - 1, 0));
		}
		newresult = CheckIn(k, result);

//		if (k > 0 && newresult)
//			FDDL_NODE(k, newresult).flags |= CHECKED_IN;

		ComplementCache[k]->Add(p, 1, newresult);
		ComplementCache[k]->Add(newresult, 1, p);
	}
	return newresult;
}

node_idx 
fddl_forest::InternalBComplement(level k, node_idx p)
{
	//Easy Terminal Cases
	if (k == 0) {
		if (p == 0)
			return 1;
		return 0;
	}
	//Check for an entry in the Cache.
	node_idx result;

	result = BComplementCache[k]->Hit(p);
	if (result >= 0) {
		if (!(FDDL_NODE(k, result).flags & DELETED))
			return result;
		return CheckIn(k, result);
	}

	node_idx newresult;

	//`Tricky' zero case

	if (p == 0) {
		result = NewNode(k);
		for (int i = 0; i <= maxVals[k]; i++)
			SetArc(k, result, i, InternalBComplement(k - 1, 0));
		newresult = CheckIn(k, result);
		BComplementCache[k]->Add(p, newresult);
		BComplementCache[k]->Add(newresult, p);
		return newresult;
	}

	result = NewNode(k);

	node   *nodeP = &FDDL_NODE(k, p);

	int psize = nodeP->size;

	//If the node is not sparse, do things the easy way.
	if (!IS_SPARSE(nodeP)) {
		for (arc_idx i = 0; i <= maxVals[k]; i++) {
			node_idx u = i < psize ? InternalBComplement(k - 1, FULL_ARC(k, nodeP, i)) : InternalBComplement(k - 1, 0);
			SetArc(k, result, i, u);
		}

		newresult = CheckIn(k, result);

//		if (k > 0 && newresult)
//			FDDL_NODE(k, newresult).flags |= CHECKED_IN;

	}
	else {
		//If the node is sparse, do things the fast way!
		int i = 0;
		int ival, idx;

		while (i < psize) {
			ival = SPARSE_INDEX(k, nodeP, i);
			idx = SPARSE_ARC(k, nodeP, i);
			SetArc(k, result, ival, InternalBComplement(k - 1, idx));
			i++;
		}
		for (i = 0; i <= maxVals[k]; i++) {
			if (FULL_ARC(k, &FDDL_NODE(k, result), i) == 0)
				SetArc(k, result, i, InternalBComplement(k - 1, 0));
		}
		newresult = CheckIn(k, result);

//		if (k > 0 && newresult)
//			FDDL_NODE(k, newresult).flags |= CHECKED_IN;
	}

	BComplementCache[k]->Add(p, newresult);
	BComplementCache[k]->Add(newresult, p);
	return newresult;
}

int
fddl_forest::DestroyMDD(mdd_handle mdd)
{
#ifdef BRIEF_DEBUG
printf("Destroy MDD: %d\n", mdd.index);
#endif
	if (mdd.index <= 0)
		return INVALID_MDD;
	FDDL_NODE(K, mdd.index).in--;
	if (FDDL_NODE(K, mdd.index).in < 1) {
		DeleteDownstream(K, mdd.index);
	}
        CompactCounter++;
        if (CompactCounter>100){
           for (level k=K;k>0;k--){
              Compact(k);
              CompactCounter=0;
           }
        }
	return SUCCESS;
}

void
fddl_forest::ReallocHandle(mdd_handle & ref)
{
	if (ref.index > 0) {
		DestroyMDD(ref);
	}
}

int
fddl_forest::Value(mdd_handle hand, int *tup, int &result)
{
	if (hand.index < 0)
		return INVALID_MDD;
	result = Value(K, hand.index, tup);
	return SUCCESS;
}

int 
fddl_forest::Value(level k, node_idx p, int *tup)
{
	if (k == 0)
		return p;
	if (p == 0)
		return 0;
	node   *nodeP = &FDDL_NODE(k, p);

	if (IS_SPARSE(nodeP)) {
		for (arc_idx i = 0; i < nodeP->size; i++)
			if (SPARSE_INDEX(k, nodeP, i) == tup[k])
				return Value(k - 1, SPARSE_ARC(k, nodeP, i), tup);
		return 0;
	}
	else {
		if (tup[k] < nodeP->size)
			return Value(k - 1, FULL_ARC(k, nodeP, tup[k]), tup);
		return 0;
	}
}

int 
fddl_forest::GetMaxVal(level k)
{
	if (k >= 0 && k <= K)
		return maxVals[k];
	else
		return INVALID_LEVEL;
}

int
fddl_forest::ChangeMaxVal(level k, int maxval)
{
	assert(maxval >= 0);			  //To "disable" range checking, the user
	assert(0 <= k && k <= K);	  //should specify a range of "INT_MAX".
	if (maxval == INT_MAX) {
		maxVals[k] = maxval;
		return SUCCESS;
	}

	if (k > 0) {
		for (node_idx i = 0; i < last[k]; i++) {
			node   *nodeP = &FDDL_NODE(k, i);

			if (IS_SPARSE(nodeP)) {
				for (int j = 0; j < nodeP->size; j++)
					if (SPARSE_ARC(k, nodeP, j) > maxval)
						return TUPLE_OUT_OF_BOUNDS;
			}
			else if (nodeP->size > maxval)
				return TUPLE_OUT_OF_BOUNDS;
		}
	}
	else {
		for (int j = 0; j < tail[1]; j++) {
			if ((*(*arcs[1])[j]) > maxval)
				return TUPLE_OUT_OF_BOUNDS;
		}
	}
	maxVals[k] = maxval;
	return SUCCESS;
}

int fddl_forest::FindRange(level k){
   int i;
	int maxVal;
	node* nodeP;
	maxVal = 0;
	for (i=1;i<last[k];i++){
           nodeP = &FDDL_NODE(k,i);
		if (IS_SPARSE(nodeP)){
         if (SPARSE_ARC(k,nodeP,nodeP->size-1) > maxVal)
			   maxVal = SPARSE_INDEX(k,nodeP, nodeP->size-1);
		}
		else{
         if (nodeP->size > maxVal)
		      maxVal = nodeP->size;
		}
	}
	return maxVal;
}

//Bring level "kold" to the top of the MDD.
int fddl_forest::Shift(mdd_handle h, level kold, mdd_handle& result){
	int temp;
	if (h.index < 0)
	   return COMPLEMENT_FAILED;

	node_idx newresult;
	
	for (level k = K; k > 0; k--)
		ShiftCache[k]->Clear();

	level current=kold;
        newresult = h.index;
	while (current < K){
      //Swap level "current" with level "current+1".
	   newresult = InternalShift(K, newresult, current+1);
	   current++;
	}

	if (result.index != newresult) {
		ReallocHandle(result);
		Attach(result, newresult);
	}
	return SUCCESS;
}


node_idx fddl_forest::InternalShift(level k, node_idx p, level target){
   node_idx r;
	int maxVal;
	node* nodeP;


	if (p==0) return 0;
	if (k==0) return p; //Probably Not Correct.
	
	nodeP = &FDDL_NODE(k,p);

	r = ShiftCache[k]->Hit(p, target);
	if (r>=0)
	   return r;

	r = NewNode(k);

   if (k>target){
      for (int i=0;i<nodeP->size;i++){
			 node_idx m;
			 m = FDDL_ARC(k,nodeP,i);
          SetArc(k,r,i,InternalShift(k-1, m, target));
		}
		r = CheckIn(k,r);
		ShiftCache[k]->Add(p,target,r);
		return r;
	}
	
	maxVal = FindRange(k-1);

#ifndef NON_DEBUG
   printf("Range(%d): %d\n", k-1,maxVal);
#endif

   for (int val=0;val<maxVal;val++){
      node_idx t;
		t = NewNode(k-1);
#ifndef NON_DEBUG
   printf("Created node: %d\n", t);
#endif
		for (int i=0;i<nodeP->size;i++){
         node_idx j;
			node_idx n;
			j = FDDL_ARC(k,nodeP, i);
#ifndef NON_DEBUG
   printf("<%d,%d>[%d] = %d\n", k,p,i,j);
#endif
			node* nodeJ = &FDDL_NODE(k-1, j);
			if (val<nodeJ->size){
			   n = FDDL_ARC(k-1, nodeJ, val);
#ifndef NON_DEBUG
   printf("<%d,%d>[%d] = %d\n", k-1,j,val,n);
#endif
			   SetArc(k-1,t,i,n);
#ifndef NON_DEBUG
   printf("Setting Arc from <%d,%d>[%d] to %d\n", k-1,t,i,n);
#endif
         }
      }
      t = CheckIn(k-1,t);
#ifndef NON_DEBUG
      printf("Checked in Node.  Result: %d\n", t);
#endif
      SetArc(k,r,val, t);
#ifndef NON_DEBUG
      printf("Setting Arc from <%d,%d>[%d] to %d\n", k,r,val,t);
#endif
	}
	r = CheckIn(k,r);
#ifndef NON_DEBUG
   printf("Checked in Node.  Result: %d\n", r);
#endif
	ShiftCache[k]->Add(p,target,r);
	return r;
}
