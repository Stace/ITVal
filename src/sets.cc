#include "sets.h"
#include "fwmdd.h"

void    
fw_fddl_forest::PrintPort(mdd_handle root, level k)
{
	node_idx newRoot;
	portset *p;

	p = new portset();

	for (level k1 = K; k1 > 0; k1--) {
		FlushCaches(k1);
	}

	PrintPort(K, root.index, 0, k, p);

	p->PrintPorts();

	if (p->numPorts == 1) {
		printf("\n# 1 result.\n");
	}
	else
		printf("\n# %d results.\n", p->numPorts);

	delete p;
}

int 
fw_fddl_forest::PrintPort(level k, node_idx p, int highByte, level cutoff, 
		portset * ps)
{
	int     i;
	int     flag;

	if (p == 0)
		return 0;

	if (k == 0)
		return (p > 0);

	flag = PrintCache[k]->Hit(p);
	if (flag >= 0)
		return flag;

	node   *nodeP = &FDDL_NODE(k, p);

	if (k == cutoff) {
		for (int i = 0; i < nodeP->size; i++) {
			if (PrintPort(k - 1, FDDL_ARC(k, nodeP, i), highByte, cutoff, ps)
				 == 1)
				ps->InsertPort(highByte * 256 + i);
		}
		return 1;
	}

	int     r;

	r = 0;
	for (i = 0; i < nodeP->size; i++) {
		flag = PrintPort(k - 1, highByte, i, cutoff, ps);
		if (flag != 0)
			r = 1;
	}
	PrintCache[k]->Add(p, 1);
	return r;
}
