#include "topology.h"
  
Topology::~Topology() {
   if (!ifaces)
      return;
      for (int i = 0; i < numIfaces; i++){
	 if (ifaces[i]){
            delete ifaces[i];
	    ifaces[i] = NULL;
	 }
      }
      delete[]ifaces;
      ifaces = NULL;
   }

int Topology::FindInterface(char *name)
{
   int i;
   for (i = 0; i < numIfaces; i++) {
      if (strncmp(name, ifaces[i]->name, 256) == 0)
         return i;
   }
   return -1;
}

char *Topology::LookupInterface(int idx)
{
   if (idx < numIfaces)
      return ifaces[idx]->name;
   return "any";
//   return NULL;
}

int Topology::AddAnonymousInterface(char *name)
{
   int addy[4];
   for (int i = 0; i < 4; i++)
      addy[i] = -1;
   if (numIfaces > 255)
      return 0;
   ifaces[numIfaces] = new Interface(name, addy);
   ifaces[numIfaces]->index = numIfaces;
   numIfaces++;
   return numIfaces - 1;
}

void Topology::PrintMapping()
{
   printf("# ----------------------------------------------------\n");
   printf("# TOPOLOGY\n");
   for (int i = 0; i < numIfaces; i++) {
      printf("# %s %d.%d.%d.%d\n", ifaces[i]->name, ifaces[i]->ip[0],
             ifaces[i]->ip[1], ifaces[i]->ip[2], ifaces[i]->ip[3]);
   }
   printf("# ----------------------------------------------------\n");
}

int* Topology::GetIP(char * name){
   int ifnum;
   int* ip;
   ifnum = FindInterface(name);
   if (ifnum<0)
      return NULL;
   ip = new int[4];
   for (int i=0;i<4;i++){
      ip[i] = ifaces[ifnum]->ip[i];
   }
   return ip;
}


