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
   return NULL;
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
   cout << "# ----------------------------------------------------" << endl;
   cout << "# TOPOLOGY" << endl;
   for (int i = 0; i < numIfaces; i++) {
      cout << "# " << ifaces[i]->name << " ";
      for (int j=0; j<4; j++){
	cout << ifaces[i]->ip[j];
	if (j<3)
		cout << ".";
	else
		cout << endl;
      }
   }
   cout << "# ----------------------------------------------------" << endl;
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


