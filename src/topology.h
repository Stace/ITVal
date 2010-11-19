#ifndef TOPOLOGY_H__
#define TOPOLOGY_H__
#include <iostream>
#include <string.h>
#include <stdio.h>

using namespace std;

class Interface {
 public:
   char name[256];
   int index;
   int ip[4];
     Interface(char *n, int *address) {
      strncpy(name, n, 256);
      for (int i = 0; i < 4; i++)
         ip[i] = address[i];
}};

class Topology {

 public:
   int FindInterface(char *name);
   int* GetIP(char* name);
   char *LookupInterface(int idx);
   int AddAnonymousInterface(char *name);
   void PrintMapping();

   int numIfaces;
   Interface **ifaces;

     Topology() {
      numIfaces = 0;
      ifaces = new Interface *[256];
     }

     Topology(char *fname) {
      FILE *iFile;
      char name[256];
      int ip[4];
      numIfaces = 0;
      ifaces = new Interface *[256];
      iFile = fopen(fname, "r");
      if (!iFile)
         return;
      while (EOF !=
             fscanf(iFile, "%256s %3d.%3d.%3d.%3d", name, &ip[0], &ip[1],
                    &ip[2], &ip[3])) {
         ifaces[numIfaces] = new Interface(name, ip);
         numIfaces++;
         if (numIfaces > 256) {
            cout <<  "Warning: ITVal cannot handle more than 256 interfaces!" << endl;
            return;
         }
      }
      fclose(iFile);
   }

   ~Topology();
};

#endif
