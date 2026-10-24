/* Owned standalone fixture. Build with gcc -O0 -g -fPIC -shared. Never runs in static tests. */
int owned_add(int x) { return x + 7; }
int (*volatile owned_pointer)(int) = owned_add;
int owned_indirect(int x) { return owned_pointer(x); }
int owned_direct(int x) { return owned_add(x); }
int owned_memory(int *x) { return *x; }
int owned_value(int x) { return x + 7; }
