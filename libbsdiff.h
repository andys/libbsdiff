
off_t bsdiff(u_char *old, off_t oldsize, u_char *new, off_t newsize, u_char *patch, off_t patch_size);
off_t size_of_patched(u_char *patch);
int bspatch(u_char *old, off_t oldsize, u_char *patch, off_t patch_size, u_char *new);


