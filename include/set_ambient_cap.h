#ifndef CADO_SET_AMBIENT_CAP_H
#define CADO_SET_AMBIENT_CAP_H

#include <stdint.h>

int set_ambient_cap(uint64_t capset);
int drop_ambient_cap(uint64_t capset);
int drop_all_capabilities(void);
int raise_cap_dac_read_search(void);
int lower_cap_dac_read_search(void);

#endif
