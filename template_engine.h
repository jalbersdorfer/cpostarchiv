#ifndef TEMPLATE_ENGINE_H
#define TEMPLATE_ENGINE_H

#include <stddef.h>

char *tpl_render_file(
    const char *dir,
    const char *name,
    const char **keys,
    const char **values,
    size_t nvars,
    char *err,
    size_t err_len
);

#endif
