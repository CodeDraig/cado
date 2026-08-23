#ifndef CADO_CONST_H
#define CADO_CONST_H

#include <cado_paths.h>

#define DEFAULT_MESSAGE \
	"# This is a scado file.\n" \
	"# format: absolute-path : capability-list [ : 64-hex-digit SHA-256 ]\n" \
	"# While editing, an empty third field requests a digest; it is filled before installation.\n"

#define TMP_TEMPLATE "cado-scado.XXXXXX"
#define TMPDIR "/tmp"

#define DIGEST_WARNING "***********************************************************\n" \
	"*         WARNING: EXECUTABLE DIGEST HAS CHANGED!         *\n" \
	"***********************************************************\n" \
	"The executable no longer matches the digest in the scado file.\n"

#define COPY_DIR CADO_EXE_DIR
#define COPY_TEMPLATE "cado-exe-copy.XXXXXX"

#endif
