/* i18n.h - common i18n declarations for psmisc programs.  */

#ifndef I18N_H
#define I18N_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef ENABLE_NLS
#include <locale.h>
#include <libintl.h>
#define _(String) gettext (String)
#else
#define _(String) (String)
#endif

#endif

