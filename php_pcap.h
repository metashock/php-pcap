/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2012 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id: header 321634 2012-01-01 13:15:04Z felipe $ */

#ifndef PHP_PCAP_H
#define PHP_PCAP_H

#include <pcap.h>

extern zend_module_entry pcap_module_entry;
#define phpext_pcap_ptr &pcap_module_entry

#ifdef PHP_WIN32
#	define PHP_PCAP_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_PCAP_API __attribute__ ((visibility("default")))
#else
#	define PHP_PCAP_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

void pcap_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC);
void pcap_filter_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC);

/* Callback function passed to pcap_dispatch */
void pcap_dispatch_callback (
    u_char *user,
    const struct pcap_pkthdr *h,
    const u_char *bytes
);

PHP_MINIT_FUNCTION(pcap);
PHP_MSHUTDOWN_FUNCTION(pcap);
PHP_RINIT_FUNCTION(pcap);
PHP_RSHUTDOWN_FUNCTION(pcap);
PHP_MINFO_FUNCTION(pcap);

PHP_FUNCTION(pcap_datalink);
PHP_FUNCTION(pcap_lib_version);
PHP_FUNCTION(pcap_compile);
//PHP_FUNCTION(pcap_create());
PHP_FUNCTION(pcap_lookupdev);
PHP_FUNCTION(pcap_lookupnet);
PHP_FUNCTION(pcap_next);
PHP_FUNCTION(pcap_dispatch);
PHP_FUNCTION(pcap_open_live);
PHP_FUNCTION(pcap_open_offline);
PHP_FUNCTION(pcap_close);
PHP_FUNCTION(pcap_setfilter);
PHP_FUNCTION(pcap_geterr);

/* 
  	Declare any global variables you may need between the BEGIN
	and END macros here:     

ZEND_BEGIN_MODULE_GLOBALS(pcap)
	long  global_value;
	char *global_string;
ZEND_END_MODULE_GLOBALS(pcap)
*/

/* In every utility function you add that needs to use variables 
   in php_pcap_globals, call TSRMLS_FETCH(); after declaring other 
   variables used by that function, or better yet, pass in TSRMLS_CC
   after the last function argument and declare your utility function
   with TSRMLS_DC after the last declared argument.  Always refer to
   the globals in your function as PCAP_G(variable).  You are 
   encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/

#ifdef ZTS
#define PCAP_G(v) TSRMG(pcap_globals_id, zend_pcap_globals *, v)
#else
#define PCAP_G(v) (pcap_globals.v)
#endif

#endif	/* PHP_PCAP_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
