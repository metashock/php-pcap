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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_pcap.h"

#define le_pcap_resource_name "pcap resource"

/* If you declare any globals in php_pcap.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(pcap)
*/

/* True global resources - no need for thread safety here */
static int le_pcap_resource;

typedef struct {
    pcap_t* pcap_handle;
} pcap_resource;



/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_pcap_lookupdev, 0, 0, 2)
    ZEND_ARG_INFO(1, errbuf)
ZEND_END_ARG_INFO()


/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_pcap_open_live, 0, 0, 5)
    ZEND_ARG_INFO(0, dev)
    ZEND_ARG_INFO(0, snaplen)
    ZEND_ARG_INFO(0, promisc)
    ZEND_ARG_INFO(0, to_ms)
    ZEND_ARG_INFO(1, errbuf)
ZEND_END_ARG_INFO()

/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_pcap_datalink, 0, 0, 1)
    ZEND_ARG_INFO(0, pcap)
ZEND_END_ARG_INFO()


/* {{{ pcap_functions[]
 *
 * Every user visible function must have an entry in pcap_functions[].
 */
const zend_function_entry pcap_functions[] = {
	PHP_FE(confirm_pcap_compiled,	NULL)		/* For testing, remove later. */
	PHP_FE(pcap_lib_version,    NULL)
    PHP_FE(pcap_lookupdev,  arginfo_pcap_lookupdev)
    PHP_FE(pcap_open_live,  arginfo_pcap_open_live)
    PHP_FE(pcap_datalink,  arginfo_pcap_datalink)
	PHP_FE_END	/* Must be the last line in pcap_functions[] */
};
/* }}} */

/* {{{ pcap_module_entry
 */
zend_module_entry pcap_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"pcap",
	pcap_functions,
	PHP_MINIT(pcap),
	PHP_MSHUTDOWN(pcap),
	PHP_RINIT(pcap),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(pcap),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(pcap),
#if ZEND_MODULE_API_NO >= 20010901
	"0.1", /* Replace with version number for your extension */
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_PCAP
ZEND_GET_MODULE(pcap)
#endif

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("pcap.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_pcap_globals, pcap_globals)
    STD_PHP_INI_ENTRY("pcap.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_pcap_globals, pcap_globals)
PHP_INI_END()
*/
/* }}} */

/* {{{ php_pcap_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_pcap_init_globals(zend_pcap_globals *pcap_globals)
{
	pcap_globals->global_value = 0;
	pcap_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(pcap)
{
	/* If you have INI entries, uncomment these lines 
	REGISTER_INI_ENTRIES();
	*/
    le_pcap_resource = zend_register_list_destructors_ex(
        pcap_destruction_handler,
        NULL,
        le_pcap_resource_name,
        module_number
    );

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(pcap)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(pcap)
{
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(pcap)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(pcap)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "pcap support", "enabled");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

void pcap_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
    pcap_resource *resource = (pcap_resource *) rsrc->ptr;
    pcap_close(resource->pcap_handle);
}


/* Remove the following function when you have succesfully modified config.m4
   so that your module can be compiled into PHP, it exists only for testing
   purposes. */

/* Every user-visible function in PHP should document itself in the source */
/* {{{ proto string confirm_pcap_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(confirm_pcap_compiled)
{
	char *arg = NULL;
	int arg_len, len;
	char *strg;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &arg, &arg_len) == FAILURE) {
		return;
	}

	len = spprintf(&strg, 0, "Congratulations! You have successfully modified ext/%.78s/config.m4. Module %.78s is now compiled into PHP.", "pcap", arg);
	RETURN_STRINGL(strg, len, 0);
}


/* Every user-visible function in PHP should document itself in the source */
/* {{{ proto string confirm_pcap_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(pcap_lib_version)
{
    const char *version = pcap_lib_version();
	RETURN_STRING(version, 1);
}


/* Every user-visible function in PHP should document itself in the source */
/* {{{ proto string confirm_pcap_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(pcap_lookupdev)
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    zval *userland_errbuf = NULL;

    if(zend_parse_parameters(
        ZEND_NUM_ARGS() TSRMLS_CC,
        "z", &userland_errbuf
    ) != SUCCESS) {
        RETURN_FALSE;
    }


    convert_to_null(userland_errbuf);

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL) {
        ZVAL_STRING(userland_errbuf, errbuf, 1);
        RETURN_FALSE;
    } else { 
        RETURN_STRING(dev,0);
    }
}


PHP_FUNCTION(pcap_open_live)
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    int snaplen, promisc, to_ms, dev_len;
    pcap_resource* pcap_resource;
    zval *userland_errbuf;

    if(zend_parse_parameters(
        ZEND_NUM_ARGS() TSRMLS_CC,
        "slllz",
        &dev, &dev_len,
        &snaplen,
        &promisc,
        &to_ms,
        &userland_errbuf
    ) != SUCCESS) {
        RETURN_FALSE;
    }

    pcap_resource = emalloc(sizeof(pcap_resource));
    pcap_resource->pcap_handle = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);
    if(pcap_resource->pcap_handle == NULL) {
        ZVAL_STRING(userland_errbuf, errbuf, 1);
        RETURN_FALSE;
    } else {
        ZEND_REGISTER_RESOURCE(return_value, pcap_resource, le_pcap_resource);
    }
}


PHP_FUNCTION(pcap_datalink)
{

    pcap_resource *resource;
    int datalink;
    zval *handle = NULL;

    if(zend_parse_parameters(
        ZEND_NUM_ARGS() TSRMLS_CC,
        "r",
        &handle
    ) != SUCCESS) {
        RETURN_FALSE;
    }


    ZEND_FETCH_RESOURCE(
        resource,
        pcap_resource*,
        &handle,
        -1,
        le_pcap_resource_name,
        le_pcap_resource
    );

    datalink = pcap_datalink(resource->pcap_handle);
    RETURN_LONG(datalink);
}


/* }}} */
/* The previous line is meant for vim and emacs, so it can correctly fold and 
   unfold functions in source code. See the corresponding marks just before 
   function definition, where the functions purpose is also documented. Please 
   follow this convention for the convenience of others editing your code.
*/


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
