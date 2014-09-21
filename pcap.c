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
  | Author: Thorsten Heymann <hek2mgl@metashock.net>                     |
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

#define LE_PCAP_RESOURCE_NAME "pcap"
#define LE_PCAP_FILTER_RESOURCE_NAME "pcap-filter"

/* resource types */
typedef struct {
    pcap_t* pcap_handle;
} pcap_resource;

typedef struct {
    struct bpf_program *program_handle;
} pcap_filter_resource;



/* If you declare any globals in php_pcap.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(pcap)
*/

/* True global resources - no need for thread safety here */
static int le_pcap_resource;
static int le_pcap_filter_resource;

/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_pcap_lookupdev, 0, 0, 2)
    ZEND_ARG_INFO(1, errbuf)
ZEND_END_ARG_INFO()


/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_pcap_lookupnet, 0, 0, 4)
    ZEND_ARG_INFO(0, dev)
    ZEND_ARG_INFO(1, net)
    ZEND_ARG_INFO(1, mask)
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
ZEND_BEGIN_ARG_INFO_EX(arginfo_pcap_open_offline, 0, 0, 2)
    ZEND_ARG_INFO(0, fname)
    ZEND_ARG_INFO(1, errbuf)
ZEND_END_ARG_INFO()


/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_pcap_close, 0, 0, 1)
    ZEND_ARG_INFO(0, pcap_handle)
ZEND_END_ARG_INFO()


/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_pcap_datalink, 0, 0, 1)
    ZEND_ARG_INFO(0, pcap)
ZEND_END_ARG_INFO()


/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_pcap_compile, 0, 0, 5)
    ZEND_ARG_INFO(0, pcap_handle)
    ZEND_ARG_INFO(1, filter_handle)
    ZEND_ARG_INFO(0, filter_string)
    ZEND_ARG_INFO(0, optimize)
    ZEND_ARG_INFO(0, netmask)
ZEND_END_ARG_INFO()


/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_pcap_setfilter, 0, 0, 2)
    ZEND_ARG_INFO(0, pcap_handle)
    ZEND_ARG_INFO(1, filter_handle)
ZEND_END_ARG_INFO()


/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_pcap_next, 0, 0, 2)
    ZEND_ARG_INFO(0, pcap_handle)
    ZEND_ARG_INFO(1, header)
ZEND_END_ARG_INFO()


/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_pcap_geterr, 0, 0, 1)
    ZEND_ARG_INFO(0, pcap_handle)
ZEND_END_ARG_INFO()


/* {{{ pcap_functions[]
 *
 * Every user visible function must have an entry in pcap_functions[].
 */
const zend_function_entry pcap_functions[] = {
	PHP_FE(pcap_lib_version,    NULL)
    PHP_FE(pcap_lookupdev,  arginfo_pcap_lookupdev)
    PHP_FE(pcap_lookupnet,  arginfo_pcap_lookupnet)
    PHP_FE(pcap_next, arginfo_pcap_next)
    PHP_FE(pcap_open_live,  arginfo_pcap_open_live)
    PHP_FE(pcap_open_offline,  arginfo_pcap_open_offline)
    PHP_FE(pcap_close,  arginfo_pcap_close)
    PHP_FE(pcap_datalink,  arginfo_pcap_datalink)
    PHP_FE(pcap_compile,  arginfo_pcap_compile)
    PHP_FE(pcap_setfilter,  arginfo_pcap_setfilter)
    PHP_FE(pcap_geterr,  arginfo_pcap_geterr)
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
        LE_PCAP_RESOURCE_NAME,
        0
    );

    le_pcap_filter_resource = zend_register_list_destructors_ex(
        pcap_filter_destruction_handler,
        NULL,
        LE_PCAP_FILTER_RESOURCE_NAME,
        1
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


/* Makes sure that the pcap_handle will get closed on PHP shutdown */
void pcap_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
    pcap_resource *resource = (pcap_resource *) rsrc->ptr;
   
    /* Close the pcap handle */
    pcap_close(resource->pcap_handle);

    /* Don't miss to free allocated memory */
    efree(resource);
}

/* Makes sure that the pcap_filter_handle will get closed on PHP shutdown */
void pcap_filter_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
// pcap_filter_resource *resource = (pcap_filter_resource *) rsrc->ptr;
// pcap_close(resource->program_handle);
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
        RETURN_STRING(dev, 1);
    }
}


PHP_FUNCTION(pcap_lookupnet)
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    zval *userland_net;
    zval *userland_mask;
    zval *userland_errbuf;
    int devlen;
    bpf_u_int32 net, mask;
    int ret;

    if(zend_parse_parameters(
        ZEND_NUM_ARGS() TSRMLS_CC,
        "szz|z", 
        &dev, &devlen,
        &userland_net,
        &userland_mask,
        &userland_errbuf
    ) != SUCCESS) {
        RETURN_FALSE;
    }

    convert_to_null(userland_net);
    convert_to_null(userland_mask);
    convert_to_null(userland_errbuf);

    ret = pcap_lookupnet(dev, &net, &mask, errbuf);
    ZVAL_STRING(userland_errbuf, errbuf, 1);
   
    if(ret == 0) {
        ZVAL_LONG(userland_net, net);
        ZVAL_LONG(userland_mask, mask);
    }
    
    RETURN_LONG(ret);
}

/* {{{ proto int pcap_datalink(string $dev, int $snaplen, int $promisc, int $to_ms[, string &$errbuf])
   open a device for capturing */
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

    convert_to_null(userland_errbuf);

    pcap_resource = emalloc(sizeof(pcap_resource));
    pcap_resource->pcap_handle = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);
    ZVAL_STRING(userland_errbuf, errbuf, 1);
    if(pcap_resource->pcap_handle == NULL) {
        RETURN_FALSE;
    } else {
        ZEND_REGISTER_RESOURCE(return_value, pcap_resource, le_pcap_resource);
    }
}


/* {{{ proto resource pcap_open_offline(string $fname, string &errbuf)
       Open a saved capture file for reading */
PHP_FUNCTION(pcap_open_offline)
{
    char *fname, *fname_safe, errbuf[PCAP_ERRBUF_SIZE];
    int fname_len;
    pcap_resource* pcap_resource;
    zval *userland_errbuf;

    // Expecting a filename and the errbuf reference
    if(zend_parse_parameters(
        ZEND_NUM_ARGS() TSRMLS_CC,
        "sz",
        &fname, &fname_len,
        &userland_errbuf
    ) != SUCCESS) {
        RETURN_FALSE;
    }

    /* Initialize userland_errbuf which has been passed 
       by reference. NULL is the default value */
    convert_to_null(userland_errbuf);

    /* Allocate memory for a pcap_resource */
    pcap_resource = emalloc(sizeof(pcap_resource));

    /* Call pcap function */
    pcap_resource->pcap_handle = pcap_open_offline(fname, errbuf);

    if(pcap_resource->pcap_handle == NULL) {
        /* Copy the error message to userland */
        ZVAL_STRING(userland_errbuf, errbuf, 1);
        /* Don't miss to free the previously allocated memory */
        efree(pcap_resource);

        RETURN_FALSE;
    } else {
        zval_dtor(return_value);
        ZEND_REGISTER_RESOURCE(return_value, pcap_resource, le_pcap_resource);
//        efree(pcap_resource);
    }
}


/* */
PHP_FUNCTION(pcap_close)
{
    pcap_resource *resource;
    zval *pcap_argument;

    // A pcap resource is expected as argument
    if(zend_parse_parameters(
        ZEND_NUM_ARGS() TSRMLS_CC,
        "z",
        &pcap_argument
    ) != SUCCESS) {
        RETURN_FALSE;
    }

    // Fetch pcap_resource from Zend
    ZEND_FETCH_RESOURCE(
        resource,
        pcap_resource*,
        &pcap_argument,
        -1,
        LE_PCAP_RESOURCE_NAME,
        le_pcap_resource
    );

    zend_list_delete(Z_LVAL_P(pcap_argument));

    RETURN_TRUE;
}


/* {{{ proto int pcap_datalink(resource $pcap_handle)
       Get the link-layer header type */
PHP_FUNCTION(pcap_datalink)
{
    pcap_resource *resource;
    int datalink;
    zval *handle = NULL;

    // only a single resource is expected as params
    if(zend_parse_parameters(
        ZEND_NUM_ARGS() TSRMLS_CC,
        "r",
        &handle
    ) != SUCCESS) {
        RETURN_FALSE;
    }

    // fetch pcap_resource from Zend
    ZEND_FETCH_RESOURCE(
        resource,
        pcap_resource*,
        &handle,
        -1,
        LE_PCAP_RESOURCE_NAME,
        le_pcap_resource
    );

    // get the datalink type and assign it to the php return value
    datalink = pcap_datalink(resource->pcap_handle);
    RETURN_LONG(datalink);
}


PHP_FUNCTION(pcap_compile)
{
    pcap_resource *resource;
    pcap_filter_resource *filter_resource;
    struct bpf_program *fp;
    const char *filter_str;
    int optimize, filter_str_len, ret;
    bpf_u_int32 netmask;
    zval *pcap_handle, *filter_handle;
    char *errbuf[PCAP_ERRBUF_SIZE];

    // only a single resource is expected as params
    if(zend_parse_parameters(
        ZEND_NUM_ARGS() TSRMLS_CC,
        "zzsll",
        &pcap_handle,
        &filter_handle,
        &filter_str, &filter_str_len,
        &optimize,
        &netmask
    ) != SUCCESS) { 
        RETURN_FALSE;
    }

    // fetch pcap_resource from Zend
    ZEND_FETCH_RESOURCE(
        resource,
        pcap_resource*,
        &pcap_handle,
        -1,
        LE_PCAP_RESOURCE_NAME,
        le_pcap_resource
    );

    // convert the user land reference to NULL
    convert_to_null(filter_handle);

    // initialize the fp pointer
    fp = emalloc(sizeof(struct bpf_program));

    ret = pcap_compile(
        resource->pcap_handle,
        fp,
        filter_str,
        optimize,
        netmask
    );

    if(ret == -1) {
        RETURN_LONG(ret);
        return;
    } else {

        /* all is working fine. we can create the filter resource and
           pass it back to the user land */
        filter_resource =
            (pcap_filter_resource *)(emalloc(sizeof(pcap_filter_resource)));
        filter_resource->program_handle = fp;

        // required to initialize the php value
        convert_to_null(filter_handle);

        ZEND_REGISTER_RESOURCE(
            filter_handle,
            filter_resource,
            le_pcap_filter_resource
        );

        RETURN_LONG(ret); 
    }
}


/* {{{ proto int pcap_setfilter(resource $pcap_handle, resource $filter_handle)
   Set the filter */
PHP_FUNCTION(pcap_setfilter) {

    zval *pcap_handle, *filter_handle;
    pcap_resource *resource;
    pcap_filter_resource *filter_resource;
    int ret;

    // only a single resource is expected as params
    if(zend_parse_parameters(
        ZEND_NUM_ARGS() TSRMLS_CC,
        "zz",
        &pcap_handle,
        &filter_handle
    ) != SUCCESS) { 
        RETURN_FALSE;
    }

    // fetch pcap_resource from Zend
    ZEND_FETCH_RESOURCE(
        resource,
        pcap_resource*,
        &pcap_handle,
        -1,
        LE_PCAP_RESOURCE_NAME,
        le_pcap_resource
    );

    // fetch pcap_filter_resource from Zend
    ZEND_FETCH_RESOURCE(
        filter_resource,
        pcap_filter_resource*,
        &filter_handle,
        -1,
        LE_PCAP_FILTER_RESOURCE_NAME,
        le_pcap_filter_resource
    );

    ret = pcap_setfilter(
        resource->pcap_handle,
        filter_resource->program_handle
    );

    RETURN_LONG(ret);
}

/* {{{ proto string pcap_setfilter(resource $pcap_handle, array &header))
   Set the filter */
PHP_FUNCTION(pcap_next) {

    zval *pcap_handle, *userland_header;
    /* we need an additional container for the 
     * timeval struct of &header */
    zval *userland_timeval;
    pcap_resource *resource;
    int ret;

    // only a single resource is expected as params
    if(zend_parse_parameters(
        ZEND_NUM_ARGS() TSRMLS_CC,
        "zz",
        &pcap_handle,
        &userland_header
    ) != SUCCESS) { 
        RETURN_FALSE;
    }

    // fetch pcap_resource from Zend
    ZEND_FETCH_RESOURCE(
        resource,
        pcap_resource*,
        &pcap_handle,
        -1,
        LE_PCAP_RESOURCE_NAME,
        le_pcap_resource
    );

    struct pcap_pkthdr header;
    const u_char *data;
    char *_data;
    data = pcap_next(resource->pcap_handle, &header);
    _data = (char *)data;    

    if(data == NULL) {
        RETURN_NULL();
    }

    /* initialize the userland_header which has been passed by reference */
    convert_to_null(userland_header);
    ALLOC_INIT_ZVAL(userland_timeval);

    array_init(userland_header);
    array_init(userland_timeval);

    add_assoc_long(userland_timeval, "tv_sec", header.ts.tv_sec);
    add_assoc_long(userland_timeval, "tv_usec", header.ts.tv_usec);

    add_assoc_zval(userland_header, "ts", userland_timeval);
    add_assoc_long(userland_header, "len", header.len);
    add_assoc_long(userland_header, "caplen", (long) (header.caplen));

    /* return the data as binary string */
    return_value->type = IS_STRING;
    /* estrndup() because it is a binary string */
    return_value->value.str.val = estrndup(_data, header.caplen);
    return_value->value.str.len = header.caplen;
}

/* {{{ proto string pcap_setfilter(resource $pcap_handle, array &header))
   Returns  the  error  text  pertaining  to the last pcap library error */
PHP_FUNCTION(pcap_geterr) {

    zval *pcap_handle;
    pcap_resource *resource;
    int ret;
    char *error;

    // only a single resource is expected as params
    if(zend_parse_parameters(
        ZEND_NUM_ARGS() TSRMLS_CC,
        "z",
        &pcap_handle
    ) != SUCCESS) { 
        RETURN_FALSE;
    }

    // Fetch the pcap_resource from Zend engine
    ZEND_FETCH_RESOURCE(
        resource,
        pcap_resource*,
        &pcap_handle,
        -1,
        LE_PCAP_RESOURCE_NAME,
        le_pcap_resource
    );

    error = pcap_geterr(resource->pcap_handle);
    RETURN_STRING(error, 1);
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
