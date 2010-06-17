#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/cmp.h>

#define DEBUG 1

#ifdef DEBUG
#define dbgmsg(fmt, ...) log_error_write(srv, __FILE__, __LINE__, "s"fmt, "CMP DEBUG: ", __VA_ARGS__)
void log_cmperrors(void)
{
#warning using hard-coded path for error log!
	FILE *f = fopen("/home/miikka/light/cmperr.log", "w");
	ERR_load_crypto_strings();
	ERR_print_errors_fp(f);
	fclose(f);
}
#else
#define dbgmsg //
void log_cmperrors(void) { return; }
#endif

#define CMP_CONTENT_TYPE "application/pkixcmp"

/* plugin config for all request/connections */

typedef struct {
	array *match;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	buffer *match_buf;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

typedef struct {
	size_t foo;
} handler_ctx;

/*
static handler_ctx * handler_ctx_init() {
	handler_ctx * hctx;

	hctx = calloc(1, sizeof(*hctx));

	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {

	free(hctx);
}
*/

/* init the plugin data */
INIT_FUNC(mod_cmpsrv_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	p->match_buf = buffer_init();

	return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_cmpsrv_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;

		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s) continue;

			array_free(s->match);

			free(s);
		}
		free(p->config_storage);
	}

	buffer_free(p->match_buf);

	free(p);

	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_cmpsrv_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "cmpsrv.array",             NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		s->match    = array_init();

		cv[0].destination = s->match;

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_cmpsrv_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(match);
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("cmpsrv.array"))) {
				PATCH(match);
			}
		}
	}

	return 0;
}
#undef PATCH

buffer *get_content(chunkqueue *cq) 
{
	if (cq->first && cq->first->mem && cq->first->mem->used > 0)
		return cq->first->mem;
	return 0;
}

// {{{ char V_CMP_TABLE[] 

char *V_CMP_TABLE[] = {
	"V_CMP_PKIBODY_IR",
	"V_CMP_PKIBODY_IP",
	"V_CMP_PKIBODY_CR",
	"V_CMP_PKIBODY_CP",
	"V_CMP_PKIBODY_P10CR",
	"V_CMP_PKIBODY_POPDECC",
	"V_CMP_PKIBODY_POPDECR",
	"V_CMP_PKIBODY_KUR",
	"V_CMP_PKIBODY_KUP",
	"V_CMP_PKIBODY_KRR",
	"V_CMP_PKIBODY_KRP",
	"V_CMP_PKIBODY_RR",
	"V_CMP_PKIBODY_RP",
	"V_CMP_PKIBODY_CCR",
	"V_CMP_PKIBODY_CCP",
	"V_CMP_PKIBODY_CKUANN",
	"V_CMP_PKIBODY_CANN",
	"V_CMP_PKIBODY_RANN",
	"V_CMP_PKIBODY_CRLANN",
	"V_CMP_PKIBODY_PKICONF",
	"V_CMP_PKIBODY_NESTED",
	"V_CMP_PKIBODY_GENM",
	"V_CMP_PKIBODY_GENP",
	"V_CMP_PKIBODY_ERROR",
	"V_CMP_PKIBODY_CERTCONF",
	"V_CMP_PKIBODY_POLLREQ",
	"V_CMP_PKIBODY_POLLREP",
};

//      }}}
#define MSG_TYPE_STR(type)  \
	(((unsigned int) (type) < sizeof(V_CMP_TABLE)/sizeof(V_CMP_TABLE[0])) \
	 ? V_CMP_TABLE[(unsigned int)(type)] : "unknown")

int handleMessage(server *srv, CMP_PKIMESSAGE *msg)
{
	UNUSED(srv);

	int bodyType = CMP_PKIMESSAGE_get_bodytype(msg);
	dbgmsg("ss", "got message", MSG_TYPE_STR(bodyType));
	switch (bodyType) {
		case V_CMP_PKIBODY_IR:
			dbgmsg("sd", "CMP version is", ASN1_INTEGER_get(msg->header->pvno));

#if 0
			X509_NAME *name = msg->header->recipient->d.directoryName;
			dbgmsg("sd", "num of entries in name", X509_NAME_entry_count(name));
			char namebuf[1024]={0};
			int n=X509_NAME_get_text_by_NID(name, 0, namebuf, sizeof(namebuf)-1);
			dbgmsg("ssd", "name is:", namebuf, n);
#endif

			X509_ALGOR *alg = msg->header->protectionAlg;
			dbgmsg("sd", "alg:", alg);

			const unsigned char *p = msg->header->senderKID->data;
			char b[1024];
			sprintf(b, "%02x %02x %02x %02x", p[0], p[1], p[2], p[3]); 
			dbgmsg("ss", "senderKID", b);

			break;

		default:
			dbgmsg("ss", "ERROR unhandled message type:", MSG_TYPE_STR(bodyType));
			break;
	}

	return 0;
}

URIHANDLER_FUNC(mod_cmpsrv_uri_handler) {
	plugin_data *p = p_d;
	int s_len;
	buffer *msg;

	UNUSED(srv);

	if (con->mode != DIRECT) return HANDLER_GO_ON;

	if (con->uri.path->used == 0) return HANDLER_GO_ON;

	mod_cmpsrv_patch_connection(srv, con, p);

	s_len = con->uri.path->used - 1;

	dbgmsg("s", "mod_cmpsrv_uri_handler called");

	if (0 == con->request.http_content_type ||
		0 != strncmp(con->request.http_content_type, CMP_CONTENT_TYPE, sizeof(CMP_CONTENT_TYPE)-1)) {
		dbgmsg("s", "invalid content type");
		return HANDLER_GO_ON;
	}


	/* TODO: handle multiple chunks correctly */
	if (chunkqueue_length(con->request_content_queue) != (off_t)con->request.content_length) {
		dbgmsg("s", "invalid chunkqueue_length");
		return HANDLER_GO_ON;
	}
	msg = get_content(con->request_content_queue);
	if (msg->used != (off_t)con->request.content_length+1) {
		dbgmsg("sd", "too many chunks", msg->used);
		return HANDLER_GO_ON;
	}

	dbgmsg("s", "decoding DER message ...");

	const unsigned char *derMsg = (unsigned char *) msg->ptr;
	size_t derLen = con->request.content_length;
	CMP_PKIMESSAGE *pkiMsg = 0;

	if (!d2i_CMP_PKIMESSAGE(&pkiMsg, &derMsg, derLen )) {
		dbgmsg("s", "ERROR decoding message");
		log_cmperrors();
		return HANDLER_GO_ON;
	}

	/* handle the received PKI message */
	handleMessage(srv, pkiMsg);

	// con->http_status = 200;
	// con->mode = DIRECT;

	con->file_finished = 1;

	/* char msg[] = "TEST123123123"; */
	/* http_chunk_append_mem(srv, con, msg, strlen(msg)+1); */
	return HANDLER_FINISHED;

	/* not found */
	return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_cmpsrv_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("cmpsrv");

	p->init        = mod_cmpsrv_init;
	p->handle_uri_clean  = mod_cmpsrv_uri_handler;
	// p->handle_subrequest_start  = mod_cmpsrv_uri_handler;
	p->set_defaults  = mod_cmpsrv_set_defaults;
	p->cleanup     = mod_cmpsrv_free;

	p->data        = NULL;

	return 0;
}
