/* vim: set ts=4 sts=4 sw=4 cino={.25s: */

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "http_chunk.h"
#include "chunk.h"

#include "plugin.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/cmp.h>

#define DEBUG 1

#ifdef DEBUG
#define dbgmsg(fmt, ...) log_error_write(srv, __FILE__, __LINE__, "s"fmt, "CMPDBG: ", __VA_ARGS__)
void log_cmperrors(void)
{
// #warning using hard-coded path for error log!
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

CMP_CTX *createContext()
{
	CMP_CTX *ctx = CMP_CTX_create();

	// CMP_CTX_set1_serverName( cmp_ctx, opt_serverName);
	// CMP_CTX_set1_serverPath( cmp_ctx, opt_serverPath);
	// CMP_CTX_set1_serverPort( cmp_ctx, opt_serverPort);
	CMP_CTX_set1_referenceValue( ctx, (unsigned char*)"\x3F\xC5\xDD\x75\xF7\xDA\x47\x5D\x80", 9);
	CMP_CTX_set1_secretValue( ctx, (unsigned char*)"\xFC\x2B\x12\x07\xDF\x2C\xFA\xAB\x04\x97\x7C\xA0", 12);
	// CMP_CTX_set0_pkey( cmp_ctx, initialPkey);
	// CMP_CTX_set1_caCert( cmp_ctx, caCert);
	// CMP_CTX_set_compatibility( cmp_ctx, opt_compatibility);

	CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_PBMAC);

	return ctx;
}

X509 *HELP_read_der_cert( const char *file) {
	X509 *x;
	BIO  *bio;

	printf("INFO: Reading Certificate from File %s\n", file);
	if ((bio=BIO_new(BIO_s_file())) != NULL)
		if (!BIO_read_filename(bio,file)) {
			printf("ERROR: could not open file \"%s\" for reading.\n", file);
			return NULL;
		}

	x=d2i_X509_bio(bio,NULL);

	BIO_free(bio);
	return x;
}



/* ############################################################################ */
/* ############################################################################ */
CMP_PKIMESSAGE * CMP_ip_new( CMP_CTX *ctx) {
	UNUSED(ctx);

	CMP_PKIMESSAGE *msg=NULL;

	// if (!ctx) goto err;
	if (!ctx->referenceValue) goto err;
	if (!ctx->secretValue) goto err;
	// if (!ctx->pkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	CMP_PKIHEADER_set1(msg->header, ctx);
	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_IP);

#if 1
	X509_NAME *sender = X509_NAME_new();
	X509_NAME_add_entry_by_txt(sender, "CN", MBSTRING_ASC, (unsigned char*) "Sender Name", -1, -1, 0);
	CMP_PKIHEADER_set1_sender(msg->header, sender);

	X509_NAME *recipient = X509_NAME_new();
	X509_NAME_add_entry_by_txt(recipient, "CN", MBSTRING_ASC, (unsigned char*) "Recipient Name", -1, -1, 0);
	CMP_PKIHEADER_set1_recipient( msg->header, recipient);
#endif


#if 0
	/* set implicitconfirm */
	msg->header->generalInfo = sk_CMP_INFOTYPEANDVALUE_new_null();
	CMP_INFOTYPEANDVALUE *itav = CMP_INFOTYPEANDVALUE_new();
	itav->infoType = OBJ_nid2obj(NID_id_it_implicitConfirm);
	sk_CMP_INFOTYPEANDVALUE_push(msg->header->generalInfo, itav);
#endif

	/* Generate X509 certificate */
	/*
	   int			X509_set_version(X509 *x,long version);
	   int			X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
	   ASN1_INTEGER *	X509_get_serialNumber(X509 *x);
	   int			X509_set_issuer_name(X509 *x, X509_NAME *name);
	   X509_NAME *	X509_get_issuer_name(X509 *a);
	   int			X509_set_subject_name(X509 *x, X509_NAME *name);
	   X509_NAME *	X509_get_subject_name(X509 *a);
	   int			X509_set_notBefore(X509 *x, const ASN1_TIME *tm);
	   int			X509_set_notAfter(X509 *x, const ASN1_TIME *tm);
	   int			X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
	   EVP_PKEY *	X509_get_pubkey(X509 *x);
	   ASN1_BIT_STRING * X509_get0_pubkey_bitstr(const X509 *x);
	   int		X509_certificate_type(X509 *x,EVP_PKEY *pubkey optional );
	   */

	CMP_CERTREPMESSAGE *resp = CMP_CERTREPMESSAGE_new();

	CMP_CERTRESPONSE *cr = CMP_CERTRESPONSE_new();
	ASN1_INTEGER_set(cr->certReqId, 0);
	ASN1_INTEGER_set(cr->status->status, CMP_PKISTATUS_accepted);

	cr->certifiedKeyPair = CMP_CERTIFIEDKEYPAIR_new();
	X509 *cert = HELP_read_der_cert("/home/miikka/code/cmpforopenssl/certs/cl_cert.der");
	cr->certifiedKeyPair->certOrEncCert->type = CMP_CERTORENCCERT_CERTIFICATE;
	cr->certifiedKeyPair->certOrEncCert->value.certificate = X509_dup(cert);

	resp->response = sk_CMP_CERTRESPONSE_new_null();
	sk_CMP_CERTRESPONSE_push(resp->response, cr);
	
	// resp->caPubs = sk_X509_new_null();

	msg->body->value.ip = resp;
	msg->protection = CMP_protection_new(msg, NULL, NULL, ctx->secretValue);

	return msg;

err:
	// CMPerr(CMP_F_CMP_IP_NEW, CMP_R_CMPERROR);
	return NULL;
}


int handleMessage(server *srv, connection *con, CMP_PKIMESSAGE *msg)
{
	UNUSED(srv);
	int result = 0;
	CMP_CTX *ctx = createContext();
	CMP_PKIMESSAGE *response = 0;
	unsigned char *derBuf = 0;
	size_t derLen = 0;

	int bodyType = CMP_PKIMESSAGE_get_bodytype(msg);
	dbgmsg("ss", "got message", MSG_TYPE_STR(bodyType));
	switch (bodyType) {
		case V_CMP_PKIBODY_IR:
			dbgmsg("sd", "CMP version is", ASN1_INTEGER_get(msg->header->pvno));

			/* verify protection */
			/* TODO store user data on disk etc etc etc */

			if (!CMP_protection_verify(msg, msg->header->protectionAlg, 0, ctx->secretValue)) {
				/* TODO return error code */
				dbgmsg("s", "ERROR: protection not valid!");
				break;
			}
			else dbgmsg("s", "protection validated successfully");

			int numCertRequests = sk_CRMF_CERTREQMSG_num(msg->body->value.ir);
			dbgmsg("sd", "number of cert requests:", numCertRequests);


			/* TODO handle multiple CERTREQMSGS? */
			// CRMF_CERTREQMSG *crm = sk_CRMF_CERTREQMSG_pop(msg->body->value.ir);
			// int reqId = ASN1_INTEGER_get(crm->certReq->certReqId);


			response = CMP_ip_new(ctx);

			dbgmsg("s", "attempting to encode message");
			derLen = i2d_CMP_PKIMESSAGE( response, &derBuf);
			dbgmsg("sd", "message encoded, sending... len=", derLen);


			response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN(CMP_CONTENT_TYPE));
			http_chunk_append_mem(srv, con, (const char*)derBuf, derLen+1);

			// response = 0;
			// dbgmsg("s", "verifying protection");
			// d2i_CMP_PKIMESSAGE(&response, (const unsigned char**)&derBuf, derLen);
			// if (CMP_protection_verify(response, response->header->protectionAlg, 0, ctx->secretValue))
				// dbgmsg("s", "protection is valid");
			// else
				// dbgmsg("s", "protection is NOT valid");

			log_cmperrors();

			result = 1;

			// CMP_PKIMESSAGE_free(response);
			break;

		case V_CMP_PKIBODY_CERTCONF:
			if (!CMP_protection_verify(msg, msg->header->protectionAlg, 0, ctx->secretValue)) {
				/* TODO return error code */
				dbgmsg("s", "ERROR: protection not valid!");
				break;
			}
			else dbgmsg("s", "protection validated successfully");

			response = CMP_PKIMESSAGE_new();
			CMP_PKIHEADER_set1(response->header, ctx);
			CMP_PKIMESSAGE_set_bodytype(response, V_CMP_PKIBODY_PKICONF);
			ASN1_TYPE *t = ASN1_TYPE_new();
			t->type = 1; // boolean
			t->value.boolean = 0;
			response->body->value.pkiconf = t;

			dbgmsg("s", "protecting");
			response->protection = CMP_protection_new(response, NULL, NULL, ctx->secretValue);

			dbgmsg("s", "encoding");
			derLen = i2d_CMP_PKIMESSAGE( response, &derBuf);
			dbgmsg("sd", "message encoded, sending... len=", derLen);

			response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN(CMP_CONTENT_TYPE));
			http_chunk_append_mem(srv, con, (const char*)derBuf, derLen+1);
			result = 1;

			log_cmperrors();
			break;

		default:
			dbgmsg("ss", "ERROR unhandled message type:", MSG_TYPE_STR(bodyType));
			break;
	}

	return result;
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
	handleMessage(srv, con, pkiMsg);

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
