#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "cli.h"
#include "colors.h"
#include "net_defs.h"
#include "dns_resolver.h"
#include "memory.h"

header_t dns_header ()
{
	srand(time(NULL));
	header_t header;
	header.id = htons(rand() % 65356);
	header.flags = htons(0x0100);
	header.qdcount = htons(1);
	header.ancount = htons(0);
	header.nscount = htons(0);
	header.arcount = htons(0);

	return header;
}


uint8_t *write_question_name (char *domain, int *qname_len, pool_t *pool)
{
	uint8_t *qname = (uint8_t *)POOL_ALLOC(pool, ADDR * sizeof(char));
	int qname_pos = 0;
	const char *label = domain;

	while (*label)
	{
		const char *dot = strchr(label, '.');
		int len = dot ? dot - label : strlen(label);
		qname[qname_pos++] = len;
		memcpy(qname + qname_pos, label, len);
		qname_pos += len;
		*qname_len = qname_pos;
		if (!dot) break;
		label = dot + 1;

	}

	qname[qname_pos++] = 0x00;
	*qname_len = qname_pos;
	return qname;
}

header_t write_dns_header (dns_buffer_t *dnsbuff)
{
	header_t header = dns_header();
	memcpy(dnsbuff->buffer + dnsbuff->offset, &header, sizeof(header));
	dnsbuff->offset += sizeof(header);
	return header;
}

void write_dns_question (char *domain, dns_buffer_t *dnsbuff, int type, pool_t *pool)
{
	int qname_len;
	uint8_t *qname = write_question_name(domain, &qname_len, pool);
	memcpy(dnsbuff->buffer + dnsbuff->offset, qname, qname_len);
	dnsbuff->offset += qname_len;

	uint16_t qtype = htons(type);
	memcpy(dnsbuff->buffer + dnsbuff->offset, &qtype, 2);
	dnsbuff->offset += 2;

	uint16_t qclass = htons(1);
	memcpy(dnsbuff->buffer + dnsbuff->offset, &qclass, 2);
	dnsbuff->offset += 2;
}

void dns_buffer (dns_buffer_t *dnsbuff, char *domain, int type, pool_t *pool)
{
	header_t header = write_dns_header(dnsbuff);
	write_dns_question(domain, dnsbuff, type, pool);

	/*
	int c = 0;
	printf("\n");
	do
	{
		printf("%02X ", dnsbuff->buffer[c++]);
	}while(c < dnsbuff->offset);

	printf("\n");
	*/

}


int rdata_size (int qtype)
{
	int rdata_size;
	switch (qtype)
	{
		case DNS_A: // A
			rdata_size = INET_ADDRSTRLEN;
			break;
		case DNS_NS: // NS
		case DNS_CNAME: // CNAME
		case DNS_PTR: // PTR
		case DNS_MX: // MX
		case DNS_TXT: // TXT
			rdata_size = ADDR;
			break;
		case DNS_SOA: // SOA
			rdata_size = (ADDR * 2 + 20);
			break;
		case DNS_AAAA: // AAAA
			rdata_size = INET6_ADDRSTRLEN;
			break;
		default:
			break;
	}

	return rdata_size;
}

int calculate_name_len(uint8_t *name)
{
	int pos = 0;
	while(1) 
	{
		int len = name[pos];
		if((name[pos] & 0xC0) == 0xC0) return pos + 2;

		else if(name[pos] == 0x00) return pos + 1;
		pos += 1 + len;
	}
}

void collect_name (dns_buffer_t response, char *name)
{
	int name_pos = 0, len;
	uint16_t offset;
	uint8_t *p = response.buffer + response.pos;
	while(1)
	{
		len = *p++;

		if((len & 0xC0) == 0xC0)
		{
			memcpy(&offset, p - 1, 2);
			offset = ntohs(offset);
			offset &= 0x3FFF;
			p = response.buffer + offset;
			continue;
		}
		if (len == 0) break;
		for(int c = 0; c < len; c++) name[name_pos++] = *p++;
		name[name_pos++] = '.';
	}
	name[name_pos - 1] = '\0';
}

void collect_soa(data_t *data, dns_buffer_t *response)
{
	        int mname_len = calculate_name_len(response->buffer + response->pos);

		collect_name(*response, data->soa.mname);
		response->pos += mname_len;

	        int rname_len = calculate_name_len(response->buffer + response->pos);
		collect_name(*response, data->soa.rname);
		response->pos += rname_len;

		memcpy(&data->soa.serial, response->buffer + response->pos, 4);
		data->soa.serial = ntohl(data->soa.serial);
		response->pos += 4;

		memcpy(&data->soa.refresh, response->buffer + response->pos, 4);
		data->soa.refresh = ntohl(data->soa.refresh);
		response->pos += 4;

		memcpy(&data->soa.retry, response->buffer + response->pos, 4);
		data->soa.retry = ntohl(data->soa.retry);
		response->pos += 4;

		memcpy(&data->soa.expire, response->buffer + response->pos, 4);
		data->soa.expire = ntohl(data->soa.expire);
		response->pos += 4;

		memcpy(&data->soa.minimum, response->buffer + response->pos, 4);
		data->soa.minimum = ntohl(data->soa.minimum);
		response->pos += 4;

}

// Verificar se estou tratando o response.pos corretamente em casos de ponteiro, onde eu tenho que fazer response.pos = response.buffer + pointer_offset, e depois sim response.pos += rname_len ou response.pos = mname_len
void format_data (data_t *data, dns_buffer_t response,  int qtype)
{ // REFATORAR ESSA FUNÇÃO POSTERIORMENTE, A ADAPTANDO PARA A ÁRVORE
	size_t size_rdata = rdata_size(data->qtype);
	if(qtype == DNS_A) // A
		snprintf(data->answer, size_rdata, "%u.%u.%u.%u", response.rdata[0], response.rdata[1], response.rdata[2], response.rdata[3]);
	else if(qtype == DNS_NS || qtype == DNS_CNAME || qtype == DNS_PTR) // NS and CMAME
	{
		collect_name(response, data->answer);
	} else if (qtype == DNS_SOA) // SOA
	{
		// criar uma função para encapsular isto e tratar casos onde a resposta é binária
		// Aqui, iremos pegar MNAME e RNAME utilizando de collect_name(), para depois, pegar os outros dados de 32 bits normalmente usando memcpy
		collect_soa(data, &response);
	} else if (qtype == DNS_MX) // MX
	{
		response.pos += 2;
		response.rdata += 2;
		collect_name(response, data->answer);

	} else if (qtype == DNS_AAAA) inet_ntop(AF_INET6, response.rdata, data->answer, INET6_ADDRSTRLEN); // AAAA
	else if (qtype == DNS_TXT)
	{
		// criar uma função para encapsular isto
		int field_len = 0, answer_pos = 0, pos = 0;

		while(pos < response.rdlength)
		{
			field_len = response.rdata[pos++];
			for(int field_pos = 0; field_pos < field_len; field_pos++) data->answer[answer_pos++] = response.rdata[pos++];

		}
		data->answer[answer_pos] = '\0';
	} else if (qtype == DNS_AXFR)
	{
		error("AXFR record not done yet\n");

	}
}

const char *get_strqtype (int qtype) {
	switch(qtype) {
		case DNS_A:     return "A";
		case DNS_NS:    return "NS";
		case DNS_CNAME: return "CNAME";
		case DNS_SOA:   return "SOA";
		case DNS_PTR:   return "PTR";
		case DNS_MX:    return "MX";
		case DNS_TXT:   return "TXT";
		case DNS_AAAA:  return "AAAA";
		case DNS_AXFR:  return "AXFR";
		default:        return "UNK";
	}
}

const char *get_strqclass (int qclass) {
	switch(qclass) {
		case DNS_IN: return "IN";
		case DNS_CH: return "CH";
		case DNS_HS: return "HS";
		case DNS_ANY: return "ANY";
		default: return "UNK";
	}
}

void reverse_buff(uint8_t *buff, size_t bufflen)
{
	uint8_t reverse_buff[bufflen];
	for(int buff_c = 0; buff_c < bufflen; buff_c++) reverse_buff[buff_c] = buff[bufflen - 1 - buff_c];
	memcpy(buff, reverse_buff, bufflen); // ao invés de fazer isso, testar retorno de reverse_buff
}

char hextodigit(uint8_t nib)
{
	return (nib < 10) ? ('0' + nib) : ('A' + (nib - 10));
}

void bufftorevdns(uint8_t *buff, size_t bufflen, char *str)
{
	int strpos = 0;
	for(int buffpos = 0; buffpos < bufflen; buffpos++)
	{
		// PEGAR O NIBBLE MAIS E MENOS SIGNIFICATIVO
		uint8_t high = (buff[buffpos] >> 4) & 0xF;
		uint8_t low = buff[buffpos] & 0xF;
		str[strpos++] = hextodigit(high);
		str[strpos++] = '.';
		str[strpos++] = hextodigit(low);
		str[strpos++] = '.';
	}
	str[strpos] = '\0';
}

void revdns_address (char *ip_addr, char *revdns)
{
	uint8_t addr_buff[16];
	if(inet_pton(AF_INET, ip_addr, addr_buff) == 1)
	{
		snprintf(revdns, ADDR, "%u.%u.%u.%u.in-addr.arpa", addr_buff[3], addr_buff[2], addr_buff[1], addr_buff[0]);
	} else if(inet_pton(AF_INET6, ip_addr, addr_buff) == 1)
	{ 
		char revdns_addr[ADDR];
		reverse_buff(addr_buff, 16);
		bufftorevdns(addr_buff, 16, revdns_addr);
		snprintf(revdns, ADDR, "%sip6.arpa", revdns_addr);
	}
}

int dns_parse (sock_t **sock, dns_buffer_t *response, dns_query_t **query, int qtype, dns_query_t **cursor, pool_t *pool)
{
	uint16_t ancount;
	response->offset = 6;
	memcpy(&ancount, response->buffer + response->offset, 2);
	ancount = ntohs(ancount);
	if (ancount == 0) return -1;
	response->offset += 6;

	for(int answer_question = 0; answer_question < ancount; answer_question++)
	{
		if(response->offset >= response->length) return -1;
	
		if ((response->buffer[response->offset] & 0xC0) == 0xC0) {
			response->offset += 2;
		} else {
			while (response->buffer[response->offset] != 0x00)
				response->offset++;
			response->offset += 5;
		}

		if ((response->buffer[response->offset] & 0xC0) == 0xC0)
			response->offset += 2;

		uint16_t checkqtype;
		memcpy(&checkqtype, response->buffer + response->offset, 2);
		checkqtype = ntohs(checkqtype);

		if (qtype != checkqtype && qtype != DNS_AXFR)
		{
			response->offset += 8;
			uint16_t skiprdata;
			memcpy(&skiprdata, response->buffer + response->offset, 2);
			response->rdlength = ntohs(skiprdata);
			response->offset += 2 + skiprdata;
			continue;
		}
		dns_query_t *new_query = create_query(checkqtype, pool);
		new_query->answer.qtype = checkqtype;
		

		response->offset += 2;

		memcpy(&new_query->answer.qclass, response->buffer + response->offset, 2);
		new_query->answer.qclass = ntohs(new_query->answer.qclass);
		response->offset += 2;

		memcpy(&new_query->answer.ttl, response->buffer + response->offset, 4);
		new_query->answer.ttl = ntohl(new_query->answer.ttl);
		response->offset += 4;

		memcpy(&response->rdlength, response->buffer + response->offset, 2);
		response->rdlength = ntohs(response->rdlength);
		response->offset += 2;
		response->pos = response->offset;
		response->rdata = (uint8_t *)POOL_ALLOC(pool, response->rdlength + 1);
		memcpy(response->rdata, response->buffer + response->offset, response->rdlength + 1);
		response->offset += response->rdlength;

		format_data(&new_query->answer, *response, new_query->answer.qtype);
		if(new_query->answer.qtype == DNS_AAAA || new_query->answer.qtype == DNS_A) revdns_address(new_query->answer.answer, new_query->req_source);

		else copystr(new_query->answer.answer, new_query->req_source);

		if (!(*query)) (*query) = (*cursor) = new_query;
		else
		{
			(*cursor)->next = new_query;
			*cursor = new_query;
		}
	}
	return 0;
}

// CRIAR A PARTE DA FUNÇÃO QUE FAZ A REVERSE DNS LOOKUP DOMAIN
// CHECAR O QUE GEROU O SEGFAULT
