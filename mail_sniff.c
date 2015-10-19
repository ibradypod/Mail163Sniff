#include "mail_sniff.h"
#include "ungzip.h"
#include "urldecode.h"
#include "http_parser.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <pcre.h>
#include <nids.h>

#define OVECCOUNT 3000 /* should be a multiple of 3 */

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

void
tcp_protocol_callback(struct tcp_stream *tcp_connection, void **arg)
{
    static char address_content[50];
    static char content[65535];
    struct tuple4 ip_and_port = tcp_connection->addr;

    strcpy(address_content,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
    sprintf(address_content+strlen(address_content)," ; %i",ip_and_port.source);
    strcat(address_content,"<------->");
    strcat(address_content,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
    sprintf(address_content+strlen(address_content)," ; %i",ip_and_port.dest);
    strcat(address_content,"\n");

    switch (tcp_connection->nids_state)  //判断LIBNIDS的状态
    {
        case NIDS_JUST_EST:
            // if(tcp_connection->addr.dest != 80) //只捕获HTTP协议的数据包
            // return;
            tcp_connection->client.collect++;
            tcp_connection->server.collect++;
        //            printf("\n\n\n===================================\n");
        //            printf("%s 连接建立...\n",address_content);
            return;
        case NIDS_CLOSE:
        //            printf("-------------------------------\n");
        //            printf("%sTCP连接正常关闭\n",address_content);
            return;
        case NIDS_RESET:          //表示TCP连接被RST关闭
        //            printf("-------------------------------\n");
        //            printf("%sTCP连接被RST关闭\n",address_content);
            return;
        case NIDS_DATA:
        {
            struct half_stream* hlf;  //表示TCP连接一端的信息，可以是客户端，也可以是服务器

            if (tcp_connection->client.count_new)
            {
                hlf = &tcp_connection->client;

                memcpy(content,hlf->data,hlf->count_new);
                content[hlf->count_new] = '\0';

                http_match(content,hlf->count_new);

            }
            if (tcp_connection->server.count_new)
            {
                hlf = &tcp_connection->server;

                memcpy(content,hlf->data,hlf->count_new);
                content[hlf->count_new] = '\0';

                http_match(content,hlf->count_new);
            }
            return;
        }

        default:
            break;
    }
}

#if 0
/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static unsigned long count = 1;                   /* packet counter */

	(void*)args;

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
    if(ntohs(ethernet->ether_type) != ETHERTYPE_IP)
        return;
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	/* determine protocol */	
	switch(ip->ip_p) 
	{
		case IPPROTO_TCP:
			break;
		default:
			return;
	}
	
	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	/* define/compute tcp payload (segment) offset */
    payload = (char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
    if (size_payload > 0)
    {
        int rc = http_match(payload,size_payload);

        if(rc > 0){
            printf("\nPacket number : %ld payload_size : %d bytes\n", count++,size_payload);

            /* print source and destination IP addresses */
            printf("       From: %s\n", inet_ntoa(ip->ip_src));
            printf("         To: %s\n", inet_ntoa(ip->ip_dst));

            print_payload((u_char*)payload, size_payload);
            return;
        }

		if(rc > 0)
            write_to_file("sniff_mail_ctx.txt",payload,size_payload);
	}
    else if (size_payload == 0)
    {

    }

	return;
}
#endif

/*
 * get content encoding state
 * @para return
 * 1 if encoded, otherwise 0
 */
static int
get_content_encoding_state (const char *content, size_t length)
{
    pcre *re = NULL;
    const char *error;
    int  erroffset;
    static int  ovector[OVECCOUNT];
    int  rc = -1;

    static const char  *pattern = "Content-Encoding: gzip(.*)";

    re = pcre_compile(pattern, 0, &error, &erroffset, NULL);

    if (re == NULL) {
        printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
        goto end;
    }

    rc = pcre_exec(re, NULL, content, length, 0, 0, ovector, OVECCOUNT);

end:
    if (re)
        pcre_free(re);

    return rc > 0 ? 1 : 0;
}

/*
 * callback function
 */
static int
on_data_cb (http_parser* p, const char *at, size_t length)
{
    if (length <= 0)
        return 0;

    // if gzip encoded
    if (get_content_encoding_state(p->data, length + (at - (char*)p->data)) > 0){

        size_t size_alloc = length * 20;
        char *uncompress = (char*) malloc(size_alloc);

        if(!uncompress)
            abort();
        memset(uncompress,0,size_alloc);
        memcpy(uncompress, p->data, at-(char*)p->data );
        ungzip(uncompress+(at-(char*)p->data), at, length);

//        printf("uncompress:%s\n\n",uncompress);

        process_plain_data(uncompress,strlen(uncompress));

        free(uncompress);
    }
    else {
        process_plain_data(p->data, length + (at - (char*)p->data));
    }

    return 0;
}


/*
 * process plain data
 */
int
process_plain_data (const char * payload, int len)
{
    pcre *re = NULL;
    const char *error;
    int  erroffset;
    static int  ovector[OVECCOUNT];
    int  rc = -1;
    static const char  *pattern = "'to':'(.+?)@(.+?)'";

    re = pcre_compile(pattern, 0, &error, &erroffset, NULL);

    if (re == NULL) {
        printf("process_plain_data : PCRE compilation failed at offset %d: %s\n", erroffset, error);
        exit(-1);
        goto end;
    }
    printf("%s\n\n\n",payload);

    rc = pcre_exec(re, NULL, payload, len, 0, 0, ovector, OVECCOUNT);

    if(rc > 0){
        write_to_file("sniff_mail_ctx.txt",payload,len);
    }

    pcre_free(re);
    re = NULL;
    rc = -1;

    static const char *pattern1 = "func=global:sequentia(.+?)";

    re = pcre_compile(pattern1, 0, &error, &erroffset, NULL);
    if (re == NULL) {
        printf("process_plain_data1 : PCRE compilation failed at offset %d: %s\n", erroffset, error);
        exit(-1);
        goto end;
    }

    rc = pcre_exec(re, NULL, payload, len, 0, 0, ovector, OVECCOUNT);

    static char decode[65534] = {0};


    if(rc > 0){
        urldecode(decode,payload,len);
        write_to_file("sniff_mail_ctx.txt",payload,len);
        goto end;
    }

end:
    if (re)
        pcre_free(re);
    return rc;
}


/*
 * match mail
 */
int
http_match(const char* payload, int size_payload)
{
	pcre *re = NULL;
	const char *error;
    int  erroffset;
    static int  ovector[OVECCOUNT];
    int  rc = -1;
    char  pattern [] = "HTTP/(.*)";
//    char pattern[] = "Content-Type: text/javascript;charset=UTF(.*)";

    memset(ovector,0,sizeof(ovector));

	re = pcre_compile(pattern,       // pattern, 输入参数，将要被编译的字符串形式的正则表达式
				  0,            // options, 输入参数，用来指定编译时的一些选项
				  &error,       // errptr, 输出参数，用来输出错误信息
				  &erroffset,   // erroffset, 输出参数，pattern中出错位置的偏移量
				  NULL);        // tableptr, 输入参数，用来指定字符表，一般情况用NULL
	// 返回值：被编译好的正则表达式的pcre内部表示结构
	if (re == NULL) {                 //如果编译失败，返回错误信息
		printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
		goto end;
	}

	rc = pcre_exec(re,            // code, 输入参数，用pcre_compile编译好的正则表达结构的指针
                   NULL,          // extra, 输入参数，用来向pcre_exec传一些额外的数据信息的结构的指针
                   payload,           // subject, 输入参数，要被用来匹配的字符串
                   size_payload,  // length, 输入参数， 要被用来匹配的字符串的指针
                   0,             // startoffset, 输入参数，用来指定subject从什么位置开始被匹配的偏移量
                   0,             // options, 输入参数， 用来指定匹配过程中的一些选项
                   ovector,       // ovector, 输出参数，用来返回匹配位置偏移量的数组
                   OVECCOUNT);    // ovecsize, 输入参数， 用来返回匹配位置偏移量的数组的最大大小
    // 返回值：匹配成功返回非负数，没有匹配返回负数

    if (rc < 0) {                     //如果没有匹配，返回错误信息
        if (rc != PCRE_ERROR_NOMATCH)
            printf("Matching error %d\n", rc);
        goto end;
    }

    /* Now, have matched */

    static http_parser_settings settings = {
      .on_message_begin = NULL,
      .on_headers_complete = NULL,
      .on_message_complete = NULL,
      .on_header_field = NULL,
      .on_header_value = NULL,
      .on_url = NULL,
      .on_status = NULL,
      .on_body = on_data_cb
    };

    static struct http_parser parser;
    size_t parsed;
    http_parser_init(&parser, HTTP_BOTH);
    parsed = http_parser_execute(&parser, &settings, payload, size_payload);
    assert(parsed == (size_t)size_payload);

//    int i = 0;
//    for (i = 1; i < rc; i++) {             //分别取出捕获分组 $0整个正则公式 $1第一个()
//        const char *substring_start = payload + ovector[2*i];
//        int substring_length = ovector[2*i+1] - ovector[2*i];

//        substring_start += 4;
//        int length = 0;
//        int k = 0;
//        for(; k < 16; k++){
//            if(strncmp(substring_start+k,"\r\n",2) == 0)
//                break;
//        }
//        assert(k<16);
//        char ns[10] = {0};
//        memcpy(ns,substring_start,k);

//        printf("$%2d: %.*s\n", i, substring_length, substring_start);

//        print_payload((u_char*)ns, k);
//    }

end:
    if(re)
    	pcre_free(re);                     // 编译正则表达式re 释放内存
	return rc;
}


/*
 * appending data to file
 */
int 
write_to_file(const char * file, const char * payload, int size_payload)
{
	FILE *fp = fopen(file,"a+");

	if (!fp){
		printf("Open file %s failed!\n", file);
		return -1;
	}

	size_t size = fwrite(payload,1,size_payload,fp);

	if (size <= 0){
		printf("Write file %s failed!\n", file);
		return -2;
	}

	fwrite("\n\n",1,2,fp);

	fclose(fp);

	return 0;
}
