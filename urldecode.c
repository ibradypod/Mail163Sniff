#include "urldecode.h"

/*
 * @param src 需要解码的url字符串
 * @param len 需要解码的url的长度
 * @return int 返回解码后的url长度
 */

int
urldecode (char *dest, const char *src, int len)
{
    unsigned char value;
    unsigned char c;
    const char *start = (const char*)dest;

    while (len--) {
        if (*src == '+') {
        *dest = ' ';
        }
        else if (*src == '%' && len >= 2 && isxdigit((int) *(src + 1))
                 && isxdigit((int) *(src + 2)))
        {

            c = ((unsigned char *)(src+1))[0];
            if (isupper(c))
                c = tolower(c);
            value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;
            c = ((unsigned char *)(src+1))[1];
            if (isupper(c))
                c = tolower(c);
            value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

            *dest = (char)value ;
            src += 2;
            len -= 2;
        } else {
            *dest = *src;
        }
        src++;
        dest++;
    }
    *dest = '\0';
    return dest - start;
}
