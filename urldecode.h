#ifndef URLDECODE_H
#define URLDECODE_H

/*
 * @param str 需要解码的url字符串
 * @param len 需要解码的url的长度
 * @return int 返回解码后的url长度
 */

int
urldecode (char *dest, const char *src, int len);

#endif // URLDECODE_H
