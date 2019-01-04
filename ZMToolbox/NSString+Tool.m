//
//  NSString+Tool.m
//  ZMToolbox
//
//  Created by Yuri Boyka on 2018/10/10.
//  Copyright © 2018 Yuri Boyka. All rights reserved.
//

#import "NSString+Tool.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import "GTMBase64.h"

@implementation NSData (AES256)

//  加密
- (NSData *)aesEncrypt:(NSString *)key
{
    // 定义一个字符数组keyPtr，元素个数是kCCKeySizeAES256+1
    // AES256加密，密钥应该是32位的
    char keyPtr[kCCKeySizeAES256 + 1];
    // [sizeof](keyPtr) 数组keyPtr所占空间的大小，即多少个个字节
    // bzero的作用是字符数组keyPtr的前sizeof(keyPtr)个字节为零且包括‘\0’。就是前32位为0，最后一位是\0
    bzero(keyPtr, sizeof(keyPtr));
    // NSString转换成C风格字符串
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];

    NSUInteger dataLength = [self length];
    // buffer缓冲，缓冲区
    //  对于块加密算法：输出的大小<= 输入的大小 +  一个块的大小
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    //  *malloc()*函数其实就在内存中找一片指定大小的空间
    void *buffer = malloc(bufferSize);
    // size_t的全称应该是size
    // type，就是说“一种用来记录大小的数据类型”。通常我们用sizeof(XXX)操作，这个操作所得到的结果就是size_t类型。
    // 英文翻译：num 数量 Byte字节  encrypt解密
    size_t numBytesEncrypted = 0;
    // **<CommonCrypto/CommonCryptor.h>框架下的类与方法**p苹果提供的
    CCCryptorStatus cryptStatus =
        CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding | kCCOptionECBMode, keyPtr, kCCBlockSizeAES128,
                NULL, [self bytes], dataLength, buffer, bufferSize, &numBytesEncrypted);
    if (cryptStatus == kCCSuccess)
    {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    free(buffer);
    return nil;
}

- (NSData *)aesDecrypt:(NSString *)key
{
    char keyPtr[kCCKeySizeAES256 + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [self length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus =
        CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding | kCCOptionECBMode, keyPtr, kCCBlockSizeAES128,
                NULL, [self bytes], dataLength, buffer, bufferSize, &numBytesDecrypted);
    if (cryptStatus == kCCSuccess)
    {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    free(buffer);
    return nil;
}

@end

@implementation NSString (Tool)

- (NSString *)MD5_16
{
    NSString *input = self;
    if (!input)
    {
        return nil;
    }
    const char *str = [input UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(str, (CC_LONG)strlen(str), result);
    NSMutableString *ret = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
    {
        [ret appendFormat:@"%02X", result[i]];
    }
    return ret;
}

- (NSString *)MD5_32
{
    NSString *input = self;
    if (!input)
    {
        return nil;
    }
    const char *str = [input UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_MD5(str, (CC_LONG)strlen(str), result);
    NSMutableString *ret = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
    {
        [ret appendFormat:@"%02X", result[i]];
    }
    return ret;
}

#pragma mark - DES加密方法
- (NSString *)desEncrypt:(NSString *)key initVec:(NSString *)iv
{
    NSString *inputText = self;
    if (!inputText)
    {
        return nil;
    }
    NSData *data = [inputText dataUsingEncoding:NSUTF8StringEncoding];
    size_t inputTextBufferSize = [data length];
    const void *vinputText = (const void *)[data bytes];

    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;

    bufferPtrSize = (inputTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc(bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);

    const void *vkey = (const void *)[key UTF8String];
    const void *vinitVec = (const void *)[iv UTF8String];

    ccStatus = CCCrypt(kCCEncrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding, vkey, kCCKeySize3DES, vinitVec, vinputText,
                       inputTextBufferSize, (void *)bufferPtr, bufferPtrSize, &movedBytes);

    NSData *myData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];
    NSString *result = [GTMBase64 stringByEncodingData:myData];
    return result;
}

#pragma mark - DES解密方法
- (NSString *)desDecrypt:(NSString *)key initVec:(NSString *)iv
{
    NSString *inputText = self;
    if (!inputText)
    {
        return nil;
    }
    NSData *decryptData = [GTMBase64 decodeString:inputText];
    size_t inputTextBufferSize = [decryptData length];
    const void *vinputText = [decryptData bytes];

    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;

    bufferPtrSize = (inputTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc(bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);

    const void *vkey = (const void *)[key UTF8String];
    const void *vinitVec = (const void *)[iv UTF8String];

    ccStatus = CCCrypt(kCCDecrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding, vkey, kCCKeySize3DES, vinitVec, vinputText,
                       inputTextBufferSize, (void *)bufferPtr, bufferPtrSize, &movedBytes);

    NSString *result =
        [[NSString alloc] initWithData:[NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes]
                              encoding:NSUTF8StringEncoding];
    return result;
}

#pragma mark - AES加密方法
- (NSString *)aesEncrypt:(NSString *)key
{
    const char *cstr = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:self.length];
    //对数据进行加密
    NSData *result = [data aesEncrypt:key];
    //转换为2进制字符串
    if (result && result.length > 0)
    {
        Byte *datas = (Byte *)[result bytes];
        NSMutableString *output = [NSMutableString stringWithCapacity:result.length * 2];
        for (int i = 0; i < result.length; i++)
        {
            [output appendFormat:@"%02x", datas[i]];
        }
        return output;
    }
    return nil;
}

#pragma mark - AES解密方法
- (NSString *)aesDecrypt:(NSString *)key
{
    //转换为2进制Data
    NSMutableData *data = [NSMutableData dataWithCapacity:self.length / 2];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0', '\0', '\0'};
    int i;
    for (i = 0; i < [self length] / 2; i++)
    {
        byte_chars[0] = [self characterAtIndex:i * 2];
        byte_chars[1] = [self characterAtIndex:i * 2 + 1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    //对数据进行解密
    NSData *result = [data aesDecrypt:key];
    if (result && result.length > 0)
    {
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    }
    return nil;
}
#pragma mark - GTMBase64加密方法
- (NSString *)GTMBase64Encrypt
{
    NSString *inputText = self;
    if (!inputText)
    {
        return nil;
    }

    NSData *encryptData = [inputText dataUsingEncoding:NSUTF8StringEncoding];
    NSString *result = [GTMBase64 stringByEncodingData:encryptData];

    return result;
}

#pragma mark - GTMBase64解密方法
- (NSString *)GTMBase64Decrypt
{
    NSString *inputText = self;
    if (!inputText)
    {
        return nil;
    }

    NSData *decryptData = [GTMBase64 decodeString:inputText];
    NSString *result = [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding];
    return result;
}

- (NSString *)sha1
{
    const char *cstr = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:self.length];

    uint8_t digest[CC_SHA1_DIGEST_LENGTH];

    CC_SHA1(data.bytes, (uint32_t)data.length, digest);

    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];

    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) [output appendFormat:@"%02x", digest[i]];

    return output;
}

- (NSString *)sha256
{
    const char *cstr = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:self.length];

    uint8_t digest[CC_SHA256_DIGEST_LENGTH];

    CC_SHA256(data.bytes, (uint32_t)data.length, digest);

    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];

    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [output appendFormat:@"%02x", digest[i]];

    return output;
}

- (NSString *)sha384
{
    const char *cstr = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:self.length];

    uint8_t digest[CC_SHA384_DIGEST_LENGTH];

    CC_SHA384(data.bytes, (uint32_t)data.length, digest);

    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA384_DIGEST_LENGTH * 2];

    for (int i = 0; i < CC_SHA384_DIGEST_LENGTH; i++) [output appendFormat:@"%02x", digest[i]];

    return output;
}

- (NSString *)sha512
{
    const char *cstr = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:self.length];

    uint8_t digest[CC_SHA512_DIGEST_LENGTH];

    CC_SHA512(data.bytes, (uint32_t)data.length, digest);

    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];

    for (int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) [output appendFormat:@"%02x", digest[i]];

    return output;
}

// my.app.name ---> MY_APP_NAME
- (NSString *)constantify
{
    return [[self stringByReplacingOccurrencesOfString:@"." withString:@"_"] uppercaseString];
}

// my.app.name ---> myAppName
- (NSString *)variablify
{
    
    return nil;
}

@end
