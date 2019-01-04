//
//  NSString+Tool.h
//  ZMToolbox
//
//  Created by Yuri Boyka on 2018/10/10.
//  Copyright © 2018 Yuri Boyka. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSData (AES256)
- (NSData *)aesEncrypt:(NSString *)key;  //  加密
- (NSData *)aesDecrypt:(NSString *)key;  //  解密
@end

@interface NSString (Tool)
/*MD5*/
- (NSString *)MD5_16;
- (NSString *)MD5_32;

/*DES*/
/// DES加密方法
- (NSString *)desEncrypt:(NSString *)key initVec:(NSString *)iv;
/// DES解密方法
- (NSString *)desDecrypt:(NSString *)key initVec:(NSString *)iv;

/*AES*/
/// AES加密方法
- (NSString *)aesEncrypt:(NSString *)key;
/// AES解密方法
- (NSString *)aesDecrypt:(NSString *)key;

/*GTMBase64*/
/// GTMBase64加密方法
- (NSString *)GTMBase64Encrypt;
/// GTMBase64解密方法
- (NSString *)GTMBase64Decrypt;

@end

NS_ASSUME_NONNULL_END
