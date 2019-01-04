//
//  ZMShellCmd.h
//  ZMToolbox
//
//  Created by Yuri Boyka on 2019/1/4.
//  Copyright © 2019 Yuri Boyka. All rights reserved.
//

#ifndef ZMShellCmd_h
#define ZMShellCmd_h

/**********************************************************************************************************************/
/*                                                  CSR Decoder                                                       */
/*                                                                                                                    */
/*Use this CSR Decoder to decode your Certificate Signing Request and and verify that it contains the correct         */
/*information. A Certificate Signing Request is a block of encoded text that contains information about the company   */
/*that an SSL certificate will be issued to and the SSL public key.Once a CSR is created it is difficult to verify what
/*information is contained in it because it is encoded. Since certificate authorities use the information in CSRs to
/*create the certificate, you need to decode CSRs to make sure the information is accurate. To check CSRs and view the
/*information inside of them, simply paste your CSR into the box below and the AJAX CSR Decoder will do the
/*rest.
/*Your CSR should start with "-----BEGIN CERTIFICATE REQUEST----- " and end with "-----END CERTIFICATE REQUEST----- ".*/
/**********************************************************************************************************************/
// openssl req - in mycsr.csr - noout - text

/**********************************************************************************************************************/
/*                                                Certificate Decoder                                                 */
/*                                                                                                                    */
/* Use this Certificate Decoder to decode your PEM encoded SSL certificate and verify that it contains the correct    */
/* information. A PEM encoded certificate is a block of encoded text that contains all of the certificate information */
/* and public key. Another simple way to view the information in a certificate on a Windows machine is to just        */
/* double-click the certificate file. You can use this certificate viewer by simply pasting the text of your          */
/* certificate into the box below and the Certificate Decoder will do the rest.                                       */
/* Your certificate should start with "-----BEGIN CERTIFICATE----- " and end with "-----END CERTIFICATE----- ".       */
/**********************************************************************************************************************/
// openssl x509 -in certificate.crt -text -noout

// security import priv_key.p12 -k ~/Library/Keychains/login.keychain

// security import pub_key.pem -k ~/Library/Keychains/login.keychain

#endif /* ZMShellCmd_h */
