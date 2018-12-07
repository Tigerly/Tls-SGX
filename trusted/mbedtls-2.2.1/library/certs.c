/*
 *  X.509 test certificates
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/certs.h"

#if defined(MBEDTLS_CERTS_C)

#if defined(MBEDTLS_ECDSA_C)
#define TEST_CA_CRT_EC                                                  \
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"MIICUjCCAdegAwIBAgIJAMFD4n5iQ8zoMAoGCCqGSM49BAMCMD4xCzAJBgNVBAYT\r\n"  \
"Ak5MMREwDwYDVQQKEwhQb2xhclNTTDEcMBoGA1UEAxMTUG9sYXJzc2wgVGVzdCBF\r\n"  \
"QyBDQTAeFw0xMzA5MjQxNTQ5NDhaFw0yMzA5MjIxNTQ5NDhaMD4xCzAJBgNVBAYT\r\n"  \
"Ak5MMREwDwYDVQQKEwhQb2xhclNTTDEcMBoGA1UEAxMTUG9sYXJzc2wgVGVzdCBF\r\n"  \
"QyBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABMPaKzRBN1gvh1b+/Im6KUNLTuBu\r\n"  \
"ww5XUzM5WNRStJGVOQsj318XJGJI/BqVKc4sLYfCiFKAr9ZqqyHduNMcbli4yuiy\r\n"  \
"aY7zQa0pw7RfdadHb9UZKVVpmlM7ILRmFmAzHqOBoDCBnTAdBgNVHQ4EFgQUnW0g\r\n"  \
"JEkBPyvLeLUZvH4kydv7NnwwbgYDVR0jBGcwZYAUnW0gJEkBPyvLeLUZvH4kydv7\r\n"  \
"NnyhQqRAMD4xCzAJBgNVBAYTAk5MMREwDwYDVQQKEwhQb2xhclNTTDEcMBoGA1UE\r\n"  \
"AxMTUG9sYXJzc2wgVGVzdCBFQyBDQYIJAMFD4n5iQ8zoMAwGA1UdEwQFMAMBAf8w\r\n"  \
"CgYIKoZIzj0EAwIDaQAwZgIxAMO0YnNWKJUAfXgSJtJxexn4ipg+kv4znuR50v56\r\n"  \
"t4d0PCu412mUC6Nnd7izvtE2MgIxAP1nnJQjZ8BWukszFQDG48wxCCyci9qpdSMv\r\n"  \
"uCjn8pwUOkABXK8Mss90fzCfCEOtIA==\r\n"                                  \
"-----END CERTIFICATE-----\r\n"
const char mbedtls_test_ca_crt_ec[] = TEST_CA_CRT_EC;

const char mbedtls_test_ca_key_ec[] =
"-----BEGIN EC PRIVATE KEY-----\r\n"
"Proc-Type: 4,ENCRYPTED\r\n"
"DEK-Info: DES-EDE3-CBC,307EAB469933D64E\r\n"
"\r\n"
"IxbrRmKcAzctJqPdTQLA4SWyBYYGYJVkYEna+F7Pa5t5Yg/gKADrFKcm6B72e7DG\r\n"
"ihExtZI648s0zdYw6qSJ74vrPSuWDe5qm93BqsfVH9svtCzWHW0pm1p0KTBCFfUq\r\n"
"UsuWTITwJImcnlAs1gaRZ3sAWm7cOUidL0fo2G0fYUFNcYoCSLffCFTEHBuPnagb\r\n"
"a77x/sY1Bvii8S9/XhDTb6pTMx06wzrm\r\n"
"-----END EC PRIVATE KEY-----\r\n";

const char mbedtls_test_ca_pwd_ec[] = "PolarSSLTest";

const char mbedtls_test_srv_crt_ec[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICHzCCAaWgAwIBAgIBCTAKBggqhkjOPQQDAjA+MQswCQYDVQQGEwJOTDERMA8G\r\n"
"A1UEChMIUG9sYXJTU0wxHDAaBgNVBAMTE1BvbGFyc3NsIFRlc3QgRUMgQ0EwHhcN\r\n"
"MTMwOTI0MTU1MjA0WhcNMjMwOTIyMTU1MjA0WjA0MQswCQYDVQQGEwJOTDERMA8G\r\n"
"A1UEChMIUG9sYXJTU0wxEjAQBgNVBAMTCWxvY2FsaG9zdDBZMBMGByqGSM49AgEG\r\n"
"CCqGSM49AwEHA0IABDfMVtl2CR5acj7HWS3/IG7ufPkGkXTQrRS192giWWKSTuUA\r\n"
"2CMR/+ov0jRdXRa9iojCa3cNVc2KKg76Aci07f+jgZ0wgZowCQYDVR0TBAIwADAd\r\n"
"BgNVHQ4EFgQUUGGlj9QH2deCAQzlZX+MY0anE74wbgYDVR0jBGcwZYAUnW0gJEkB\r\n"
"PyvLeLUZvH4kydv7NnyhQqRAMD4xCzAJBgNVBAYTAk5MMREwDwYDVQQKEwhQb2xh\r\n"
"clNTTDEcMBoGA1UEAxMTUG9sYXJzc2wgVGVzdCBFQyBDQYIJAMFD4n5iQ8zoMAoG\r\n"
"CCqGSM49BAMCA2gAMGUCMQCaLFzXptui5WQN8LlO3ddh1hMxx6tzgLvT03MTVK2S\r\n"
"C12r0Lz3ri/moSEpNZWqPjkCMCE2f53GXcYLqyfyJR078c/xNSUU5+Xxl7VZ414V\r\n"
"fGa5kHvHARBPc8YAIVIqDvHH1Q==\r\n"
"-----END CERTIFICATE-----\r\n";

const char mbedtls_test_srv_key_ec[] =
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEIPEqEyB2AnCoPL/9U/YDHvdqXYbIogTywwyp6/UfDw6noAoGCCqGSM49\r\n"
"AwEHoUQDQgAEN8xW2XYJHlpyPsdZLf8gbu58+QaRdNCtFLX3aCJZYpJO5QDYIxH/\r\n"
"6i/SNF1dFr2KiMJrdw1VzYoqDvoByLTt/w==\r\n"
"-----END EC PRIVATE KEY-----\r\n";

const char mbedtls_test_cli_crt_ec[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICLDCCAbKgAwIBAgIBDTAKBggqhkjOPQQDAjA+MQswCQYDVQQGEwJOTDERMA8G\r\n"
"A1UEChMIUG9sYXJTU0wxHDAaBgNVBAMTE1BvbGFyc3NsIFRlc3QgRUMgQ0EwHhcN\r\n"
"MTMwOTI0MTU1MjA0WhcNMjMwOTIyMTU1MjA0WjBBMQswCQYDVQQGEwJOTDERMA8G\r\n"
"A1UEChMIUG9sYXJTU0wxHzAdBgNVBAMTFlBvbGFyU1NMIFRlc3QgQ2xpZW50IDIw\r\n"
"WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARX5a6xc9/TrLuTuIH/Eq7u5lOszlVT\r\n"
"9jQOzC7jYyUL35ji81xgNpbA1RgUcOV/n9VLRRjlsGzVXPiWj4dwo+THo4GdMIGa\r\n"
"MAkGA1UdEwQCMAAwHQYDVR0OBBYEFHoAX4Zk/OBd5REQO7LmO8QmP8/iMG4GA1Ud\r\n"
"IwRnMGWAFJ1tICRJAT8ry3i1Gbx+JMnb+zZ8oUKkQDA+MQswCQYDVQQGEwJOTDER\r\n"
"MA8GA1UEChMIUG9sYXJTU0wxHDAaBgNVBAMTE1BvbGFyc3NsIFRlc3QgRUMgQ0GC\r\n"
"CQDBQ+J+YkPM6DAKBggqhkjOPQQDAgNoADBlAjBKZQ17IIOimbmoD/yN7o89u3BM\r\n"
"lgOsjnhw3fIOoLIWy2WOGsk/LGF++DzvrRzuNiACMQCd8iem1XS4JK7haj8xocpU\r\n"
"LwjQje5PDGHfd3h9tP38Qknu5bJqws0md2KOKHyeV0U=\r\n"
"-----END CERTIFICATE-----\r\n";

const char mbedtls_test_cli_key_ec[] =
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEIPb3hmTxZ3/mZI3vyk7p3U3wBf+WIop6hDhkFzJhmLcqoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEV+WusXPf06y7k7iB/xKu7uZTrM5VU/Y0Dswu42MlC9+Y4vNcYDaW\r\n"
"wNUYFHDlf5/VS0UY5bBs1Vz4lo+HcKPkxw==\r\n"
"-----END EC PRIVATE KEY-----\r\n";

const size_t mbedtls_test_ca_crt_ec_len  = sizeof( mbedtls_test_ca_crt_ec );
const size_t mbedtls_test_ca_key_ec_len  = sizeof( mbedtls_test_ca_key_ec );
const size_t mbedtls_test_ca_pwd_ec_len  = sizeof( mbedtls_test_ca_pwd_ec ) - 1;
const size_t mbedtls_test_srv_crt_ec_len = sizeof( mbedtls_test_srv_crt_ec );
const size_t mbedtls_test_srv_key_ec_len = sizeof( mbedtls_test_srv_key_ec );
const size_t mbedtls_test_cli_crt_ec_len = sizeof( mbedtls_test_cli_crt_ec );
const size_t mbedtls_test_cli_key_ec_len = sizeof( mbedtls_test_cli_key_ec );
#else
#define TEST_CA_CRT_EC
#endif /* MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_RSA_C)
#define TEST_CA_CRT_RSA                                           \
"-----BEGIN CERTIFICATE-----\r\n"\
"MIIFsTCCA5mgAwIBAgIJAP1dDgAupgNqMA0GCSqGSIb3DQEBCwUAMG8xCzAJBgNV\r\n"\
"BAYTAlVTMREwDwYDVQQIDAh2aXJnaW5pYTETMBEGA1UEBwwKYmxhY2tzYnVyZzEL\r\n"\
"MAkGA1UECgwCdnQxCzAJBgNVBAsMAnZ0MQswCQYDVQQDDAJ2dDERMA8GCSqGSIb3\r\n"\
"DQEJARYCdnQwHhcNMTcxMTI3MTk1NjQ3WhcNMTgxMTI3MTk1NjQ3WjBvMQswCQYD\r\n"\
"VQQGEwJVUzERMA8GA1UECAwIdmlyZ2luaWExEzARBgNVBAcMCmJsYWNrc2J1cmcx\r\n"\
"CzAJBgNVBAoMAnZ0MQswCQYDVQQLDAJ2dDELMAkGA1UEAwwCdnQxETAPBgkqhkiG\r\n"\
"9w0BCQEWAnZ0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA7B2dhJxe\r\n"\
"logLrx5Xzo+uZdg1l+WWO0G5pPDAKXmpoxzfKkOBngCr2QdcSqw+yXaGFM5+ZwDC\r\n"\
"MNhBZDEUUE3s6aIw3p6T+agtHt8CLPblmU6DsRnZ3Ro5WyEkUKL5s3YGeAQbkM2J\r\n"\
"da/T+i+oi45HyE/64WuVqha3wORNFjt3U3tLFip2BbpX5/rXHNsN8VGYVGoV6P07\r\n"\
"VkmDuK94EJSW6E7rgTdvNos4rfsI0M3y+uO1Gdp7CR2Non+tAZpsrMEwctlNJkwx\r\n"\
"Ju6VGr4FppG8aqcDyYyzI9MPlfXPp00uoN9EUbpNAe560SC1rBh8Urr/xDLpISX6\r\n"\
"8W3z/jL5NLaBgDXeCPq6MB5P54DA5GzW2CwGUxUu5o1MKJACX1LIj967Q3yTr3kw\r\n"\
"J1ujwVzCxKTu2N7fUv6I37nUb0PW+EvXWzUlWiPsHIObJBuw7POZA/5vsZAOVU9x\r\n"\
"ue9Eu5wkbrzfue6pzWZ1+E0jZRIkJlV5i7YMOx1hNmbv1UbxGGoeCPWVkl7GEmNH\r\n"\
"rVfXNDbDMl40Wa5WiuB0POvrAxVuAd73/UsosAQ4mpPfUyGZHFHRhtynEKyyDZCi\r\n"\
"LtUm9ZROX11duQw06kTikl44Xf45qlDGC9lYpd8/xQ8fBLvo69nUk7dPTx6BJL0U\r\n"\
"RkKJaIfTu6zs/Jkx52cRM/Gb8jNPFQU3WoUCAwEAAaNQME4wHQYDVR0OBBYEFF78\r\n"\
"9pRx8jYHnWi1Ltrqc6vpWGS5MB8GA1UdIwQYMBaAFF789pRx8jYHnWi1Ltrqc6vp\r\n"\
"WGS5MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAKRFFR8479Jz08K7\r\n"\
"AvawYzzxQbNaH6Zhsjn/gnYary7eZimR/qb6LFrraGq5ot0PKkF9aMlsJcXbhdZm\r\n"\
"uQCJ66Mvc49eT9lAQ7M3DiACgULx/ot/lPHnnCZOvgS/REMwXJ2z0g7TNms5/LGR\r\n"\
"8TA/YCLvilgbH7DyyvNb//GXUIXt69soosu/fX/jHIhufGDx1ZJZY16XXYeX94ar\r\n"\
"MiELv57CZIGXXzJZJPP+bXqo35/fmrDt7FEXq2pU6mgqIXV0KdS6xmeAbokfMoBI\r\n"\
"lTDZhF2B9CktMj6xd95dDuwkYbwaF8EVjfRzV2id68OY/eQJwwiy+f87PaiI+8vO\r\n"\
"5Uexk+wXT77B2NeJsFT88iG7E8bNZ/5QDrOI/i9j1JV7e8fmqdMin754wNFBSoBP\r\n"\
"E52I4Owav2Dh7FWoHKprMTz2Qb9I+Wgh6voJyx3oeyHff9E+te7intT+vgTD2At9\r\n"\
"XPypkDA3NZe6t/cYh/wG8ocxZ6U2MGuHgpMKPaoBeH+Y7rYh0Ll919jSpR9eEt1N\r\n"\
"XB60O0prLrDsgSZHZeEHbX3PlYkD1uYAIDevsQURYrb5VXzrEpjnJWMd78nJ3LC8\r\n"\
"1Kh8dkdlNEN6MeKNOC+ndYJRE5wmZT76Ssp8so1uowWJYRtmR1Bg5IIK6qWpgTqw\r\n"\
"ImQzZovtYACGEx6XfwtukmGsgYYj\r\n"\
"-----END CERTIFICATE-----\r\n"

/*"-----BEGIN CERTIFICATE-----\r\n"                                       \
"MIIDhzCCAm+gAwIBAgIBADANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n"  \
"MA8GA1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n"  \
"MTEwMjEyMTQ0NDAwWhcNMjEwMjEyMTQ0NDAwWjA7MQswCQYDVQQGEwJOTDERMA8G\r\n"  \
"A1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwggEiMA0G\r\n"  \
"CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA3zf8F7vglp0/ht6WMn1EpRagzSHx\r\n"  \
"mdTs6st8GFgIlKXsm8WL3xoemTiZhx57wI053zhdcHgH057Zk+i5clHFzqMwUqny\r\n"  \
"50BwFMtEonILwuVA+T7lpg6z+exKY8C4KQB0nFc7qKUEkHHxvYPZP9al4jwqj+8n\r\n"  \
"YMPGn8u67GB9t+aEMr5P+1gmIgNb1LTV+/Xjli5wwOQuvfwu7uJBVcA0Ln0kcmnL\r\n"  \
"R7EUQIN9Z/SG9jGr8XmksrUuEvmEF/Bibyc+E1ixVA0hmnM3oTDPb5Lc9un8rNsu\r\n"  \
"KNF+AksjoBXyOGVkCeoMbo4bF6BxyLObyavpw/LPh5aPgAIynplYb6LVAgMBAAGj\r\n"  \
"gZUwgZIwDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUtFrkpbPe0lL2udWmlQ/rPrzH\r\n"  \
"/f8wYwYDVR0jBFwwWoAUtFrkpbPe0lL2udWmlQ/rPrzH/f+hP6Q9MDsxCzAJBgNV\r\n"  \
"BAYTAk5MMREwDwYDVQQKEwhQb2xhclNTTDEZMBcGA1UEAxMQUG9sYXJTU0wgVGVz\r\n"  \
"dCBDQYIBADANBgkqhkiG9w0BAQUFAAOCAQEAuP1U2ABUkIslsCfdlc2i94QHHYeJ\r\n"  \
"SsR4EdgHtdciUI5I62J6Mom+Y0dT/7a+8S6MVMCZP6C5NyNyXw1GWY/YR82XTJ8H\r\n"  \
"DBJiCTok5DbZ6SzaONBzdWHXwWwmi5vg1dxn7YxrM9d0IjxM27WNKs4sDQhZBQkF\r\n"  \
"pjmfs2cb4oPl4Y9T9meTx/lvdkRYEug61Jfn6cA+qHpyPYdTH+UshITnmp5/Ztkf\r\n"  \
"m/UTSLBNFNHesiTZeH31NcxYGdHSme9Nc/gfidRa0FLOCfWxRlFqAI47zG9jAQCZ\r\n"  \
"7Z2mCGDNMhjQc+BYcdnl0lPXjdDK6V0qCg1dVewhUBcW5gZKzV7e9+DpVA==\r\n"      \
"-----END CERTIFICATE-----\r\n"*/


const char mbedtls_test_ca_crt_rsa[] = TEST_CA_CRT_RSA;

const char mbedtls_test_ca_key_rsa[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"Proc-Type: 4,ENCRYPTED\r\n"
"DEK-Info: DES-EDE3-CBC,A1CF6B9F288690B4\r\n"
"\r\n"
"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\r\n"
"-----END RSA PRIVATE KEY-----\r\n";
/*"-----BEGIN RSA PRIVATE KEY-----\r\n"
"Proc-Type: 4,ENCRYPTED\r\n"
"DEK-Info: DES-EDE3-CBC,A8A95B05D5B7206B\r\n"
"\r\n"
"9Qd9GeArejl1GDVh2lLV1bHt0cPtfbh5h/5zVpAVaFpqtSPMrElp50Rntn9et+JA\r\n"
"7VOyboR+Iy2t/HU4WvA687k3Bppe9GwKHjHhtl//8xFKwZr3Xb5yO5JUP8AUctQq\r\n"
"Nb8CLlZyuUC+52REAAthdWgsX+7dJO4yabzUcQ22Tp9JSD0hiL43BlkWYUNK3dAo\r\n"
"PZlmiptjnzVTjg1MxsBSydZinWOLBV8/JQgxSPo2yD4uEfig28qbvQ2wNIn0pnAb\r\n"
"GxnSAOazkongEGfvcjIIs+LZN9gXFhxcOh6kc4Q/c99B7QWETwLLkYgZ+z1a9VY9\r\n"
"gEU7CwCxYCD+h9hY6FPmsK0/lC4O7aeRKpYq00rPPxs6i7phiexg6ax6yTMmArQq\r\n"
"QmK3TAsJm8V/J5AWpLEV6jAFgRGymGGHnof0DXzVWZidrcZJWTNuGEX90nB3ee2w\r\n"
"PXJEFWKoD3K3aFcSLdHYr3mLGxP7H9ThQai9VsycxZKS5kwvBKQ//YMrmFfwPk8x\r\n"
"vTeY4KZMaUrveEel5tWZC94RSMKgxR6cyE1nBXyTQnDOGbfpNNgBKxyKbINWoOJU\r\n"
"WJZAwlsQn+QzCDwpri7+sV1mS3gBE6UY7aQmnmiiaC2V3Hbphxct/en5QsfDOt1X\r\n"
"JczSfpRWLlbPznZg8OQh/VgCMA58N5DjOzTIK7sJJ5r+94ZBTCpgAMbF588f0NTR\r\n"
"KCe4yrxGJR7X02M4nvD4IwOlpsQ8xQxZtOSgXv4LkxvdU9XJJKWZ/XNKJeWztxSe\r\n"
"Z1vdTc2YfsDBA2SEv33vxHx2g1vqtw8SjDRT2RaQSS0QuSaMJimdOX6mTOCBKk1J\r\n"
"9Q5mXTrER+/LnK0jEmXsBXWA5bqqVZIyahXSx4VYZ7l7w/PHiUDtDgyRhMMKi4n2\r\n"
"iQvQcWSQTjrpnlJbca1/DkpRt3YwrvJwdqb8asZU2VrNETh5x0QVefDRLFiVpif/\r\n"
"tUaeAe/P1F8OkS7OIZDs1SUbv/sD2vMbhNkUoCms3/PvNtdnvgL4F0zhaDpKCmlT\r\n"
"P8vx49E7v5CyRNmED9zZg4o3wmMqrQO93PtTug3Eu9oVx1zPQM1NVMyBa2+f29DL\r\n"
"1nuTCeXdo9+ni45xx+jAI4DCwrRdhJ9uzZyC6962H37H6D+5naNvClFR1s6li1Gb\r\n"
"nqPoiy/OBsEx9CaDGcqQBp5Wme/3XW+6z1ISOx+igwNTVCT14mHdBMbya0eIKft5\r\n"
"X+GnwtgEMyCYyyWuUct8g4RzErcY9+yW9Om5Hzpx4zOuW4NPZgPDTgK+t2RSL/Yq\r\n"
"rE1njrgeGYcVeG3f+OftH4s6fPbq7t1A5ZgUscbLMBqr9tK+OqygR4EgKBPsH6Cz\r\n"
"L6zlv/2RV0qAHvVuDJcIDIgwY5rJtINEm32rhOeFNJwZS5MNIC1czXZx5//ugX7l\r\n"
"I4sy5nbVhwSjtAk8Xg5dZbdTZ6mIrb7xqH+fdakZor1khG7bC2uIwibD3cSl2XkR\r\n"
"wN48lslbHnqqagr6Xm1nNOSVl8C/6kbJEsMpLhAezfRtGwvOucoaE+WbeUNolGde\r\n"
"P/eQiddSf0brnpiLJRh7qZrl9XuqYdpUqnoEdMAfotDOID8OtV7gt8a48ad8VPW2\r\n"
"-----END RSA PRIVATE KEY-----\r\n";
*/
const char mbedtls_test_ca_pwd_rsa[] = "PolarSSLTest";

const char mbedtls_test_srv_crt_rsa[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIFVjCCAz4CAQEwDQYJKoZIhvcNAQELBQAwbzELMAkGA1UEBhMCVVMxETAPBgNV\r\n"
"BAgMCHZpcmdpbmlhMRMwEQYDVQQHDApibGFja3NidXJnMQswCQYDVQQKDAJ2dDEL\r\n"
"MAkGA1UECwwCdnQxCzAJBgNVBAMMAnZ0MREwDwYJKoZIhvcNAQkBFgJ2dDAeFw0x\r\n"
"NzExMjcyMDAzMTVaFw0xODExMjcyMDAzMTVaMHMxCzAJBgNVBAYTAlVTMREwDwYD\r\n"
"VQQIDAh2aXJnaW5pYTETMBEGA1UEBwwKYmxhY2tzYnVyZzEMMAoGA1UECgwDdnQy\r\n"
"MQwwCgYDVQQLDAN2dDIxDDAKBgNVBAMMA3Z0MjESMBAGCSqGSIb3DQEJARYDdnQy\r\n"
"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2IcIdvzvi32AwDW4Ehhj\r\n"
"ihlp5wgUOyA0o7raaz/F3BWFZyRNKon4Vcvdmb8r8xZeT1tobpmamzI8exeaeiUX\r\n"
"bPTDhyWi8+Ur2wTujzjm588u3UKUB0not9PB3mEdZgFSI+mud73mKcgOXuxqZtW9\r\n"
"0Ttf2r9WMt+/oEzjs6NeYC+i4rdiazRDoCb6LZoKvyYlMySns1ijcaw1wK7IIi+i\r\n"
"Hik6Xy+uFmBHd9BBMR+mwXoPQ3NJrej+uSyW6c1SNywIBDt0GkJszMZJ6KGmz+kr\r\n"
"SpXeaElgBMhCzVd1ELf8CTKCJr94rMfJaXPb2CG09TBZROdhtf69euHqiCiTFxQN\r\n"
"ol39tmImoxyrr1TpPQhMgtAB3XNsEkPPrpFrkQu+ipny3OovXbBYsXn2dQ54HFhn\r\n"
"ejpOHY6wQJQ3/w00k7hHvAlxmige3m/KsFS6khDCw0ra18gNAdQNlChboyUrsFV4\r\n"
"EMRArTmcAJIO9rgDeDOtxqMV32PcVGtI0h8m6sQss04alKDvlrRuhOzAp58fLW8z\r\n"
"ZP3jS9ifu3Ufam23ZOzS2X2HxAdVnsyffrL6hYypGGzMujAjsKqMostUDGuvZDXC\r\n"
"G/M0YtqSj/FuSITE2I7Xs/kekDRrs8QIVwKAH/AvZCZhzQLxUlEHwm/CRAopvoKL\r\n"
"GiN1bBtekDtYGtBHpLq58p0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAS/ETtk9g\r\n"
"5ceojkQ0NJDDBjRXVmDW1Kl3kM5ucAAFG7630cZQUTze2SzNE2g8myQXQkvFtCFF\r\n"
"xhpz4CCJmHkb4ajpdpNaluCkYPXujSrQN6urRAjvwEDhOjd8fjUxhfXtz9bYOymT\r\n"
"ik5ZP6QI39LbHyVnS2z6yqPyYQN5lBq/dwMcRw2aQg2H9NihWz7VMpEyVAZLPD8X\r\n"
"Et9MN53hSdq/VoHi3WtUw5RNrv5Y+pMwnIG87tii8HXs0l0mbTPf7UzEO+0U+XYa\r\n"
"JLcHKDPpsMk1lt7OrNRyoSMiN0ZSl8mL5+IBVHavDhg+lGE6vJtIo7y8xfjLTALJ\r\n"
"MZe9NGTfbAIDMAyH9vgn081J1N4HDXutDQrY1KrMvNhJe4FhA3C0lerE5fpYtt6d\r\n"
"+aaSjD1oUg/SeeB+lfHkhywSkSWFXVOsd3n6zawMILBEOH75iv0ULlO2kjVLX4C2\r\n"
"UwetRTGz803DJRLuycNJAPGbA6bJFKBlkSnYQasSeSD5zWMKKVduTQgq3A4ky69d\r\n"
"c6LtHLuSmG5nHFIND7fHbLtayiE/+DF8HaAKfVIyKGeAeNJZrNVbexDTKqiBtKjD\r\n"
"iu5VovwKyAzY+5dazTsYAccOBswq/DXHYQiE2EfBtkGHVJ8MoILMO1zOqXlXzJZu\r\n"
"xPCQNz97Et9ye/yxNMQiGPIOCbk5WldgbFk=\r\n"
"-----END CERTIFICATE-----\r\n";
/*"-----BEGIN CERTIFICATE-----\r\n"
"MIIDNzCCAh+gAwIBAgIBAjANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n"
"MA8GA1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n"
"MTEwMjEyMTQ0NDA2WhcNMjEwMjEyMTQ0NDA2WjA0MQswCQYDVQQGEwJOTDERMA8G\r\n"
"A1UEChMIUG9sYXJTU0wxEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcN\r\n"
"AQEBBQADggEPADCCAQoCggEBAMFNo93nzR3RBNdJcriZrA545Do8Ss86ExbQWuTN\r\n"
"owCIp+4ea5anUrSQ7y1yej4kmvy2NKwk9XfgJmSMnLAofaHa6ozmyRyWvP7BBFKz\r\n"
"NtSj+uGxdtiQwWG0ZlI2oiZTqqt0Xgd9GYLbKtgfoNkNHC1JZvdbJXNG6AuKT2kM\r\n"
"tQCQ4dqCEGZ9rlQri2V5kaHiYcPNQEkI7mgM8YuG0ka/0LiqEQMef1aoGh5EGA8P\r\n"
"hYvai0Re4hjGYi/HZo36Xdh98yeJKQHFkA4/J/EwyEoO79bex8cna8cFPXrEAjya\r\n"
"HT4P6DSYW8tzS1KW2BGiLICIaTla0w+w3lkvEcf36hIBMJcCAwEAAaNNMEswCQYD\r\n"
"VR0TBAIwADAdBgNVHQ4EFgQUpQXoZLjc32APUBJNYKhkr02LQ5MwHwYDVR0jBBgw\r\n"
"FoAUtFrkpbPe0lL2udWmlQ/rPrzH/f8wDQYJKoZIhvcNAQEFBQADggEBAJxnXClY\r\n"
"oHkbp70cqBrsGXLybA74czbO5RdLEgFs7rHVS9r+c293luS/KdliLScZqAzYVylw\r\n"
"UfRWvKMoWhHYKp3dEIS4xTXk6/5zXxhv9Rw8SGc8qn6vITHk1S1mPevtekgasY5Y\r\n"
"iWQuM3h4YVlRH3HHEMAD1TnAexfXHHDFQGe+Bd1iAbz1/sH9H8l4StwX6egvTK3M\r\n"
"wXRwkKkvjKaEDA9ATbZx0mI8LGsxSuCqe9r9dyjmttd47J1p1Rulz3CLzaRcVIuS\r\n"
"RRQfaD8neM9c1S/iJ/amTVqJxA1KOdOS5780WhPfSArA+g4qAmSjelc3p4wWpha8\r\n"
"zhuYwjVuX6JHG0c=\r\n"
"-----END CERTIFICATE-----\r\n";
*/
const char mbedtls_test_srv_key_rsa[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"Proc-Type: 4,ENCRYPTED\r\n"
"DEK-Info: DES-EDE3-CBC,295C03EEF1890180\r\n"
"\r\n"
"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\r\n"
"-----END RSA PRIVATE KEY-----\r\n";
/*"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIIEpAIBAAKCAQEAwU2j3efNHdEE10lyuJmsDnjkOjxKzzoTFtBa5M2jAIin7h5r\r\n"
"lqdStJDvLXJ6PiSa/LY0rCT1d+AmZIycsCh9odrqjObJHJa8/sEEUrM21KP64bF2\r\n"
"2JDBYbRmUjaiJlOqq3ReB30Zgtsq2B+g2Q0cLUlm91slc0boC4pPaQy1AJDh2oIQ\r\n"
"Zn2uVCuLZXmRoeJhw81ASQjuaAzxi4bSRr/QuKoRAx5/VqgaHkQYDw+Fi9qLRF7i\r\n"
"GMZiL8dmjfpd2H3zJ4kpAcWQDj8n8TDISg7v1t7HxydrxwU9esQCPJodPg/oNJhb\r\n"
"y3NLUpbYEaIsgIhpOVrTD7DeWS8Rx/fqEgEwlwIDAQABAoIBAQCXR0S8EIHFGORZ\r\n"
"++AtOg6eENxD+xVs0f1IeGz57Tjo3QnXX7VBZNdj+p1ECvhCE/G7XnkgU5hLZX+G\r\n"
"Z0jkz/tqJOI0vRSdLBbipHnWouyBQ4e/A1yIJdlBtqXxJ1KE/ituHRbNc4j4kL8Z\r\n"
"/r6pvwnTI0PSx2Eqs048YdS92LT6qAv4flbNDxMn2uY7s4ycS4Q8w1JXnCeaAnYm\r\n"
"WYI5wxO+bvRELR2Mcz5DmVnL8jRyml6l6582bSv5oufReFIbyPZbQWlXgYnpu6He\r\n"
"GTc7E1zKYQGG/9+DQUl/1vQuCPqQwny0tQoX2w5tdYpdMdVm+zkLtbajzdTviJJa\r\n"
"TWzL6lt5AoGBAN86+SVeJDcmQJcv4Eq6UhtRr4QGMiQMz0Sod6ettYxYzMgxtw28\r\n"
"CIrgpozCc+UaZJLo7UxvC6an85r1b2nKPCLQFaggJ0H4Q0J/sZOhBIXaoBzWxveK\r\n"
"nupceKdVxGsFi8CDy86DBfiyFivfBj+47BbaQzPBj7C4rK7UlLjab2rDAoGBAN2u\r\n"
"AM2gchoFiu4v1HFL8D7lweEpi6ZnMJjnEu/dEgGQJFjwdpLnPbsj4c75odQ4Gz8g\r\n"
"sw9lao9VVzbusoRE/JGI4aTdO0pATXyG7eG1Qu+5Yc1YGXcCrliA2xM9xx+d7f+s\r\n"
"mPzN+WIEg5GJDYZDjAzHG5BNvi/FfM1C9dOtjv2dAoGAF0t5KmwbjWHBhcVqO4Ic\r\n"
"BVvN3BIlc1ue2YRXEDlxY5b0r8N4XceMgKmW18OHApZxfl8uPDauWZLXOgl4uepv\r\n"
"whZC3EuWrSyyICNhLY21Ah7hbIEBPF3L3ZsOwC+UErL+dXWLdB56Jgy3gZaBeW7b\r\n"
"vDrEnocJbqCm7IukhXHOBK8CgYEAwqdHB0hqyNSzIOGY7v9abzB6pUdA3BZiQvEs\r\n"
"3LjHVd4HPJ2x0N8CgrBIWOE0q8+0hSMmeE96WW/7jD3fPWwCR5zlXknxBQsfv0gP\r\n"
"3BC5PR0Qdypz+d+9zfMf625kyit4T/hzwhDveZUzHnk1Cf+IG7Q+TOEnLnWAWBED\r\n"
"ISOWmrUCgYAFEmRxgwAc/u+D6t0syCwAYh6POtscq9Y0i9GyWk89NzgC4NdwwbBH\r\n"
"4AgahOxIxXx2gxJnq3yfkJfIjwf0s2DyP0kY2y6Ua1OeomPeY9mrIS4tCuDQ6LrE\r\n"
"TB6l9VGoxJL4fyHnZb8L5gGvnB1bbD8cL6YPaDiOhcRseC9vBiEuVg==\r\n"
"-----END RSA PRIVATE KEY-----\r\n";
*/
const char mbedtls_test_cli_crt_rsa[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDPzCCAiegAwIBAgIBBDANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n"
"MA8GA1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n"
"MTEwMjEyMTQ0NDA3WhcNMjEwMjEyMTQ0NDA3WjA8MQswCQYDVQQGEwJOTDERMA8G\r\n"
"A1UEChMIUG9sYXJTU0wxGjAYBgNVBAMTEVBvbGFyU1NMIENsaWVudCAyMIIBIjAN\r\n"
"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyHTEzLn5tXnpRdkUYLB9u5Pyax6f\r\n"
"M60Nj4o8VmXl3ETZzGaFB9X4J7BKNdBjngpuG7fa8H6r7gwQk4ZJGDTzqCrSV/Uu\r\n"
"1C93KYRhTYJQj6eVSHD1bk2y1RPD0hrt5kPqQhTrdOrA7R/UV06p86jt0uDBMHEw\r\n"
"MjDV0/YI0FZPRo7yX/k9Z5GIMC5Cst99++UMd//sMcB4j7/Cf8qtbCHWjdmLao5v\r\n"
"4Jv4EFbMs44TFeY0BGbH7vk2DmqV9gmaBmf0ZXH4yqSxJeD+PIs1BGe64E92hfx/\r\n"
"/DZrtenNLQNiTrM9AM+vdqBpVoNq0qjU51Bx5rU2BXcFbXvI5MT9TNUhXwIDAQAB\r\n"
"o00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBRxoQBzckAvVHZeM/xSj7zx3WtGITAf\r\n"
"BgNVHSMEGDAWgBS0WuSls97SUva51aaVD+s+vMf9/zANBgkqhkiG9w0BAQUFAAOC\r\n"
"AQEAAn86isAM8X+mVwJqeItt6E9slhEQbAofyk+diH1Lh8Y9iLlWQSKbw/UXYjx5\r\n"
"LLPZcniovxIcARC/BjyZR9g3UwTHNGNm+rwrqa15viuNOFBchykX/Orsk02EH7NR\r\n"
"Alw5WLPorYjED6cdVQgBl9ot93HdJogRiXCxErM7NC8/eP511mjq+uLDjLKH8ZPQ\r\n"
"8I4ekHJnroLsDkIwXKGIsvIBHQy2ac/NwHLCQOK6mfum1pRx52V4Utu5dLLjD5bM\r\n"
"xOBC7KU4xZKuMXXZM6/93Yb51K/J4ahf1TxJlTWXtnzDr9saEYdNy2SKY/6ZiDNH\r\n"
"D+stpAKiQLAWaAusIWKYEyw9MQ==\r\n"
"-----END CERTIFICATE-----\r\n";

const char mbedtls_test_cli_key_rsa[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIIEpAIBAAKCAQEAyHTEzLn5tXnpRdkUYLB9u5Pyax6fM60Nj4o8VmXl3ETZzGaF\r\n"
"B9X4J7BKNdBjngpuG7fa8H6r7gwQk4ZJGDTzqCrSV/Uu1C93KYRhTYJQj6eVSHD1\r\n"
"bk2y1RPD0hrt5kPqQhTrdOrA7R/UV06p86jt0uDBMHEwMjDV0/YI0FZPRo7yX/k9\r\n"
"Z5GIMC5Cst99++UMd//sMcB4j7/Cf8qtbCHWjdmLao5v4Jv4EFbMs44TFeY0BGbH\r\n"
"7vk2DmqV9gmaBmf0ZXH4yqSxJeD+PIs1BGe64E92hfx//DZrtenNLQNiTrM9AM+v\r\n"
"dqBpVoNq0qjU51Bx5rU2BXcFbXvI5MT9TNUhXwIDAQABAoIBAGdNtfYDiap6bzst\r\n"
"yhCiI8m9TtrhZw4MisaEaN/ll3XSjaOG2dvV6xMZCMV+5TeXDHOAZnY18Yi18vzz\r\n"
"4Ut2TnNFzizCECYNaA2fST3WgInnxUkV3YXAyP6CNxJaCmv2aA0yFr2kFVSeaKGt\r\n"
"ymvljNp2NVkvm7Th8fBQBO7I7AXhz43k0mR7XmPgewe8ApZOG3hstkOaMvbWAvWA\r\n"
"zCZupdDjZYjOJqlA4eEA4H8/w7F83r5CugeBE8LgEREjLPiyejrU5H1fubEY+h0d\r\n"
"l5HZBJ68ybTXfQ5U9o/QKA3dd0toBEhhdRUDGzWtjvwkEQfqF1reGWj/tod/gCpf\r\n"
"DFi6X0ECgYEA4wOv/pjSC3ty6TuOvKX2rOUiBrLXXv2JSxZnMoMiWI5ipLQt+RYT\r\n"
"VPafL/m7Dn6MbwjayOkcZhBwk5CNz5A6Q4lJ64Mq/lqHznRCQQ2Mc1G8eyDF/fYL\r\n"
"Ze2pLvwP9VD5jTc2miDfw+MnvJhywRRLcemDFP8k4hQVtm8PMp3ZmNECgYEA4gz7\r\n"
"wzObR4gn8ibe617uQPZjWzUj9dUHYd+in1gwBCIrtNnaRn9I9U/Q6tegRYpii4ys\r\n"
"c176NmU+umy6XmuSKV5qD9bSpZWG2nLFnslrN15Lm3fhZxoeMNhBaEDTnLT26yoi\r\n"
"33gp0mSSWy94ZEqipms+ULF6sY1ZtFW6tpGFoy8CgYAQHhnnvJflIs2ky4q10B60\r\n"
"ZcxFp3rtDpkp0JxhFLhiizFrujMtZSjYNm5U7KkgPVHhLELEUvCmOnKTt4ap/vZ0\r\n"
"BxJNe1GZH3pW6SAvGDQpl9sG7uu/vTFP+lCxukmzxB0DrrDcvorEkKMom7ZCCRvW\r\n"
"KZsZ6YeH2Z81BauRj218kQKBgQCUV/DgKP2985xDTT79N08jUo3hTP5MVYCCuj/+\r\n"
"UeEw1TvZcx3LJby7P6Xad6a1/BqveaGyFKIfEFIaBUBItk801sDDpDaYc4gL00Xc\r\n"
"7lFuBHOZkxJYlss5QrGpuOEl9ZwUt5IrFLBdYaKqNHzNVC1pCPfb/JyH6Dr2HUxq\r\n"
"gxUwAQKBgQCcU6G2L8AG9d9c0UpOyL1tMvFe5Ttw0KjlQVdsh1MP6yigYo9DYuwu\r\n"
"bHFVW2r0dBTqegP2/KTOxKzaHfC1qf0RGDsUoJCNJrd1cwoCLG8P2EF4w3OBrKqv\r\n"
"8u4ytY0F+Vlanj5lm3TaoHSVF1+NWPyOTiwevIECGKwSxvlki4fDAA==\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

const size_t mbedtls_test_ca_crt_rsa_len  = sizeof( mbedtls_test_ca_crt_rsa );
const size_t mbedtls_test_ca_key_rsa_len  = sizeof( mbedtls_test_ca_key_rsa );
const size_t mbedtls_test_ca_pwd_rsa_len  = sizeof( mbedtls_test_ca_pwd_rsa ) - 1;
const size_t mbedtls_test_srv_crt_rsa_len = sizeof( mbedtls_test_srv_crt_rsa );
const size_t mbedtls_test_srv_key_rsa_len = sizeof( mbedtls_test_srv_key_rsa );
const size_t mbedtls_test_cli_crt_rsa_len = sizeof( mbedtls_test_cli_crt_rsa );
const size_t mbedtls_test_cli_key_rsa_len = sizeof( mbedtls_test_cli_key_rsa );
#else
#define TEST_CA_CRT_RSA
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_PEM_PARSE_C)
/* Concatenation of all available CA certificates */
const char mbedtls_test_cas_pem[] = TEST_CA_CRT_RSA TEST_CA_CRT_EC;
const size_t mbedtls_test_cas_pem_len = sizeof( mbedtls_test_cas_pem );
#endif

/* List of all available CA certificates */
const char * mbedtls_test_cas[] = {
#if defined(MBEDTLS_RSA_C)
    mbedtls_test_ca_crt_rsa,
#endif
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_test_ca_crt_ec,
#endif
    NULL
};
const size_t mbedtls_test_cas_len[] = {
#if defined(MBEDTLS_RSA_C)
    sizeof( mbedtls_test_ca_crt_rsa ),
#endif
#if defined(MBEDTLS_ECDSA_C)
    sizeof( mbedtls_test_ca_crt_ec ),
#endif
    0
};

#if defined(MBEDTLS_RSA_C)
const char *mbedtls_test_ca_crt  = mbedtls_test_ca_crt_rsa;
const char *mbedtls_test_ca_key  = mbedtls_test_ca_key_rsa;
const char *mbedtls_test_ca_pwd  = mbedtls_test_ca_pwd_rsa;
const char *mbedtls_test_srv_crt = mbedtls_test_srv_crt_rsa;
const char *mbedtls_test_srv_key = mbedtls_test_srv_key_rsa;
const char *mbedtls_test_cli_crt = mbedtls_test_cli_crt_rsa;
const char *mbedtls_test_cli_key = mbedtls_test_cli_key_rsa;
const size_t mbedtls_test_ca_crt_len  = sizeof( mbedtls_test_ca_crt_rsa );
const size_t mbedtls_test_ca_key_len  = sizeof( mbedtls_test_ca_key_rsa );
const size_t mbedtls_test_ca_pwd_len  = sizeof( mbedtls_test_ca_pwd_rsa ) - 1;
const size_t mbedtls_test_srv_crt_len = sizeof( mbedtls_test_srv_crt_rsa );
const size_t mbedtls_test_srv_key_len = sizeof( mbedtls_test_srv_key_rsa );
const size_t mbedtls_test_cli_crt_len = sizeof( mbedtls_test_cli_crt_rsa );
const size_t mbedtls_test_cli_key_len = sizeof( mbedtls_test_cli_key_rsa );
#else /* ! MBEDTLS_RSA_C, so MBEDTLS_ECDSA_C */
const char *mbedtls_test_ca_crt  = mbedtls_test_ca_crt_ec;
const char *mbedtls_test_ca_key  = mbedtls_test_ca_key_ec;
const char *mbedtls_test_ca_pwd  = mbedtls_test_ca_pwd_ec;
const char *mbedtls_test_srv_crt = mbedtls_test_srv_crt_ec;
const char *mbedtls_test_srv_key = mbedtls_test_srv_key_ec;
const char *mbedtls_test_cli_crt = mbedtls_test_cli_crt_ec;
const char *mbedtls_test_cli_key = mbedtls_test_cli_key_ec;
const size_t mbedtls_test_ca_crt_len  = sizeof( mbedtls_test_ca_crt_ec );
const size_t mbedtls_test_ca_key_len  = sizeof( mbedtls_test_ca_key_ec );
const size_t mbedtls_test_ca_pwd_len  = sizeof( mbedtls_test_ca_pwd_ec ) - 1;
const size_t mbedtls_test_srv_crt_len = sizeof( mbedtls_test_srv_crt_ec );
const size_t mbedtls_test_srv_key_len = sizeof( mbedtls_test_srv_key_ec );
const size_t mbedtls_test_cli_crt_len = sizeof( mbedtls_test_cli_crt_ec );
const size_t mbedtls_test_cli_key_len = sizeof( mbedtls_test_cli_key_ec );
#endif /* MBEDTLS_RSA_C */

#endif /* MBEDTLS_CERTS_C */
