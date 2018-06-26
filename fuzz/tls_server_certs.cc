/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <assert.h>
#include <stdint.h>

#include "ssl.h"

#include "cpputil.h"
#include "scoped_ptrs.h"
#include "tls_server_certs.h"

const uint8_t kP256ServerCert[] = {
    0x30, 0x82, 0x01, 0xcf, 0x30, 0x82, 0x01, 0x76, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x09, 0x00, 0xd9, 0x4c, 0x04, 0xda, 0x49, 0x7d, 0xbf, 0xeb,
    0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01, 0x30,
    0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
    0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31,
    0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e,
    0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69,
    0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x1e,
    0x17, 0x0d, 0x31, 0x34, 0x30, 0x34, 0x32, 0x33, 0x32, 0x33, 0x32, 0x31,
    0x35, 0x37, 0x5a, 0x17, 0x0d, 0x31, 0x34, 0x30, 0x35, 0x32, 0x33, 0x32,
    0x33, 0x32, 0x31, 0x35, 0x37, 0x5a, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30,
    0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65,
    0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65,
    0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74,
    0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xe6, 0x2b, 0x69, 0xe2,
    0xbf, 0x65, 0x9f, 0x97, 0xbe, 0x2f, 0x1e, 0x0d, 0x94, 0x8a, 0x4c, 0xd5,
    0x97, 0x6b, 0xb7, 0xa9, 0x1e, 0x0d, 0x46, 0xfb, 0xdd, 0xa9, 0xa9, 0x1e,
    0x9d, 0xdc, 0xba, 0x5a, 0x01, 0xe7, 0xd6, 0x97, 0xa8, 0x0a, 0x18, 0xf9,
    0xc3, 0xc4, 0xa3, 0x1e, 0x56, 0xe2, 0x7c, 0x83, 0x48, 0xdb, 0x16, 0x1a,
    0x1c, 0xf5, 0x1d, 0x7e, 0xf1, 0x94, 0x2d, 0x4b, 0xcf, 0x72, 0x22, 0xc1,
    0xa3, 0x50, 0x30, 0x4e, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
    0x16, 0x04, 0x14, 0xab, 0x84, 0xd2, 0xac, 0xab, 0x95, 0xf0, 0x82, 0x4e,
    0x16, 0x78, 0x07, 0x55, 0x57, 0x5f, 0xe4, 0x26, 0x8d, 0x82, 0xd1, 0x30,
    0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
    0xab, 0x84, 0xd2, 0xac, 0xab, 0x95, 0xf0, 0x82, 0x4e, 0x16, 0x78, 0x07,
    0x55, 0x57, 0x5f, 0xe4, 0x26, 0x8d, 0x82, 0xd1, 0x30, 0x0c, 0x06, 0x03,
    0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x09,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01, 0x03, 0x48, 0x00,
    0x30, 0x45, 0x02, 0x21, 0x00, 0xf2, 0xa0, 0x35, 0x5e, 0x51, 0x3a, 0x36,
    0xc3, 0x82, 0x79, 0x9b, 0xee, 0x27, 0x50, 0x85, 0x8e, 0x70, 0x06, 0x74,
    0x95, 0x57, 0xd2, 0x29, 0x74, 0x00, 0xf4, 0xbe, 0x15, 0x87, 0x5d, 0xc4,
    0x07, 0x02, 0x20, 0x7c, 0x1e, 0x79, 0x14, 0x6a, 0x21, 0x83, 0xf0, 0x7a,
    0x74, 0x68, 0x79, 0x5f, 0x14, 0x99, 0x9a, 0x68, 0xb4, 0xf1, 0xcb, 0x9e,
    0x15, 0x5e, 0xe6, 0x1f, 0x32, 0x52, 0x61, 0x5e, 0x75, 0xc9, 0x14};

const uint8_t kP256ServerKey[] = {
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    0x07, 0x0f, 0x08, 0x72, 0x7a, 0xd4, 0xa0, 0x4a, 0x9c, 0xdd, 0x59, 0xc9,
    0x4d, 0x89, 0x68, 0x77, 0x08, 0xb5, 0x6f, 0xc9, 0x5d, 0x30, 0x77, 0x0e,
    0xe8, 0xd1, 0xc9, 0xce, 0x0a, 0x8b, 0xb4, 0x6a, 0xa1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0xe6, 0x2b, 0x69, 0xe2, 0xbf, 0x65, 0x9f, 0x97, 0xbe, 0x2f,
    0x1e, 0x0d, 0x94, 0x8a, 0x4c, 0xd5, 0x97, 0x6b, 0xb7, 0xa9, 0x1e, 0x0d,
    0x46, 0xfb, 0xdd, 0xa9, 0xa9, 0x1e, 0x9d, 0xdc, 0xba, 0x5a, 0x01, 0xe7,
    0xd6, 0x97, 0xa8, 0x0a, 0x18, 0xf9, 0xc3, 0xc4, 0xa3, 0x1e, 0x56, 0xe2,
    0x7c, 0x83, 0x48, 0xdb, 0x16, 0x1a, 0x1c, 0xf5, 0x1d, 0x7e, 0xf1, 0x94,
    0x2d, 0x4b, 0xcf, 0x72, 0x22, 0xc1};

const uint8_t kRsaServerCert[] = {
    0x30, 0x82, 0x03, 0xb5, 0x30, 0x82, 0x02, 0x9d, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x09, 0x00, 0xb5, 0xb6, 0x22, 0xb9, 0x5a, 0x04, 0xa5, 0x21,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x0b, 0x05, 0x00, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
    0x55, 0x04, 0x08, 0x13, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74,
    0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a,
    0x13, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57,
    0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c,
    0x74, 0x64, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x37, 0x30, 0x39,
    0x30, 0x34, 0x33, 0x38, 0x30, 0x39, 0x5a, 0x17, 0x0d, 0x31, 0x36, 0x30,
    0x38, 0x30, 0x38, 0x30, 0x34, 0x33, 0x38, 0x30, 0x39, 0x5a, 0x30, 0x45,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41,
    0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a,
    0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21,
    0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x18, 0x49, 0x6e, 0x74,
    0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74,
    0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x82, 0x01,
    0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01,
    0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xba, 0x0b, 0xda, 0x84, 0x19, 0x12,
    0x01, 0x41, 0x75, 0x7c, 0x2e, 0x3d, 0xbd, 0xbd, 0x5b, 0xbe, 0x53, 0xeb,
    0x72, 0x5f, 0x34, 0x92, 0x8a, 0x75, 0x88, 0xba, 0x62, 0xb9, 0x8a, 0x33,
    0xe1, 0x0a, 0x6d, 0xc3, 0x2e, 0x7b, 0xf8, 0x45, 0xac, 0xb1, 0x90, 0x5c,
    0x1e, 0x9a, 0xd9, 0xe4, 0x19, 0x16, 0x7f, 0xa3, 0xde, 0x19, 0x9e, 0xc5,
    0xe4, 0x05, 0xf5, 0x3f, 0x22, 0x5b, 0x18, 0x76, 0x4b, 0xaa, 0xf3, 0x02,
    0xbd, 0x58, 0x8f, 0xea, 0x97, 0x78, 0x30, 0x5a, 0x31, 0xfe, 0x28, 0x04,
    0x48, 0x84, 0x84, 0x1c, 0x48, 0xb1, 0xa2, 0x25, 0xc2, 0xcd, 0xea, 0x41,
    0xae, 0x1b, 0x69, 0xe5, 0x44, 0x12, 0x8c, 0x70, 0xf8, 0x0f, 0x88, 0x4a,
    0xb6, 0x07, 0x4c, 0x81, 0x5c, 0x57, 0xf8, 0xb4, 0x6d, 0xc2, 0x05, 0xb7,
    0x9a, 0x7b, 0xbf, 0xbc, 0x1b, 0xbb, 0xaf, 0x3a, 0x6b, 0xfc, 0x34, 0xbc,
    0x8a, 0x8f, 0x7d, 0xa7, 0x79, 0x6a, 0x67, 0x50, 0x24, 0xcb, 0xe6, 0x8d,
    0x95, 0xc3, 0x23, 0xe8, 0xc6, 0x32, 0xf1, 0x4f, 0x98, 0x14, 0x47, 0xaf,
    0x6f, 0xf5, 0x74, 0x95, 0x16, 0x3d, 0xa2, 0xac, 0x26, 0x5b, 0xb0, 0x47,
    0x9d, 0x78, 0xa4, 0x9b, 0xfb, 0xe2, 0xea, 0xc8, 0xc8, 0x4b, 0x7e, 0x74,
    0x53, 0xcc, 0xdb, 0xfe, 0x64, 0x73, 0x61, 0xe2, 0x2c, 0xd9, 0x1e, 0xb9,
    0x2d, 0x47, 0x6e, 0x4c, 0xbe, 0x74, 0xf9, 0x43, 0x20, 0x6a, 0xdf, 0x68,
    0x71, 0xec, 0x08, 0xd9, 0xdb, 0xfc, 0x68, 0xef, 0x43, 0xa6, 0x1f, 0xbc,
    0x35, 0xd1, 0xad, 0x83, 0xc2, 0xc5, 0x63, 0x24, 0xd3, 0x1d, 0xc5, 0x31,
    0x26, 0x83, 0x2b, 0xd4, 0xf4, 0xce, 0x82, 0x79, 0x84, 0x4f, 0x5f, 0x56,
    0x24, 0x7e, 0x0f, 0xac, 0x5c, 0x24, 0xed, 0x91, 0x35, 0x40, 0x94, 0x10,
    0xd4, 0xbe, 0x22, 0x2a, 0x63, 0xde, 0x42, 0x2b, 0x2d, 0xb9, 0x02, 0x03,
    0x01, 0x00, 0x01, 0xa3, 0x81, 0xa7, 0x30, 0x81, 0xa4, 0x30, 0x1d, 0x06,
    0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xf9, 0x9b, 0xa5, 0x6f,
    0xcd, 0x88, 0xd5, 0x60, 0x71, 0xb7, 0xd2, 0x20, 0x44, 0xfa, 0x3d, 0x97,
    0x0e, 0x15, 0x04, 0xf2, 0x30, 0x75, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
    0x6e, 0x30, 0x6c, 0x80, 0x14, 0xf9, 0x9b, 0xa5, 0x6f, 0xcd, 0x88, 0xd5,
    0x60, 0x71, 0xb7, 0xd2, 0x20, 0x44, 0xfa, 0x3d, 0x97, 0x0e, 0x15, 0x04,
    0xf2, 0xa1, 0x49, 0xa4, 0x47, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d,
    0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x13, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74,
    0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79,
    0x20, 0x4c, 0x74, 0x64, 0x82, 0x09, 0x00, 0xb5, 0xb6, 0x22, 0xb9, 0x5a,
    0x04, 0xa5, 0x21, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05,
    0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01,
    0x00, 0x3e, 0xc9, 0x83, 0xaf, 0x12, 0x02, 0xb6, 0x16, 0x95, 0xca, 0x07,
    0x7d, 0x90, 0x01, 0xf7, 0x43, 0xe6, 0xca, 0xbb, 0x79, 0x1f, 0xa0, 0xfc,
    0x2d, 0x18, 0xbe, 0x5b, 0x64, 0x62, 0xd5, 0xf0, 0x4d, 0xc5, 0x11, 0x04,
    0x2e, 0x77, 0xb3, 0x58, 0x9d, 0xac, 0x72, 0x39, 0x78, 0x50, 0xc7, 0x2c,
    0x29, 0x8a, 0x78, 0x3e, 0x2f, 0x79, 0xd2, 0x05, 0x4d, 0xfb, 0xad, 0x88,
    0x82, 0xb2, 0x26, 0x70, 0x23, 0x6f, 0xb5, 0xbe, 0x48, 0xd4, 0x27, 0xf2,
    0xfc, 0xc3, 0x4d, 0xba, 0xbf, 0x5f, 0x7d, 0xab, 0x3a, 0x5f, 0x7d, 0xf8,
    0x0f, 0x48, 0x58, 0x54, 0x84, 0x13, 0x78, 0xfc, 0x85, 0x93, 0x7b, 0xa6,
    0x23, 0xed, 0xa6, 0x25, 0x0a, 0xed, 0x65, 0x9c, 0x8c, 0x3c, 0x82, 0x92,
    0x63, 0xfb, 0x18, 0x19, 0x01, 0xe1, 0x18, 0x65, 0xfa, 0xc0, 0x62, 0xbe,
    0x18, 0xef, 0xe8, 0x83, 0x43, 0xd0, 0x93, 0xf5, 0x6e, 0xe8, 0x3f, 0x86,
    0x53, 0x65, 0xd1, 0x9c, 0x35, 0x74, 0x61, 0x98, 0x35, 0x96, 0xc0, 0x2c,
    0x1d, 0xdd, 0xb5, 0x5e, 0xbc, 0x8a, 0xe9, 0xf0, 0xe6, 0x36, 0x41, 0x0c,
    0xc1, 0xb2, 0x16, 0xae, 0xdb, 0x38, 0xc5, 0xce, 0xec, 0x71, 0x1a, 0xc6,
    0x1d, 0x6c, 0xbe, 0x88, 0xc7, 0xfa, 0xff, 0xba, 0x7f, 0x02, 0x4f, 0xd2,
    0x22, 0x27, 0x0c, 0xe1, 0x74, 0xb0, 0x9a, 0x54, 0x3c, 0xa4, 0xfc, 0x40,
    0x64, 0xfa, 0xfe, 0x13, 0x62, 0xe8, 0x55, 0xdf, 0x69, 0x32, 0x95, 0x94,
    0xc2, 0x95, 0xb6, 0x51, 0xbb, 0x4e, 0xe7, 0x0b, 0x06, 0x4e, 0xb6, 0x39,
    0xb0, 0xee, 0x39, 0xb4, 0x53, 0x4d, 0xff, 0x2f, 0xa3, 0xb5, 0x48, 0x5e,
    0x07, 0x50, 0xb6, 0x8a, 0x33, 0x9b, 0x1b, 0xfb, 0x57, 0x10, 0xb6, 0xa2,
    0xc8, 0x27, 0x4c, 0xf9, 0x2f, 0xf0, 0x69, 0xeb, 0xaf, 0xd0, 0xc5, 0xed,
    0x23, 0x8c, 0x67, 0x9f, 0x50};

const uint8_t kRsaServerKey[] = {
    0x30, 0x82, 0x04, 0xbc, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
    0x04, 0xa6, 0x30, 0x82, 0x04, 0xa2, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01,
    0x01, 0x00, 0xba, 0x0b, 0xda, 0x84, 0x19, 0x12, 0x01, 0x41, 0x75, 0x7c,
    0x2e, 0x3d, 0xbd, 0xbd, 0x5b, 0xbe, 0x53, 0xeb, 0x72, 0x5f, 0x34, 0x92,
    0x8a, 0x75, 0x88, 0xba, 0x62, 0xb9, 0x8a, 0x33, 0xe1, 0x0a, 0x6d, 0xc3,
    0x2e, 0x7b, 0xf8, 0x45, 0xac, 0xb1, 0x90, 0x5c, 0x1e, 0x9a, 0xd9, 0xe4,
    0x19, 0x16, 0x7f, 0xa3, 0xde, 0x19, 0x9e, 0xc5, 0xe4, 0x05, 0xf5, 0x3f,
    0x22, 0x5b, 0x18, 0x76, 0x4b, 0xaa, 0xf3, 0x02, 0xbd, 0x58, 0x8f, 0xea,
    0x97, 0x78, 0x30, 0x5a, 0x31, 0xfe, 0x28, 0x04, 0x48, 0x84, 0x84, 0x1c,
    0x48, 0xb1, 0xa2, 0x25, 0xc2, 0xcd, 0xea, 0x41, 0xae, 0x1b, 0x69, 0xe5,
    0x44, 0x12, 0x8c, 0x70, 0xf8, 0x0f, 0x88, 0x4a, 0xb6, 0x07, 0x4c, 0x81,
    0x5c, 0x57, 0xf8, 0xb4, 0x6d, 0xc2, 0x05, 0xb7, 0x9a, 0x7b, 0xbf, 0xbc,
    0x1b, 0xbb, 0xaf, 0x3a, 0x6b, 0xfc, 0x34, 0xbc, 0x8a, 0x8f, 0x7d, 0xa7,
    0x79, 0x6a, 0x67, 0x50, 0x24, 0xcb, 0xe6, 0x8d, 0x95, 0xc3, 0x23, 0xe8,
    0xc6, 0x32, 0xf1, 0x4f, 0x98, 0x14, 0x47, 0xaf, 0x6f, 0xf5, 0x74, 0x95,
    0x16, 0x3d, 0xa2, 0xac, 0x26, 0x5b, 0xb0, 0x47, 0x9d, 0x78, 0xa4, 0x9b,
    0xfb, 0xe2, 0xea, 0xc8, 0xc8, 0x4b, 0x7e, 0x74, 0x53, 0xcc, 0xdb, 0xfe,
    0x64, 0x73, 0x61, 0xe2, 0x2c, 0xd9, 0x1e, 0xb9, 0x2d, 0x47, 0x6e, 0x4c,
    0xbe, 0x74, 0xf9, 0x43, 0x20, 0x6a, 0xdf, 0x68, 0x71, 0xec, 0x08, 0xd9,
    0xdb, 0xfc, 0x68, 0xef, 0x43, 0xa6, 0x1f, 0xbc, 0x35, 0xd1, 0xad, 0x83,
    0xc2, 0xc5, 0x63, 0x24, 0xd3, 0x1d, 0xc5, 0x31, 0x26, 0x83, 0x2b, 0xd4,
    0xf4, 0xce, 0x82, 0x79, 0x84, 0x4f, 0x5f, 0x56, 0x24, 0x7e, 0x0f, 0xac,
    0x5c, 0x24, 0xed, 0x91, 0x35, 0x40, 0x94, 0x10, 0xd4, 0xbe, 0x22, 0x2a,
    0x63, 0xde, 0x42, 0x2b, 0x2d, 0xb9, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02,
    0x82, 0x01, 0x00, 0x1c, 0xfb, 0xef, 0xc5, 0x18, 0xaa, 0xc7, 0x6b, 0x4d,
    0x44, 0x55, 0x67, 0xe5, 0x01, 0x75, 0x23, 0x87, 0xab, 0x6c, 0x9c, 0x0c,
    0x72, 0xb0, 0x03, 0x73, 0x93, 0xa6, 0x01, 0xc5, 0xd8, 0x23, 0x3d, 0x1e,
    0xb0, 0x83, 0xb3, 0x68, 0x90, 0x62, 0x41, 0x1f, 0x7e, 0x5a, 0x7e, 0x41,
    0x67, 0xd9, 0xc8, 0xb9, 0x85, 0xeb, 0xfa, 0x0d, 0xd4, 0x42, 0x9b, 0xf3,
    0x03, 0x2c, 0xf5, 0x08, 0x30, 0x95, 0xc5, 0x42, 0x2a, 0xb1, 0x18, 0xf5,
    0x02, 0xd5, 0x2a, 0x32, 0x4e, 0x3a, 0xef, 0x9f, 0x88, 0x5b, 0x4b, 0xd9,
    0xd1, 0x16, 0x3a, 0x26, 0x4a, 0xbf, 0xb8, 0x98, 0xc0, 0x36, 0xc1, 0xaa,
    0x93, 0xbf, 0x31, 0x2c, 0x94, 0x04, 0xf1, 0x56, 0x88, 0x5d, 0x27, 0x71,
    0xf1, 0xcd, 0x53, 0x1f, 0x39, 0xec, 0xc7, 0x87, 0x60, 0x7d, 0x3e, 0xbe,
    0x36, 0x2e, 0x13, 0xe5, 0x4e, 0xb2, 0xb8, 0x0d, 0xf7, 0x39, 0x96, 0xb0,
    0xe0, 0xd7, 0x58, 0x65, 0x8b, 0x44, 0x92, 0xa3, 0x62, 0xa8, 0xae, 0x95,
    0x61, 0xee, 0x26, 0x03, 0x1c, 0x55, 0x87, 0x9a, 0xac, 0x72, 0x28, 0x55,
    0x54, 0xc1, 0xa4, 0x05, 0x5a, 0x89, 0x36, 0x28, 0x84, 0xa2, 0xd7, 0x2d,
    0x9b, 0x59, 0x69, 0x87, 0xca, 0x30, 0xfb, 0xba, 0x3c, 0x82, 0x05, 0xce,
    0x5b, 0xdc, 0x66, 0xf9, 0x11, 0xc7, 0x3d, 0xc1, 0xfb, 0x12, 0x9c, 0x7b,
    0x86, 0x39, 0x1b, 0xfe, 0x17, 0xa5, 0x00, 0xd7, 0x18, 0x38, 0xaf, 0x79,
    0xd1, 0x6e, 0x7f, 0x47, 0xed, 0xb3, 0x59, 0x5f, 0x51, 0xea, 0x4c, 0x68,
    0xe9, 0x1f, 0xbf, 0x85, 0xf1, 0x85, 0x16, 0x60, 0xaf, 0x97, 0x89, 0x39,
    0xfa, 0x2f, 0x18, 0xd0, 0x89, 0x44, 0xbf, 0x77, 0xf3, 0x7b, 0x51, 0x34,
    0x2f, 0x0c, 0x9f, 0xdf, 0xbf, 0x62, 0xdc, 0x2f, 0xdc, 0x29, 0xcb, 0x9a,
    0x13, 0x98, 0x30, 0x47, 0x9e, 0x01, 0x01, 0x02, 0x81, 0x81, 0x00, 0xf1,
    0x96, 0xc3, 0x72, 0xf4, 0xcd, 0xfb, 0x1e, 0x08, 0x2e, 0x82, 0x51, 0xed,
    0xf1, 0x6f, 0x9c, 0xb8, 0xf3, 0x6d, 0xc4, 0xd8, 0xc5, 0x09, 0x62, 0x23,
    0x35, 0x1f, 0x5d, 0x4a, 0xf7, 0x6b, 0xd4, 0xe8, 0xb6, 0xf1, 0x9d, 0x40,
    0x63, 0xe0, 0x41, 0x3d, 0x2b, 0xfa, 0x50, 0x12, 0xa7, 0x4f, 0x93, 0xe9,
    0x38, 0x58, 0xea, 0xc5, 0xf3, 0x18, 0xfe, 0x3f, 0xf3, 0xa0, 0xa7, 0x48,
    0x69, 0x85, 0xf5, 0xa6, 0x18, 0x1e, 0x40, 0x75, 0xdc, 0x1e, 0xb0, 0x75,
    0xa5, 0x2f, 0x32, 0xa1, 0xa1, 0x7f, 0xa5, 0x32, 0x52, 0x37, 0x66, 0x1b,
    0xf2, 0xff, 0x64, 0x97, 0xf0, 0xa1, 0xd7, 0x27, 0x98, 0x5d, 0xa3, 0x55,
    0x1a, 0x67, 0x81, 0x2e, 0x41, 0xfd, 0x1f, 0xac, 0x08, 0x71, 0x4c, 0x43,
    0x31, 0xab, 0x35, 0x8b, 0xc5, 0x54, 0xce, 0xc8, 0x73, 0x85, 0xc9, 0x6e,
    0x08, 0xd1, 0xa8, 0x26, 0x3f, 0x70, 0x51, 0x02, 0x81, 0x81, 0x00, 0xc5,
    0x24, 0xea, 0x16, 0x9d, 0xcb, 0x2c, 0x7d, 0x60, 0xab, 0xb2, 0xe0, 0xd6,
    0x12, 0x87, 0x94, 0xef, 0x56, 0x61, 0xdf, 0xe6, 0xc3, 0xf7, 0xa1, 0x85,
    0xb3, 0x6f, 0x42, 0x74, 0x86, 0xc7, 0xa5, 0xc6, 0xf1, 0x85, 0x66, 0x23,
    0x03, 0xd4, 0x4c, 0xf3, 0x2c, 0x5b, 0x18, 0xfa, 0x29, 0x7b, 0x1c, 0xe8,
    0x19, 0xc5, 0x75, 0x1d, 0x7e, 0xa3, 0xf0, 0x4d, 0x6c, 0xd3, 0x17, 0xd8,
    0x64, 0x95, 0x76, 0xde, 0xbc, 0x68, 0x33, 0xd6, 0x63, 0xf6, 0x5e, 0x43,
    0x99, 0x90, 0x09, 0x40, 0xfc, 0x58, 0x5c, 0x87, 0x6e, 0xde, 0x1e, 0x0f,
    0xb2, 0x58, 0x59, 0x2d, 0xdd, 0xe9, 0xf8, 0x31, 0x07, 0x8d, 0xbb, 0x0b,
    0x0b, 0xf6, 0xaf, 0x93, 0x73, 0x38, 0x89, 0x98, 0xa6, 0xd4, 0x53, 0x0f,
    0x04, 0x93, 0x2c, 0xc0, 0xa4, 0x8b, 0xdb, 0x7c, 0xac, 0xa9, 0x7a, 0x18,
    0xff, 0x29, 0xe8, 0xaf, 0xe5, 0xb4, 0xe9, 0x02, 0x81, 0x80, 0x76, 0x1e,
    0xbb, 0xa3, 0x3a, 0x34, 0x78, 0x02, 0x60, 0x07, 0xb5, 0x6a, 0x2f, 0x87,
    0xab, 0x85, 0x9a, 0x1c, 0x53, 0x60, 0x3a, 0x88, 0x64, 0x25, 0x1a, 0x87,
    0xbf, 0xb5, 0x12, 0x91, 0x54, 0xa4, 0xbd, 0xbf, 0xac, 0xf4, 0xb0, 0xe5,
    0xe4, 0x60, 0xa1, 0x73, 0x1e, 0x29, 0x06, 0x65, 0xcd, 0x8f, 0xc9, 0x28,
    0xe6, 0xb8, 0xab, 0x5e, 0x47, 0xab, 0x10, 0x43, 0xa3, 0x1a, 0x07, 0x5a,
    0xa8, 0xc7, 0xc9, 0x94, 0xe3, 0x3d, 0xab, 0x22, 0x9b, 0xd2, 0xb5, 0x42,
    0xb5, 0x87, 0xf0, 0xe5, 0x10, 0x8f, 0x09, 0xc2, 0x8f, 0x19, 0x9a, 0xb2,
    0xbd, 0xd2, 0x46, 0x43, 0xbe, 0x2d, 0x7f, 0x4b, 0x8d, 0x04, 0xed, 0xf8,
    0x42, 0x01, 0x34, 0x47, 0xc9, 0x66, 0x31, 0xeb, 0xd2, 0xd1, 0x71, 0xcd,
    0x18, 0x23, 0xcf, 0x1a, 0x05, 0x74, 0x31, 0x27, 0xe2, 0x92, 0xf0, 0xfc,
    0xd8, 0xdd, 0x79, 0x0d, 0xed, 0x71, 0x02, 0x81, 0x80, 0x6e, 0xc6, 0x4c,
    0x46, 0xc3, 0x09, 0x7c, 0x09, 0x43, 0x3d, 0x97, 0x38, 0xa0, 0xf1, 0x2e,
    0x7f, 0xf0, 0x70, 0x30, 0x74, 0xd8, 0x3d, 0x3b, 0x32, 0xe6, 0x66, 0xa9,
    0xd8, 0xc4, 0x93, 0x4b, 0x31, 0x8a, 0x75, 0x01, 0xc9, 0x1f, 0x59, 0xb2,
    0x7c, 0x3e, 0x93, 0xa8, 0xe8, 0x83, 0x00, 0xb5, 0xed, 0xcb, 0x39, 0x57,
    0xeb, 0x73, 0xd4, 0x4a, 0x17, 0xe7, 0xd9, 0x83, 0x4f, 0xbd, 0xc6, 0xde,
    0xf9, 0x39, 0x34, 0xd2, 0xb4, 0x75, 0xfe, 0x1b, 0x5c, 0x62, 0x4d, 0xb2,
    0x52, 0x90, 0xd2, 0x7a, 0x70, 0x1b, 0xa5, 0x9f, 0x67, 0x72, 0xd8, 0x7a,
    0xae, 0x39, 0x88, 0x9d, 0x44, 0x59, 0x80, 0x6e, 0x12, 0x30, 0xa5, 0xdb,
    0x4a, 0x52, 0xe7, 0x06, 0x58, 0xc2, 0x8e, 0xd3, 0x75, 0x8c, 0x55, 0xbc,
    0xc1, 0x03, 0xca, 0x31, 0xcf, 0xf5, 0xe1, 0x2b, 0x25, 0xb1, 0x50, 0x07,
    0x63, 0x79, 0x1a, 0xf0, 0xa9, 0x02, 0x81, 0x80, 0x79, 0xf1, 0x03, 0x53,
    0xd5, 0x87, 0xc7, 0xde, 0x34, 0xba, 0xdb, 0xe9, 0x93, 0xda, 0x95, 0xea,
    0xa8, 0xb8, 0xcb, 0xaa, 0xfb, 0x03, 0xef, 0x8d, 0x95, 0x62, 0x71, 0x68,
    0x1d, 0x1f, 0x87, 0x04, 0xe9, 0xcd, 0xf2, 0xbc, 0xb4, 0x75, 0xd6, 0xb8,
    0x96, 0x0c, 0x0c, 0xd7, 0x4e, 0x8b, 0xe4, 0x58, 0x12, 0x83, 0xd0, 0xce,
    0x66, 0xf0, 0x12, 0x67, 0xe4, 0x06, 0x16, 0x4f, 0x90, 0x55, 0x0b, 0xfe,
    0x73, 0xbe, 0xc0, 0x49, 0x6a, 0x6e, 0x86, 0x60, 0x66, 0x6a, 0x66, 0x42,
    0xaf, 0x06, 0x57, 0xae, 0xaf, 0x57, 0x73, 0xdd, 0x91, 0x0c, 0xf9, 0x0a,
    0x16, 0xa9, 0xcf, 0xf4, 0xc5, 0x6f, 0xd3, 0xa8, 0x58, 0x28, 0xda, 0x74,
    0x9a, 0x84, 0x9d, 0x33, 0xc7, 0x48, 0x68, 0xce, 0xae, 0x4a, 0x8c, 0x2c,
    0xfe, 0xbf, 0xda, 0x0e, 0xce, 0x28, 0xb9, 0xdb, 0x9b, 0xcf, 0x6e, 0xa8,
    0xe4, 0x60, 0xca, 0x98};

void InstallServerCertificate(PRFileDesc* fd, const uint8_t* cert_data,
                              size_t cert_len, const uint8_t* key_data,
                              size_t key_len) {
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  assert(slot);

  SECItem certItem = {siBuffer, toUcharPtr(cert_data),
                      static_cast<unsigned int>(cert_len)};
  SECItem pkcs8Item = {siBuffer, toUcharPtr(key_data),
                       static_cast<unsigned int>(key_len)};

  // Import the certificate.
  static CERTCertDBHandle* certDB = CERT_GetDefaultCertDB();
  ScopedCERTCertificate cert(
      CERT_NewTempCertificate(certDB, &certItem, nullptr, false, true));
  assert(cert);

  // Import the private key.
  SECKEYPrivateKey* key = nullptr;
  SECStatus rv = PK11_ImportDERPrivateKeyInfoAndReturnKey(
      slot.get(), &pkcs8Item, nullptr, nullptr, false, false, KU_ALL, &key,
      nullptr);
  assert(rv == SECSuccess);

  // Adopt the private key to ensure it's freed.
  ScopedSECKEYPrivateKey privKey(key);

  // Configure server with the imported key and certificate.
  rv = SSL_ConfigServerCert(fd, cert.get(), privKey.get(), nullptr, 0);
  assert(rv == SECSuccess);
}

void InstallServerCertificates(PRFileDesc* fd) {
  // ECDSA P-256 certificate.
  InstallServerCertificate(fd, kP256ServerCert, sizeof(kP256ServerCert),
                           kP256ServerKey, sizeof(kP256ServerKey));

  // RSA-2048 certificate.
  InstallServerCertificate(fd, kRsaServerCert, sizeof(kRsaServerCert),
                           kRsaServerKey, sizeof(kRsaServerKey));
}
