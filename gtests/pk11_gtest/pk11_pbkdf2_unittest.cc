/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <memory>
#include "nss.h"
#include "pk11pub.h"

#include "gtest/gtest.h"
#include "scoped_ptrs.h"

namespace nss_test {

static unsigned char* ToUcharPtr(std::string& str) {
  return const_cast<unsigned char*>(
      reinterpret_cast<const unsigned char*>(str.c_str()));
}

class Pkcs11Pbkdf2Test : public ::testing::Test {
 public:
  void Derive(std::vector<uint8_t>& derived, SECOidTag hash_alg) {
    // Shared between test vectors.
    const unsigned int iterations = 4096;
    std::string pass("passwordPASSWORDpassword");
    std::string salt("saltSALTsaltSALTsaltSALTsaltSALTsalt");

    // Derivation must succeed with the right values.
    EXPECT_TRUE(DeriveBytes(pass, salt, derived, hash_alg, iterations));

    // Derivation must fail when the password is bogus.
    std::string bogusPass("PasswordPASSWORDpassword");
    EXPECT_FALSE(DeriveBytes(bogusPass, salt, derived, hash_alg, iterations));

    // Derivation must fail when the salt is bogus.
    std::string bogusSalt("SaltSALTsaltSALTsaltSALTsaltSALTsalt");
    EXPECT_FALSE(DeriveBytes(pass, bogusSalt, derived, hash_alg, iterations));

    // Derivation must fail when using the wrong hash function.
    SECOidTag next_hash_alg = static_cast<SECOidTag>(hash_alg + 1);
    EXPECT_FALSE(DeriveBytes(pass, salt, derived, next_hash_alg, iterations));

    // Derivation must fail when using the wrong number of iterations.
    EXPECT_FALSE(DeriveBytes(pass, salt, derived, hash_alg, iterations + 1));
  }

 private:
  bool DeriveBytes(std::string& pass, std::string& salt,
                   std::vector<uint8_t>& derived, SECOidTag hash_alg,
                   unsigned int iterations) {
    SECItem passItem = {siBuffer, ToUcharPtr(pass),
                        static_cast<unsigned int>(pass.length())};
    SECItem saltItem = {siBuffer, ToUcharPtr(salt),
                        static_cast<unsigned int>(salt.length())};

    // Set up PBKDF2 params.
    ScopedSECAlgorithmID alg_id(
        PK11_CreatePBEV2AlgorithmID(SEC_OID_PKCS5_PBKDF2, hash_alg, hash_alg,
                                    derived.size(), iterations, &saltItem));

    // Derive.
    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    ScopedPK11SymKey symKey(
        PK11_PBEKeyGen(slot.get(), alg_id.get(), &passItem, false, nullptr));

    SECStatus rv = PK11_ExtractKeyValue(symKey.get());
    EXPECT_EQ(rv, SECSuccess);

    SECItem* keyData = PK11_GetKeyData(symKey.get());
    return !memcmp(&derived[0], keyData->data, keyData->len);
  }
};

}  // namespace nss_test
