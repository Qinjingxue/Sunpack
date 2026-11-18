#include "Rar20Crypto.h"

extern "C" void sunpack_rar2_decrypt_prefix(const Byte *password, unsigned size, Byte *block)
{
    NCrypto::NRar2::CData cipher;
    cipher.SetPassword(password, size);
    cipher.DecryptBlock(block);
}
