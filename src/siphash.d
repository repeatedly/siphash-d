// Written in the D programming language.

/**

$(BOOKTABLE ,
$(TR $(TH Category) $(TH Functions))
$(TR $(TDNW Template API) $(TD $(MYREF SipHash)))
$(TR $(TDNW Helpers) $(TD $(MYREF siphash24Of)))
)

 * SipHash: a fast short-input PRF
 *
 * Example:
 * -----
 * // Create key
 * ubyte[16] key = cast(ubyte[])"To be|not to be!";
 * // Compute hash with key and arbitrary message
 * ulong  hashed = siphash24Of(key, cast(ubyte[])"that is the question.");
 * assert(hashed == 17352353082512417190);
 * -----
 *
 * See_Also:
 *  $(LINK2 https://www.131002.net/siphash/, SipHash: a fast short-input PRF)
 *
 * Copyright: Copyright Masahiro Nakagawa 2012-.
 * License:   <a href="http://www.boost.org/LICENSE_1_0.txt">Boost License 1.0</a>.
 * Authors:   Masahiro Nakagawa
 */
module siphash;

import std.bitmanip : littleEndianToNative, nativeToLittleEndian;

/**
 * siphash template, which takes SipRound C and D parameters
 */
template siphash(size_t C, size_t D)
{
    /**
     * Computes SipHash hashes of arbitrary data.
     *
     * Params:
     *  key     = 16 byte key to hash
     *  message = an arbitrary message
     *
     * Returns:
     *  a 8 byte hash value.
     */
    @safe pure nothrow
    ulong siphashOf(in ubyte[16] key, in ubyte[] message)
    {
        return siphashOf(u8to64_le(key.ptr), u8to64_le(key.ptr, BlockSize), message);
    }

    /// ditto
    @safe pure nothrow
    ulong siphashOf(in ulong k0, in ulong k1, in ubyte[] message)
    {
        ulong v0 = k0 ^ 0x736f6d6570736575UL;
        ulong v1 = k1 ^ 0x646f72616e646f6dUL;
        ulong v2 = k0 ^ 0x6c7967656e657261UL;
        ulong v3 = k1 ^ 0x7465646279746573UL;

        size_t index;
        for (size_t blocks = message.length & ~7; index < blocks; index += BlockSize) {
            immutable mi = u8to64_le(message.ptr, index);
            v3 ^= mi;
            foreach (Unused; 0..C)
                mixin(SipRound);
            v0 ^= mi;
        }

        ulong tail = cast(ulong)(message.length & 0xff) << 56;
        switch (message.length % BlockSize) {
        case 7: tail |= cast(ulong)message[index + 6] << 48; goto case 6;
        case 6: tail |= cast(ulong)message[index + 5] << 40; goto case 5;
        case 5: tail |= cast(ulong)message[index + 4] << 32; goto case 4;
        case 4: tail |= cast(ulong)message[index + 3] << 24; goto case 3;
        case 3: tail |= cast(ulong)message[index + 2] << 16; goto case 2;
        case 2: tail |= cast(ulong)message[index + 1] <<  8; goto case 1;
        case 1: tail |= cast(ulong)message[index]; break;
        default:
            break;
        }

        v3 ^= tail;
        foreach (Unused; 0..C)
            mixin(SipRound);
        v0 ^= tail;

        v2 ^= 0xff;
        foreach (Unused; 0..D)
            mixin(SipRound);

        return v0 ^ v1 ^ v2 ^ v3;
    }
}

alias siphash!(2, 4).siphashOf siphash24Of;

/**
 * SipHash object implements std.digest like API for supporting streaming update.
 *
 * Example:
 * -----
 * ubyte[16] key = cast(ubyte[])"To be|not to be!";
 * auto sh = SipHash!(2, 4)(key);
 *
 * sh.start();
 * foreach (chunk; chunks(cast(ubyte[])"that is the question.", 2))
 *     sh.put(chunk);
 * auto hashed = sh.finish();
 * -----
 */
struct SipHash(size_t C, size_t D)
{
  private:
    immutable ulong k0, k1;
    ulong v0, v1, v2, v3;

    size_t processedLength;
    const(ubyte)[] message;


  public:
    @safe pure nothrow
    {
        /**
         * Constructs SipHash with 16 byte key.
         */
        this(in ubyte[16] key)
        {
            this(u8to64_le(key.ptr), u8to64_le(key.ptr, BlockSize));
        }

        /**
         * Constructs SipHash with two 8 byte key numbers.
         */
        this(in ulong key0, in ulong key1)
        {
            k0 = key0;
            k1 = key1;
        }

        /**
         * Used to initialize the SipHash.
         */
        void start()
        {
            this = SipHash!(C, D)(k0, k1);

            v0 = k0 ^ 0x736f6d6570736575UL;
            v1 = k1 ^ 0x646f72616e646f6dUL;
            v2 = k0 ^ 0x6c7967656e657261UL;
            v3 = k1 ^ 0x7465646279746573UL;
            processedLength = 0;
        }

        /**
         * Use this to feed the digest with data.
         * Also implements the $(XREF range, OutputRange) interface for $(D ubyte) and $(D const(ubyte)[]).
         */
        void put(scope const(ubyte)[] data...)
        {
            message ~= data;

            size_t index;
            for (size_t blocks = message.length & ~7; index < blocks;
                 index += BlockSize, processedLength += BlockSize) {
                immutable mi = u8to64_le(message.ptr, index);
                v3 ^= mi;
                foreach (Unused; 0..C)
                    mixin(SipRound);
                v0 ^= mi;
            }

            if (index != 0)
                message = message[index..$];
        }

        /**
         * Returns the finished SipHash hash as ubyte[8], not ulong.
         * This also calls $(LREF start) to reset the internal state.
         */
        ubyte[8] finish()
        {
            ulong tail = cast(ulong)((processedLength + message.length) & 0xff) << 56;
            switch (message.length % BlockSize) {
            case 7: tail |= cast(ulong)message[6] << 48; goto case 6;
            case 6: tail |= cast(ulong)message[5] << 40; goto case 5;
            case 5: tail |= cast(ulong)message[4] << 32; goto case 4;
            case 4: tail |= cast(ulong)message[3] << 24; goto case 3;
            case 3: tail |= cast(ulong)message[2] << 16; goto case 2;
            case 2: tail |= cast(ulong)message[1] <<  8; goto case 1;
            case 1: tail |= cast(ulong)message[0]; break;
            default:
                break;
            }

            v3 ^= tail;
            foreach (Unused; 0..C)
                mixin(SipRound);
            v0 ^= tail;

            v2 ^= 0xff;
            foreach (Unused; 0..D)
                mixin(SipRound);

            ubyte[8] result = nativeToLittleEndian(v0 ^ v1 ^ v2 ^ v3);

            start();

            return result;
        }
    }
}

private:

enum BlockSize = ulong.sizeof;

enum SipRound = "
    v0 += v1;
    v1  = rotl(v1, 13);
    v1 ^= v0;
    v0  = rotl(v0, 32);

    v2 += v3;
    v3  = rotl(v3, 16);
    v3 ^= v2;

    v2 += v1;
    v1  = rotl(v1, 17);
    v1 ^= v2;
    v2  = rotl(v2, 32);

    v0 += v3;
    v3  = rotl(v3, 21);
    v3 ^= v0;
";

@safe pure nothrow
ulong rotl(in ulong u, in uint s)
{
    return (u << s) | (u >> (64 - s));
}

@trusted pure nothrow
ulong u8to64_le(in ubyte* ptr, in size_t i = 0)
{
    return *cast(ulong*)(ptr + i);
}

unittest
{
    import std.conv;
    import std.range : chunks;

    /*
      SipHash-2-4 output with
      key = 00 01 02 ...
      and
      message = (empty string)
      message = 00 (1 byte)
      message = 00 01 (2 bytes)
      message = 00 01 02 (3 bytes)
      ...
      message = 00 01 02 ... 3e (63 bytes)
    */
    ulong[64] testVectors = [
        0x726fdb47dd0e0e31UL, 0x74f839c593dc67fdUL, 0x0d6c8009d9a94f5aUL, 0x85676696d7fb7e2dUL,
        0xcf2794e0277187b7UL, 0x18765564cd99a68dUL, 0xcbc9466e58fee3ceUL, 0xab0200f58b01d137UL,
        0x93f5f5799a932462UL, 0x9e0082df0ba9e4b0UL, 0x7a5dbbc594ddb9f3UL, 0xf4b32f46226bada7UL,
        0x751e8fbc860ee5fbUL, 0x14ea5627c0843d90UL, 0xf723ca908e7af2eeUL, 0xa129ca6149be45e5UL,
        0x3f2acc7f57c29bdbUL, 0x699ae9f52cbe4794UL, 0x4bc1b3f0968dd39cUL, 0xbb6dc91da77961bdUL,
        0xbed65cf21aa2ee98UL, 0xd0f2cbb02e3b67c7UL, 0x93536795e3a33e88UL, 0xa80c038ccd5ccec8UL,
        0xb8ad50c6f649af94UL, 0xbce192de8a85b8eaUL, 0x17d835b85bbb15f3UL, 0x2f2e6163076bcfadUL,
        0xde4daaaca71dc9a5UL, 0xa6a2506687956571UL, 0xad87a3535c49ef28UL, 0x32d892fad841c342UL,
        0x7127512f72f27cceUL, 0xa7f32346f95978e3UL, 0x12e0b01abb051238UL, 0x15e034d40fa197aeUL,
        0x314dffbe0815a3b4UL, 0x027990f029623981UL, 0xcadcd4e59ef40c4dUL, 0x9abfd8766a33735cUL,
        0x0e3ea96b5304a7d0UL, 0xad0c42d6fc585992UL, 0x187306c89bc215a9UL, 0xd4a60abcf3792b95UL,
        0xf935451de4f21df2UL, 0xa9538f0419755787UL, 0xdb9acddff56ca510UL, 0xd06c98cd5c0975ebUL,
        0xe612a3cb9ecba951UL, 0xc766e62cfcadaf96UL, 0xee64435a9752fe72UL, 0xa192d576b245165aUL,
        0x0a8787bf8ecb74b2UL, 0x81b3e73d20b49b6fUL, 0x7fa8220ba3b2eceaUL, 0x245731c13ca42499UL,
        0xb78dbfaf3a8d83bdUL, 0xea1ad565322a1a0bUL, 0x60e61c23a3795013UL, 0x6606d7e446282b93UL,
        0x6ca4ecb15c5f91e1UL, 0x9f626da15c9625f3UL, 0xe51b38608ef25f57UL, 0x958a324ceb064572UL
    ];

    ubyte[16] key;
    foreach (ubyte i; 0..16)
        key[i] = i;

    auto sh = SipHash!(2, 4)(key);
    ulong calcViaStreaming(ubyte[] message)
    {
        sh.start();
        foreach (chunk; chunks(message, 3))
            sh.put(chunk);
        return littleEndianToNative!ulong(sh.finish());
    }

    ubyte[] message;
    foreach (ubyte i; 0..64) {
        auto result = siphash24Of(key, message);
        assert(result == testVectors[i], "test vector failed for " ~ to!string(i));
        assert(calcViaStreaming(message) == testVectors[i],
               "test vector failed for " ~ to!string(i) ~ " in streaming");

        message ~= i;
    }
}
