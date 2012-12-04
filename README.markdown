# siphash-d

D implementation of SipHash.

# Install

shiphash-d is only one file. Please copy src/siphash.d onto your project. 

# Usage

Use siphash24 function.

```d
import siphash;

ubyte[16] k = cast(ubyte[])"To be|not to be!";
ubyte[] msg = cast(ubyte[])"that is the question.";
auto hashed = siphash24(k, msg);
```

# TODO

* Implement SipHash struct like std.digest hashes.

# Link

* [SipHash: a fast short-input PRF](https://www.131002.net/siphash/)

  official site

# Copyright

    Copyright (c) 2012- Masahiro Nakagawa

Distributed under the Boost Software License, Version 1.0.
