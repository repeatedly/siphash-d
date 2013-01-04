[![Build Status](https://travis-ci.org/repeatedly/siphash-d.png)](https://travis-ci.org/repeatedly/siphash-d)

# siphash-d

D implementation of SipHash.

# Install

shiphash-d is only one file. Please copy src/siphash.d onto your project. 

# Usage

## siphash24Of function.

siphash24Of is pre-defined function.

```d
import siphash;

ubyte[16] k = cast(ubyte[])"To be|not to be!";
ubyte[] msg = cast(ubyte[])"that is the question.";
auto hashed = siphash24Of(k, msg);
```

You can use siphash template for other SipRound pair.

```d
alias siphash!(1, 2).siphashOf siphash12Of;
```

## SipHash object

SipHash provides std.digest like API.

```d
import siphash;

ubyte[16] key = cast(ubyte[])"To be|not to be!";
auto sh = SipHash!(2, 4)(key);
sh.start();
sh.put(cast(ubyte[])"that is the question.");
auto hashed = sh.finish();
```

# Link

* [SipHash: a fast short-input PRF](https://www.131002.net/siphash/)

  official site

# Copyright

    Copyright (c) 2012- Masahiro Nakagawa

Distributed under the Boost Software License, Version 1.0.
