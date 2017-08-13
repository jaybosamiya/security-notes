# Some security related notes

I have started to write down notes on the security related videos I
watch (as a way of quick recall).

These might be more useful to beginners.

The order of notes here is _not_ in order of difficulty, but in
reverse chronological order of how I write them (i.e., latest first).

## License

[![CC BY-NC-SA 4.0](https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png)](http://creativecommons.org/licenses/by-nc-sa/4.0/)

This work is licensed under a [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-nc-sa/4.0/).

## The Notes Themselves

### Misc RE tips

Written on Aug 12 2017

> Influenced by Gynvael's CONFidence CTF 2017
> Livestreams [here](https://www.youtube.com/watch?v=kZtHy9GqQ8o)
> and [here](https://www.youtube.com/watch?v=W7s5CWaw6I4); and by his
> Google CTF Quals 2017
> Livestream [here](https://www.youtube.com/watch?v=KvyBn4Btv8E)

Sometimes, a challenge might implement a complicated task by
implementing a VM. It is not always necessary to completely reverse
engineer the VM and work on solving the challenge. Sometimes, you can
RE a little bit, and once you know what is going on, you can hook into
the VM, and get access to stuff that you need. Additionally, timing
based side-channel attacks become easier in VMs (mainly due to more
number of _"real"_ instructions executed.

Cryptographically interesting functions in binaries can be recognized
and quickly RE'd simply by looking for the constants and searching for
them online. For standard crypto functions, these constants are
sufficient to quickly guess at a function. Simpler crypto functions
can be recognized even more easily. If you see a lot of XORs and stuff
like that happening, and no easily identifiable constants, it is
probably hand-rolled crypto (and also possibly broken).

Sometimes, when using IDA with HexRays, the disassembly view might be
better than the decompilation view. This is especially true if you
notice that there seems to be a lot of complication going on in the
decompilation view, but you notice repetitive patterns in the
disassembly view. (You can quickly switch b/w the two using the space
bar). For example, if there is a (fixed size) big-integer library
implemented, then the decompilation view is terrible, but the
disassembly view is easy to understand stuff (and easily recognizable
due to the repetitive "with-carry" instructions such as
`adc`). Additionally, when analyzing like this, using the "Group
Nodes" feature in IDA's graph view is extremely useful to quickly
reduce the complexity of your graph, as you understand what each node
does.

For weird architectures, having a good emulator is extremely
useful. Especially, an emulator that can give you a dump of the memory
can be used to quickly figure out what is going on, and recognize
interesting portions, once you have the memory out of the
emulator. Additionally, using an emulator implemented in a comfortable
language (such as Python), means that you could run things exactly how
you like. For example, if there is some interesting part of the code
you might wish to run multiple times (for example, to brute force or
something), then using the emulator, you can quickly code up something
that does only that part of the code, rather than having to run the
complete program.

Being lazy is good, when REing. Do NOT waste time reverse engineering
everything, but spend enough time doing recon (even in an RE
challenge!), so as to be able to reduce the time spent on actually
doing the more difficult task of REing. What recon, in such a
situation means, is to just take quick looks at different functions,
without spending too much time on analyzing each function
thoroughly. You just quickly gauge what the function might be about
(for example "looks like a crypto thing", or "looks like a memory
management thing", etc.)

For unknown hardware or architecture, spend enough time looking it up
on Google, you might get lucky with a bunch of useful tools or
documents that might help you build tools quicker. Often times, you'll
find toy emulator etc implementations that might be useful as a quick
point to start off from. Alternatively, you might get some interesting
info (such as how bitmaps are stored, or how strings are stored, or
something) with which you can write a quick "fix" script, and then use
normal tools to see if interesting stuff is there.

Gimp (the image manipulation tool), has a very cool open/load
functionality to see raw pixel data. You can use this to quickly look
for assets or repetitive structures in raw binary data. Do spend time
messing around with the settings to see if more info can be gleaned
from it.

### Analysis for RE and Pwning tasks in CTFs

Written on Jul 2 2017

> Influenced by a discussion with [@p4n74](https://github.com/p4n74/)
> and [@h3rcul35](https://github.com/aazimcr) on
> the [InfoSecIITR](https://github.com/InfoSecIITR/) #bin chat. We
> were discussing on how sometimes beginners struggle to start with a
> larger challenge binary, especially when it is stripped.

To either solve the RE challenge, or to be able to pwn it, one must
first analyze the given binary, in order to be able to effectively
exploit it. Since the binary might possibly be stripped etc (found
using `file`) one must know where to begin analysis, to get a foothold
to build up from.

There's a few styles of analysis, when looking for vulnerabilities in
binaries (and from what I have gathered, different CTF teams have
different preferences):

1. Static Analysis

 1.1. Transpiling complete code to C

  This kind of analysis is sort of rare, but is quite useful for
  smaller binaries. The idea is to go in an reverse engineer the
  entirety of the code. Each and every function is opened in IDA
  (using the decompiler view), and renaming (shortcut: n) and retyping
  (shortcut: y) are used to quickly make the decompiled code much more
  readable. Then, all the code is copied/exported into a separate .c
  file, which can be compiled to get an equivalent (but not same)
  binary to the original. Then, source code level analysis can be
  done, to find vulns etc. Once the point of vulnerability is found,
  then the exploit is built on the original binary, by following along
  in the nicely decompiled source in IDA, side by side with the
  disassembly view (use Tab to quickly switch between the two; and use
  Space to switch quickly between Graph and Text view for
  disassembly).

 1.2. Minimal analysis of decompilation

  This is done quite often, since most of the binary is relatively
  useless (from the attacker's perspective). You only need to analyze
  the functions that are suspicious or might lead you to the vuln. To
  do this, there are some approaches to start off:

  1.2.1. Start from main

   Now usually, for a stripped binary, even main is not labelled (IDA
   6.9 onwards does mark it for you though), but over time, you learn
   to recognize how to reach the main from the entry point (where IDA
   opens at by default). You jump to that and start analyzing from
   there.

  1.2.2. Find relevant strings

   Sometimes, you know some specific strings that might be outputted
   etc, that you know might be useful (for example "Congratulations,
   your flag is %s" for an RE challenge). You can jump to Strings View
   (shortcut: Shift+F12), find the string, and work backwards using
   XRefs (shortcut: x). The XRefs let you find the path of functions
   to that string, by using XRefs on all functions in that chain,
   until you reach main (or some point that you know).

  1.2.3. From some random function

   Sometimes, not specific string might be useful, and you don't want
   to start from main. So instead, you quickly flip through the whole
   functions list, looking for functions that look suspicious (such as
   having lots of constants, or lots of xors, etc) or call important
   functions (XRefs of malloc, free, etc), and you start off from
   there, and go both forwards (following functions it calls) and
   backwards (XRefs of the function)

 1.3. Pure disassembly analysis

  Sometimes, you cannot use the decompilation view (because of weird
  architecture, or anti-decompilation techniques, or hand written
  assembly, or decompilation looking too unnecessarily complex). In
  that case, it is perfectly valid to look purely at the disassembly
  view. It is extremely useful (for new architectures) to turn on Auto
  Comments, which shows a comment explaining each
  instruction. Additionally, the node colorization and group nodes
  functionalities are immensely helpful. Even if you don't use any of
  these, regularly marking comments in the disassembly helps a lot. If
  I am personally doing this, I prefer writing down Python-like
  comments, so that I can quickly then transpile in manually into
  Python (especially useful for RE challenges, where you might have to
  use Z3 etc).

 1.4. Using platforms like BAP, etc.

  This kind of analysis is (semi-)automated, and is usually more
  useful for much larger software, and is rarely directly used in
  CTFs.

2. Fuzzing

 Fuzzing can be an effective technique to quickly get to the vuln,
 without having to actually understand it initially. By using a
 fuzzer, one can get a lot of low-hanging-fruit style of vulns, which
 then need to be analyzed and triaged to get to the actual vuln. See
 my notes
 on
 [basics of fuzzing](https://github.com/jaybosamiya/security-notes#basics-of-fuzzing) and
 [genetic fuzzing](https://github.com/jaybosamiya/security-notes#genetic-fuzzing) for
 more info.

3. Dynamic Analysis

 Dynamic Analysis can be used after finding a vuln using static
 analysis, to help build exploits quickly. Alternatively, it can be
 used to find the vuln itself. Usually, one starts up the executable
 inside a debugger, and tries to go along code paths that trigger the
 bug. By placing breakpoints at the right locations, and analyzing the
 state of the registers/heap/stack/etc, one can get a good idea of
 what is going on.  One can also use debuggers to quickly identify
 interesting functions. This can be done, for example, by setting
 temporary breakpoints on all functions initially; then proceeding to
 do 2 walks - one through all uninteresting code paths; and one
 through only a single interesting path. The first walk trips all the
 uninteresting functions and disables those breakpoints, thereby
 leaving the interesting ones showing up as breakpoints during the
 second walk.

My personal style for analysis, is to start with static analysis,
usually from main (or for non-console based applications, from
strings), and work towards quickly finding a function that looks
odd. I then spend time and branch out forwards and backwards from
here, regularly writing down comments, and continuously renaming and
retyping variables to improve the decompilation. Like others, I do use
names like Apple,Banana,Carrot,etc for seemingly useful, but as of yet
unknown functions/variables/etc, to make it easier to analyze (keeping
track of func_123456 style of names is too difficult for me). I also
regularly use the Structures view in IDA to define structures (and
enums) to make the decompilation even nicer. Once I find the vuln, I
usually move to writing a script with pwntools (and use that to call a
`gdb.attach()`). This way, I can get a lot of control over what is
going on. Inside gdb, I usually use plain gdb, though I have added a
command `peda` that loads peda instantly if needed.

My style is definitely evolving though, as I have gotten more
comfortable with my tools, and also with custom tools I have written
to speed things up. I would be happy to hear of other analysis styles,
as well as possible changes to my style that might help me get
faster. For any comments/criticisms/praise you have, as always, I can
be reached on Twitter [@jay\_f0xtr0t](http://twitter.com/@jay_f0xtr0t).

### Return Oriented Programming

Written on Jun 4 2017

> Influenced by [this](https://www.youtube.com/watch?v=iwRSFlZoSCM)
> awesome live stream by Gynvael Coldwind, where he discusses the
> basics of ROP, and gives a few tips and tricks

Return Oriented Programming (ROP) is one of the classic exploitation
techniques, that is used to bypass the NX (non executable memory)
protection. Microsoft has incorporated NX as DEP (data execution
prevention). Even Linux etc, have it effective, which means that with
this protection, you could no longer place shellcode onto heap/stack
and have it execute just by jumping to it. So now, to be able to
execute code, you jump into pre-existing code (main binary, or its
libraries -- libc, ldd etc on Linux; kernel32, ntdll etc on
Windows). ROP comes into existence by re-using fragments of this code
that is already there, and figuring out a way to combine those
fragments into doing what you want to do (which is of course, HACK THE
PLANET!!!).

Originally, ROP started with ret2libc, and then became more advanced
over time by using many more small pieces of code. Some might say that
ROP is now "dead", due to additional protections to mitigate it, but
it still can be exploited in a lot of scenarios (and definitely
necessary for many CTFs).

The most important part of ROP, is the gadgets. Gadgets are "usable
pieces of code for ROP". That usually means pieces of code that end
with a `ret` (but other kinds of gadgets might also be useful; such as
those ending with `pop eax; jmp eax` etc). We chain these gadgets
together to form the exploit, which is known as the _ROP chain_.

One of the most important assumptions of ROP is that you have control
over the stack (i.e., the stack pointer points to a buffer that you
control). If this is not true, then you will need to apply other
tricks (such as stack pivoting) to gain this control before building a
ROP chain.

How do you extract gadgets? Use downloadable tools (such
as [ropgadget](http://shell-storm.org/project/ROPgadget/)) or online
tool (such as [ropshell](http://ropshell.com/)) or write your own
tools (might be more useful for more difficult challenges sometimes,
since you can tweak it to the specific challenge if need
be). Basically, we just need the addresses that we can jump to for
these gadgets. This is where there might be a problem with ASLR etc
(in which case, you get a leak of the address, before moving on to
actually doing ROP).

So now, how do we use these gadgets to make a ropchain? We first look
for "basic gadgets". These are gadgets that can do _simple_ tasks for
us (such as `pop ecx; ret`, which can be used to load a value into ecx
by placing the gadget, followed by the value to be loaded, followed by
rest of chain, which is returned to after the value is loaded). The
most useful basic gadgets, are usually "set a register", "store
register value at address pointed to by register", etc.

We can build up from these primitive functions to gain higher level
functionality (similar to my post
titled [exploitation abstraction](#exploitation-abstraction)). For
example, using the set-register, and store-value-at-address gadgets,
we can come up with a "poke" function, that lets us set any specific
address with a specific value. Using this, we can build a
"poke-string" function that lets us store any particular string at any
particular location in memory. Now that we have poke-string, we are
basically almost done, since we can create any structures that we want
in memory, and can also call any functions we want with the parameters
we want (since we can set-register, and can place values on stack).

One of the most important reasons to build from these lower order
primitives to larger functions that do more complex things, is to
reduce the chances of making mistakes (which is common in ROP
otherwise).

There are more complex ideas, techniques, and tips for ROP, but that
is possibly a topic for a separate note, for a different time :)

PS: Gyn has a blogpost
on [Return-Oriented Exploitation](http://gynvael.coldwind.pl/?id=149)
that might be worth a read.

### Genetic Fuzzing

Written on May 27 2017; extended on May 29 2017

> Influenced by [this](https://www.youtube.com/watch?v=JhsHGms_7JQ)
> amazing live stream by Gynvael Coldwind, where he talks about the
> basic theory behind genetic fuzzing, and starts to build a basic
> genetic fuzzer.  He then proceeds to complete the implementation
> in [this](https://www.youtube.com/watch?v=HN_tI601jNU) live stream.

"Advanced" fuzzing (compared to a blind fuzzer, described in
my ["Basics of Fuzzing"](#basics-of-fuzzing) note). It also
modifies/mutates bytes etc, but it does it a little bit smarter than
the blind "dumb" fuzzer.

Why do we need a genetic fuzzer?

Some programs might be "nasty" towards dumb fuzzers, since it is
possible that a vulnerability might require a whole bunch of
conditions to be satisfied to be reached. In a dumb fuzzer, we have
very low probability of this happening since it doesn't have any idea
if it is making any progress or not. As a specific example, if we have
the code `if a: if b: if c: if d: crash!` (let's call it the CRASHER
code), then in this case we need 4 conditions to be satisfied to crash
the program. However, a dumb fuzzer might be unable to get past the
`a` condition, just because there is very low chance that all 4
mutations `a`, `b`, `c`, `d`, happen at same time. In fact, even if it
progresses by doing just `a`, the next mutation might go back to `!a`
just because it doesn't know anything about the program.

Wait, when does this kind of "bad case" program show up?

It is quite common in file format parsers, to take one example. To
reach some specific code paths, one might need to go past multiple
checks "this value must be this, and that value must be that, and some
other value must be something of something else" and so
on. Additionally, almost no real world software is "uncomplicated",
and most software has many many many possible code paths, some of
which can be accessed only after many things in the state get set up
correctly. Thereby, many of these programs' code paths are basically
inaccessible to dumb fuzzers. Additionally, sometimes, some paths
might be completely inaccessible (rather than just crazily improbable)
due to not enough mutations done whatsoever. If any of these paths
have bugs, a dumb fuzzer would never be able to find them.

So how do we do better than dumb fuzzers?

Consider the Control Flow Graph (CFG) of the above mentioned CRASHER
code. If by chance a dumb fuzzer suddenly got `a` correct, then too it
would not recognize that it reached a new node, but it would continue
ignoring this, discarding the sample. On the other hand, what AFL (and
other genetic or "smart" fuzzers) do, is they recognize this as a new
piece of information ("a newly reached path") and store this sample as
a new initial point into the corpus. What this means is that now the
fuzzer can start from the `a` block and move further. Of course,
sometimes, it might go back to the `!a` from the `a` sample, but most
of the time, it will not, and instead might be able to reach `b`
block. This again is a new node reached, so adds a new sample into the
corpus. This continues, allowing more and more possible paths to be
checked, and finally reaches the `crash!`.

Why does this work?

By adding mutated samples into the corpus, that explore the graph more
(i.e. reach parts not explored before), we can reach previously
unreachable areas, and can thus fuzz such areas. Since we can fuzz
such areas, we might be able to uncover bugs in those regions.

Why is it called genetic fuzzing?

This kind of "smart" fuzzing is kind of like genetic
algorithms. Mutation and crossover of specimens causes new
specimens. We keep specimens which are better suited to the conditions
which are tested. In this case, the condition is "how many nodes in
the graph did it reach?". The ones that traverse more can be
kept. This is not exactly like genetic algos, but is a variation
(since we keep all specimens that traverse unexplored territory, and
we don't do crossover) but is sufficiently similar to get the same
name. Basically, choice from pre-existing population, followed by
mutation, followed by fitness testing (whether it saw new areas), and
repeat.

Wait, so we just keep track of unreached nodes?

Nope, not really. AFL keeps track of edge traversals in the graph,
rather than nodes. Additionally, it doesn't just say "edge travelled
or not", it keeps track of how many times an edge was traversed. If an
edge is traversed 0, 1, 2, 4, 8, 16, ... times, it is considered as a
"new path" and leads to addition into the corpus. This is done because
looking at edges rather than nodes is a better way to distinguish
between application states, and using an exponentially increasing
count of the edge traversals gives more info (an edge traversed once
is quite different from traversed twice, but traversed 10 is not too
different from 11 times).

So, what and all do you need in a genetic fuzzer?

We need 2 things, the first part is called the tracer (or tracing
instrumentation). It basically tells you which instructions were
executed in the application. AFL does this in a simple way by jumping
in between the compilation stages. After the generation of the
assembly, but before assembling the program, it looks for basic blocks
(by looking for endings, by checking for jump/branch type of
instructions), and adds code to each block that marks the block/edge
as executed (probably into some shadow memory or something). If we
don't have source code, we can use other techniques for tracing (such
as pin, debugger, etc). Turns out, even ASAN can give coverage
information (see docs for this).

For the second part, we then use the coverage information given by the
tracer to keep track of new paths as they appear, and add those
generated samples into the corpus for random selection in the future.

There are multiple mechanisms to make the tracer. They can be software
based, or hardware based. For hardware based, there are, for example,
some Intel CPU features exist where given a buffer in memory, it
records information of all basic blocks traversed into that buffer. It
is a kernel feature, so the kernel has to support it and provide it as
an API (which Linux does). For software based, we can do it by adding
in code, or using a debugger (using temporary breakpoints, or through
single stepping), or use address sanitizer's tracing abilities, or use
hooks, or emulators, or a whole bunch of other ways.

Another way to differentiate the mechanisms is by either black-box
tracing (where you can only use the unmodified binary), or software
white-box tracing (where you have access to the source code, and
modify the code itself to add in tracing code).

AFL uses software instrumentation during compilation as the method for
tracing (or through QEMU emulation). Honggfuzz supports both software
and hardware based tracing methods. Other smart fuzzers might be
different. The one that Gyn builds uses the tracing/coverage provided
by address sanitizer (ASAN).

Some fuzzers use "speedhacks" (i.e. increase fuzzing speed) such as by
making a forkserver or other such ideas. Might be worth looking into
these at some point :)

### Basics of Fuzzing

Written on 20th April 2017

> Influenced by [this](https://www.youtube.com/watch?v=BrDujogxYSk)
> awesome live stream by Gynvael Coldwind, where he talks about what
> fuzzing is about, and also builds a basic fuzzer from scratch!

What is a fuzzer, in the first place? And why do we use it?

Consider that we have a library/program that takes input data. The
input may be structured in some way (say a PDF, or PNG, or XML, etc;
but it doesn't need to be any "standard" format). From a security
perspective, it is interesting if there is a security boundary between
the input and the process / library / program, and we can pass some
"special input" which causes unintended behaviour beyond that
boundary. A fuzzer is one such way to do this. It does this by
"mutating" things in the input (thereby _possibly_ corrupting it), in
order to lead to either a normal execution (including safely handled
errors) or a crash. This can happen due to edge case logic not being
handled well.

Crashing is the easiest way for error conditions. There might be
others as well. For example, using ASAN (address sanitizer) etc might
lead to detecting more things as well, which might be security
issues. For example, a single byte overflow of a buffer might not
cause a crash on its own, but by using ASAN, we might be able to catch
even this with a fuzzer.

Another possible use for a fuzzer is that inputs generated by fuzzing
one program can also possibly be used in another library/program and
see if there are differences. For example, some high-precision math
library errors were noticed like this. This doesn't usually lead to
security issues though, so we won't concentrate on this much.

How does a fuzzer work?

A fuzzer is basically a mutate-execute-repeat loop that explores the
state space of the application to try to "randomly" find states of a
crash / security vuln. It does _not_ find an exploit, just a vuln. The
main part of the fuzzer is the mutator itself. More on this later.

Outputs from a fuzzer?

In the fuzzer, a debugger is (sometimes) attached to the application
to get some kind of a report from the crash, to be able to analyze it
later as security vuln vs a benign (but possibly important) crash.

How to determine what areas of programs are best to fuzz first?

When fuzzing, we want to usually concentrate on a single piece or
small set of piece of the program. This is usually done mainly to
reduce the amount of execution to be done. Usually, we concentrate on
the parsing and processing only. Again, the security boundary matters
a _lot_ in deciding which parts matter to us.

Types of fuzzers?

Input samples given to the fuzzer are called the _corpus_. In
oldschool fuzzers (aka "blind"/"dumb" fuzzzers) there was a necessity
for a large corpus. Newer ones (aka "genetic" fuzzers, for example
AFL) do not necessarily need such a large corpus, since they explore
the state on their own.

How are fuzzers useful?

Fuzzers are mainly useful for "low hanging fruit". It won't find
complicated logic bugs, but it can find easy to find bugs (which are
actually sometimes easy to miss out during manual analysis).  While I
might say _input_ throughout this note, and usually refer to an _input
file_, it need not be just that. Fuzzers can handle inputs that might
be stdin or input file or network socket or many others. Without too
much loss of generality though, we can think of it as just a file for
now.

How to write a (basic) fuzzer?

Again, it just needs to be a mutate-run-repeat loop. We need to be
able to call the target often (`subprocess.Popen`). We also need to be
able to pass input into the program (eg: files) and detect crashes
(`SIGSEGV` etc cause exceptions which can be caught). Now, we just
have to write a mutator for the input file, and keep calling the
target on the mutated files.

Mutators? What?!?

There can be multiple possible mutators. Easy (i.e. simple to
implement) ones might be to mutate bits, mutate bytes, or mutate to
"magic" values. To increase chance of crash, instead of changing only
1 bit or something, we can change multiple (maybe some parameterized
percentage of them?). We can also (instead of random mutations),
change bytes/words/dwords/etc to some "magic" values. The magic values
might be `0`, `0xff`, `0xffff`, `0xffffffff`, `0x80000000` (32-bit
`INT_MIN`), `0x7fffffff` (32-bit `INT_MAX`) etc. Basically, pick ones
that are common to causing security issues (because they might trigger
some edge cases). We can write smarter mutators if we know more info
about the program (for example, for string based integers, we might
write something that changes an integer string to `"65536"` or `-1`
etc). Chunk based mutators might move pieces around (basically,
reorganizing input). Additive/appending mutators also work (for
example causing larger input into buffer). Truncators also might work
(for example, sometimes EOF might not be handled well). Basically, try
a whole bunch of creative ways of mangling things. The more experience
with respect to the program (and exploitation in general), the more
useful mutators might be possible.

But what is this "genetic" fuzzing?

That is probably a discussion for a later time. However, a couple of
links to some modern (open source) fuzzers
are [AFL](http://lcamtuf.coredump.cx/afl/)
and [honggfuzz](https://github.com/google/honggfuzz).

### Exploitation Abstraction

Written on 7th April 2017

> Influenced from a nice challenge
> in [PicoCTF 2017](http://2017.picoctf.com/) (name of challenge
> withheld, since the contest is still under way)

WARNING: This note might seem simple/obvious to some readers, but it
necessitates saying, since the layering wasn't crystal clear to me
until very recently.

Of course, when programming, all of us use abstractions, whether they
be classes and objects, or functions, or meta-functions, or
polymorphism, or monads, or functors, or all that jazz. However, can
we really have such a thing during exploitation? Obviously, we can
exploit mistakes that are made in implementing the aforementioned
abstractions, but here, I am talking about something different.

Across multiple CTFs, whenever I've written an exploit previously, it
has been an ad-hoc exploit script that drops a shell. I use the
amazing pwntools as a framework (for connecting to the service, and
converting things, and DynELF, etc), but that's about it. Each exploit
tended to be an ad-hoc way to work towards the goal of arbitrary code
execution. However, this current challenge, as well as thinking about
my previous note
on
["Advanced" Format String Exploitation](#advanced-format-string-exploitation),
made me realize that I could layer my exploits in a consistent way,
and move through different abstraction layers to finally reach the
requisite goal.

As an example, let us consider the vulnerability to be a logic error,
which lets us do a read/write of 4 bytes, somewhere in a small range
_after_ a buffer. We want to abuse this all the way to gaining code
execution, and finally the flag.

In this scenario, I would consider this abstraction to be a
`short-distance-write-anything` primitive. With this itself, obviously
we cannot do much. Nevertheless, I make a small Python function
`vuln(offset, val)`. However, since just after the buffer, there may
be some data/meta-data that might be useful, we can abuse this to
build both `read-anywhere` and `write-anything-anywhere`
primitives. This means, I write short Python functions that call the
previously defined `vuln()` function. These `get_mem(addr)` and
`set_mem(addr, val)` functions are made simply (in this current
example) simply by using the `vuln()` function to overwrite a pointer,
which can then be dereferenced elsewhere in the binary.

Now, after we have these `get_mem()` and `set_mem()` abstractions, I
build an anti-ASLR abstraction, by basically leaking 2 addresses from
the GOT through `get_mem()` and comparing against
a [libc database](https://github.com/niklasb/libc-database) (thanks
@niklasb for making the database). The offsets from these give me a
`libc_base` reliably, which allows me to replace any function in
the GOT with another from libc.

This has essentially given me control over EIP (the moment I can
"trigger" one of those functions _exactly_ when I want to). Now, all
that remains is for me to call the trigger with the right parameters.
So I set up the parameters as a separate abstraction, and then call
`trigger()` and I have shell access on the system.

TL;DR: One can build small exploitation primitives (which do not have
too much power), and by combining them and building a hierarchy of
stronger primitives, we can gain complete execution.

### "Advanced" Format String Exploitation

Written on 6th April 2017

> Influenced by [this](https://www.youtube.com/watch?v=xAdjDEwENCQ)
> awesome live stream by Gynvael Coldwind, where he talks about format
> string exploitation

Simple format string exploits:

You can use the `%p` to see what's on the stack. If the format string
itself is on the stack, then one can place an address (say _foo_) onto
the stack, and then seek to it using the position specifier `n$` (for
example, `AAAA %7$p` might return `AAAA 0x41414141`, if 7 is the
position on the stack). We can then use this to build a **read-where**
primitive, using the `%s` format specifier instead (for example, `AAAA
%7$s` would return the value at the address 0x41414141, continuing the
previous example). We can also use the `%n` format specifier to make
it into a **write-what-where** primitive. Usually instead, we use
`%hhn` (a glibc extension, iirc), which lets us write one byte at a
time.

We use the above primitives to initially beat ASLR (if any) and then
overwrite an entry in the GOT (say `exit()` or `fflush()` or ...) to
then raise it to an **arbitrary-eip-control** primitive, which
basically gives us **arbitrary-code-execution**.

Possible difficulties (that make it "advanced" exploitation):

If we have **partial ASLR**, then we can still use format strings and
beat it, but this becomes much harder if we only have one-shot exploit
(i.e., our exploit needs to run instantaneously, and the addresses are
randomized on each run, say). The way we would beat this is to use
addresses that are already in the memory, and overwrite them partially
(since ASLR affects only higher order bits). This way, we can gain
reliability during execution.

If we have a **read only .GOT** section, then the "standard" attack of
overwriting the GOT will not work. In this case, we look for
alternative areas that can be overwritten (preferably function
pointers). Some such areas are: `__malloc_hook` (see `man` page for
the same), `stdin`'s vtable pointer to `write` or `flush`, etc. In
such a scenario, having access to the libc sources is extremely
useful. As for overwriting the `__malloc_hook`, it works even if the
application doesn't call `malloc`, since it is calling `printf` (or
similar), and internally, if we pass a width specifier greater than
64k (say `%70000c`), then it will call malloc, and thus whatever
address was specified at the global variable `__malloc_hook`.

If we have our format string **buffer not on the stack**, then we can
still gain a **write-what-where** primitive, though it is a little
more complex. First off, we need to stop using the position specifiers
`n$`, since if this is used, then `printf` internally copies the stack
(which we will be modifying as we go along). Now, we find two pointers
that point _ahead_ into the stack itself, and use those to overwrite
the lower order bytes of two further _ahead_ pointing pointers on the
stack, so that they now point to `x+0` and `x+2` where `x` is some
location further _ahead_ on the stack. Using these two overwrites, we
are able to completely control the 4 bytes at `x`, and this becomes
our **where** in the primitive. Now we just have to ignore more
positions on the format string until we come to this point, and we
have a **write-what-where** primitive.

### Race Conditions & Exploiting Them

Written on 1st April 2017

> Influenced by [this](https://www.youtube.com/watch?v=kqdod-ATGVI)
> amazing live stream by Gynvael Coldwind, where he explains about race
> conditions

If a memory region (or file or any other resource) is accessed _twice_
with the assumption that it would remain same, but due to switching of
threads, we are able to change the value, we have a race condition.

Most common kind is a TOCTTOU (Time-of-check to Time-of-use), where a
variable (or file or any other resource) is first checked for some
value, and if a certain condition for it passes, then it is used. In
this case, we can attack it by continuously "spamming" this check in
one thread, and in another thread, continuously "flipping" it so that
due to randomness, we might be able to get a flip in the middle of the
"window-of-opportunity" which is the (short) timeframe between the
check and the use.

Usually the window-of-opportunity might be very small. We can use
multiple tricks in order to increase this window of opportunity by a
factor of 3x or even up to ~100x. We do this by controlling how the
value is being cached, or paged. If a value (let's say a `long int`)
is not aligned to a cache line, then 2 cache lines might need to be
accessed and this causes a delay for the same instruction to
execute. Alternatively, breaking alignment on a page, (i.e., placing
it across a page boundary) can cause a much larger time to
access. This might give us higher chance of the race condition being
triggered.

Smarter ways exist to improve this race condition situation (such as
clearing TLB etc, but these might not even be necessary sometimes).

Race conditions can be used, in (possibly) their extreme case, to get
ring0 code execution (which is "higher than root", since it is kernel
mode execution).

It is possible to find race conditions "automatically" by building
tools/plugins on top of architecture emulators. For further details,
http://vexillium.org/pub/005.html

### Types of "basic" heap exploits

Written on 31st Mar 2017

> Influenced by [this](https://www.youtube.com/watch?v=OwQk9Ti4mg4jjj)
> amazing live stream by Gynvael Coldwind, where he is experimenting
> on the heap

Use-after-free:

Let us say we have a bunch of pointers to a place in heap, and it is
freed without making sure that all of those pointers are updated. This
would leave a few dangling pointers into free'd space. This is
exploitable by usually making another allocation of different type
into the same region, such that you control different areas, and then
you can abuse this to gain (possibly) arbitrary code execution.

Double-free:

Free up a memory region, and the free it again. If you can do this,
you can take control by controlling the internal structures used by
malloc. This _can_ get complicated, compared to use-after-free, so
preferably use that one if possible.

Classic buffer overflow on the heap (heap-overflow):

If you can write beyond the allocated memory, then you can start to
write into the malloc's internal structures of the next malloc'd
block, and by controlling what internal values get overwritten, you
can usually gain a read-what-where primitive, that can usually be
abused to gain higher levels of access (usually arbitrary code
execution, via the `GOT PLT`, or `__fini_array__` or similar).
