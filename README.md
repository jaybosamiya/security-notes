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
factor of 3x or even upto ~100x. We do this by controlling how the
value is being cached, or paged. If a value (let's say a `long int`)
is not alligned to a cache line, then 2 cache lines might need to be
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
