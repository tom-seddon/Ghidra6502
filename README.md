# improved 6502 support for Ghidra

## new 6502 CPU description

Pick `6502`/`NMOS` from the language list.

This has slightly more traditional syntax, and some of the opcode
descriptions are improved, though I'm not sure this makes a huge
difference.

Illegal opcodes aren't supported yet.

## 65c02 instruction support

Pick `6502`/`CMOS` from the language list.

This supports the basic set of CMOS instructions only.

## new 6502 analyzer

This appears as `6502 Constant Reference Analyzer` in the analysis
options.

Does a better job of handling indexed addressing. The default analysis
has a bad habit of treating indexed addressing as a reference to the
indexed address, whereas for most 6502 code it should be treated as a
reference to the base address.

The `(zp,X)` addressing mode is still treated as a reference to
`zp+X`.

The 6502 analyzer 

# installation

The repo contains an Eclipse project. Presumably it's possible to make
it generate a `.jar` file for easy installation, but I don't know how,
so for now: import Eclipse project into your workspace, and run Ghidra
from inside Eclipse.

Ghidra should build the CPU descriptions automatically, but I've found
this a bit flaky. You can build them by running `ant` in the `data`
folder.

# known issues

* the new `6502 Constant Reference Analyzer` is active when the
  language is `6502`/`Default`, but it behaves as the `Basic Constant
  Reference Analyzer`. Need to fix this so that it just doesn't appear
  in the first place
* the new sleigh stuff produces totally unreadable C code - should
  probably dial back the accuracy a bit. I didn't realise the sleigh
  description would be used for this when writing it
* Ghidra is annoyingly keen on address 0 being invalid, which shows
  itself up at least by `STA (0),Y` disassembling as, e.g., `STA
  (0),Y=>DAT_0000` rather than `STA (DAT_0000),Y`
* probably loads of others that I'll discover in time...
