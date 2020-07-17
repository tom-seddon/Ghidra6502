# Improved 6502 support for Ghidra

## New 6502 CPU description

Pick `6502`/`NMOS` from the language list.

This has slightly more traditional syntax, and some of the opcode
descriptions are improved, though I'm not sure this makes a huge
difference.

Illegal opcodes aren't supported yet.

## 65c02 instruction support

Pick `6502`/`CMOS` from the language list.

This supports the basic set of CMOS instructions only.

## New 6502 analyzer

This appears as `6502 Constant Reference Analyzer` in the analysis
options.

Does a better job of handling indexed addressing. The default analysis
has a bad habit of treating indexed addressing as a reference to the
indexed address, whereas for most 6502 code it should be treated as a
reference to the base address.

The `(zp,X)` addressing mode is still treated as a reference to
`zp+X`.

The 6502 analyzer 

# Build

Run the following Gradle task.
```
set GHIDRA_INSTALL_DIR=/YOUR_INSTALL_PATH/Ghidra
gradle buildExtension
```

A zip should be created in the `dist/` directory. (`ie: ghidra_9.1.2_PUBLIC_20200717_Ghidra6502.zip`)

# Installation

Copy the the zip file `ghidra_XXX_PUBLIC_XXX_Ghidra6502.zip` to your Ghidra extension directory: `/GHIDRA_DIR/Extensions/Ghidra`.

From Ghidra :
 1. Open the menu item `File > Install Extensions`
 2. Check the `Ghidra 6502` extension 
 3. Restart

# Other notes

Known issues: https://github.com/tom-seddon/Ghidra6502/issues
