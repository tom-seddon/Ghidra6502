/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra6502;

import java.lang.reflect.Field;

import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.plugin.processors.sleigh.ConstructState;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class M6502SymbolicPropogator extends SymbolicPropogator {
	private ConstructState[] _constructStates = new ConstructState[256];
	private boolean[] _gotConstructState = new boolean[256];

	public M6502SymbolicPropogator(Program program) {
		super(program);
	}

	@Override
	public void makeReference(VarnodeContext vContext, Instruction instruction, int opIndex, long knownSpaceID,
			long wordOffset, int size, RefType refType, int pcodeop, boolean knownReference, TaskMonitor monitor) {

		if (opIndex >= 0) {
			int opcode;
			try {
				opcode = instruction.getByte(0) & 0xff;
			} catch (MemoryAccessException ex) {
				return;
			}

			var basePrototype = instruction.getPrototype();
			if (basePrototype instanceof SleighInstructionPrototype) {
				var proto = (SleighInstructionPrototype) basePrototype;

				if (!_gotConstructState[opcode]) {
					try {
						// This is a bit ugly, but it appears to be impossible to get this info out any
						// other way.
						Field field = proto.getClass().getDeclaredField("rootState");
						field.setAccessible(true);
						_constructStates[opcode] = (ConstructState) field.get(proto);
						_gotConstructState[opcode] = true;
					} catch (NoSuchFieldException ex) {
						return;
					} catch (IllegalAccessException ex) {
						return;
					}
				}
			}

			final ConstructState c = _constructStates[opcode];
			if (c != null) {
				final Constructor ct = c.getConstructor();
				if (opIndex < ct.getNumOperands()) {
					OperandSymbol op;
					try {
						op = ct.getOperand(opIndex);
					} catch (ArrayIndexOutOfBoundsException ex) {
						throw ex;
					}

					final String mode = op.getName();
					try {
						switch (mode) {
						case "ZPX":
						case "ZPY":
						case "ZIY":
							// And maybe ZIX as well? I'm not sure.
							wordOffset = ((long) instruction.getByte(1)) & 0xff;
							break;

						case "ABX":
						case "ABY":
						case "AIX": {
							long lsb = ((long) instruction.getByte(1)) & 0xff;
							long msb = ((long) instruction.getByte(2)) & 0xff;
							wordOffset = lsb | msb << 8;
							break;
						}

						default:
							// Default Ghidra handling is fine in these cases.
							break;
						}
					} catch (MemoryAccessException ex) {
						return;
					}
				}
			}
		}

		if (wordOffset == 0) {
			// Work around the (slightly dubious) assumption made in
			// SymbolicPropogator.makeReference that references to address 0 aren't valid.
			// Presumably it should actually have some min value settings, like the constant
			// analyzer...
			//
			// But there's some sign extension handling that ends up turning address -65536
			// into address 0, so easy enough to work around.
			wordOffset = -65536;
		}

		super.makeReference(vContext, instruction, opIndex, knownSpaceID, wordOffset, size, refType, pcodeop,
				knownReference, monitor);
	}
}

class M6502ConstantPropagationContextEvaluator extends ConstantPropagationContextEvaluator {
	public M6502ConstantPropagationContextEvaluator(boolean trustWriteMemOption, long minStoreLoadRefAddress,
			long minSpeculativeRefAddress,long maxSpeculativeRefAddress) {
		super(trustWriteMemOption, minStoreLoadRefAddress, minSpeculativeRefAddress,maxSpeculativeRefAddress);
	}

	@Override
	public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop, Address address, int size,
			RefType refType) {

		return super.evaluateReference(context, instr, pcodeop, address, size, refType);

//		// unless this is a direct address copy, don't trust computed accesses below minStoreLoadOffset
//		//     External spaces can have low addresses... so don't check them
//		AddressSpace space = address.getAddressSpace();
//		if (space.isExternalSpace()) {
//			return true;
//		}
//
//		long maxAddrOffset = space.getMaxAddress().getAddressableWordOffset();
//		long wordOffset = address.getAddressableWordOffset();
//		boolean isKnownReference = !address.isConstantAddress();
//
//		if (pcodeop != PcodeOp.COPY && ((wordOffset >= 0 && wordOffset < this.minStoreLoadOffset) ||
//			(Math.abs(maxAddrOffset - wordOffset) < minStoreLoadOffset))) {
//			if (!isKnownReference) {
//				return false;
//			}
//			PcodeOp[] pcode = instr.getPcode();
//			if (pcode.length > 1) { // for simple pcode, assume it is a good location.
//				return false;
//			}
//		}
//		
//		return true;
	}
}

/**
 * TODO: Provide class-level documentation that describes what this analyzer
 * does.
 */
public class Ghidra6502Analyzer extends ConstantPropagationAnalyzer {
	private final static String PROCESSOR_NAME = "6502";

	public Ghidra6502Analyzer() {
		super(PROCESSOR_NAME);

		// This is a more sensible default for the 6502, but the option to change it
		// is still open.
		this.minStoreLoadRefAddress = 0;
	}

//	@Override
//	public boolean getDefaultEnablement(Program program) {
//
//		// TODO: Return true if analyzer should be enabled by default
//
//		return true;
//	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor wantedProcessor = Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME);

		// TODO: Examine 'program' to determine of this analyzer should analyze it.
		// Return true if it can.
		Language lang = program.getLanguage();
		Processor gotProcessor = lang.getProcessor();

		if (!gotProcessor.equals(wantedProcessor)) {
			return false;
		}

		return true;
	}

	@Override
	public AddressSetView analyzeLocation(final Program program, Address start, AddressSetView set,
			final TaskMonitor monitor) throws CancelledException {
		// copy of ConstantPropagationAnalyzer.analyzeLocation :( - sadly there doesn't
		// seem to be any way to just replace the SymbolicPropogator derived type.
		//
		// (Could override the relevant flowConstants and have it ignore the symEval
		// argument? But I'm not sure I fancy that...)

		monitor.checkCanceled();

		// get the function body
		if (program.getListing().getInstructionAt(start) == null) {
			return new AddressSet();
		}

		Address flowStart = start;
		AddressSetView flowSet = set;
		final Function func = program.getFunctionManager().getFunctionContaining(start);
		if (func != null) {
			AddressSetView body = func.getBody();
			if (set != null && body.getNumAddresses() > set.getNumAddresses()) {
				flowSet = body;
			}
			flowStart = func.getEntryPoint();
		}

		SymbolicPropogator symEval = new M6502SymbolicPropogator(program);
		symEval.setParamRefCheck(checkParamRefsOption);
		symEval.setReturnRefCheck(checkParamRefsOption);
		symEval.setStoredRefCheck(checkStoredRefsOption);

		// follow all flows building up context
		// use context to fill out addresses on certain instructions
		return this.flowConstants(program, flowStart, flowSet, symEval, monitor);
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart, AddressSetView flowSet,
			final SymbolicPropogator symEval, final TaskMonitor monitor) throws CancelledException {

		var eval = new M6502ConstantPropagationContextEvaluator(trustWriteMemOption, minStoreLoadRefAddress,
				minSpeculativeRefAddress,maxSpeculativeRefAddress);

		return symEval.flowConstants(flowStart, flowSet, eval, true, monitor);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// As per minStoreLoadRefAddress, but this field is set in a particularly
		// annoying fashion, and the only way to fix it seems to be to change the
		// option's default value.
		options.registerOption(MINSPECULATIVEREFADDRESS_OPTION_NAME, (long)0, null,
				MINSPECULATIVEREFADDRESS_OPTION_DESCRIPTION);
		
		super.registerOptions(options, program);

		this.minSpeculativeRefAddress = 0;
	}

//	@Override
//	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
//			throws CancelledException {
//
//		// TODO: Perform analysis when things get added to the 'program'. Return true if
//		// the analysis succeeded.
//
//		return false;
//	}
}
