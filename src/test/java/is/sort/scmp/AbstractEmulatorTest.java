// Copyright 2025 Sigurdur Asgeirsson <siggi@sort.is>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package is.sort.scmp;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblyBuffer;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;

public abstract class AbstractEmulatorTest extends AbstractIntegrationTest {
	public AbstractEmulatorTest(String lang) {
		super(lang);

		emulator = new PcodeEmulator(language) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return new LocalPcodeUseropLibrary(language);
			}
		};
		thread = emulator.newThread();

		regAC = language.getRegister("AC");
		regSR = language.getRegister("SR");
		regE = language.getRegister("E");
		regSERIAL = language.getRegister("SERIAL");
		regPC = language.getRegister("PC");
		regP1 = language.getRegister("P1");
		regP2 = language.getRegister("P2");
		regP3 = language.getRegister("P3");
	}

	protected int assemble(int addr, String... code) {
		AddressSpace dyn = language.getDefaultSpace();
		Address entry = dyn.getAddress(addr);
		Assembler asm = Assemblers.getAssembler(language);
		AssemblyBuffer buffer = new AssemblyBuffer(asm, entry);
		for (String line : code) {
			try {
				buffer.assemble(line);
			}
			catch (Exception e) {
				fail("Failed to assemble line: " + line, e);
				return 0;
			}
		}

		byte[] bytes = buffer.getBytes();
		emulator.getSharedState().setVar(dyn, entry.getOffset(), bytes.length, true, bytes);

		return bytes.length;
	}

	protected void setAC(int value) {
		writeRegister(regAC, value);
	}

	protected void setSR(int value) {
		writeRegister(regSR, value);
	}

	protected void setE(int value) {
		writeRegister(regE, value);
	}

	protected void setSERIAL(int value) {
		writeRegister(regSERIAL, value);
	}

	protected void setPC(int value) {
		writeRegister(regPC, value);
		thread.setCounter(address(value));
	}

	protected void setP1(int value) {
		writeRegister(regP1, value);
	}

	protected void setP2(int value) {
		writeRegister(regP2, value);
	}

	protected void setP3(int value) {
		writeRegister(regP3, value);
	}

	protected int getAC() {
		return readRegister(regAC);
	}

	protected int getSR() {
		return readRegister(regSR);
	}

	protected int getE() {
		return readRegister(regE);
	}

	protected int getSERIAL() {
		return readRegister(regSERIAL);
	}

	protected int getPC() {
		return readRegister(regPC);
	}

	protected int getP1() {
		return readRegister(regP1);
	}

	protected int getP2() {
		return readRegister(regP2);
	}

	protected int getP3() {
		return readRegister(regP3);
	}

	protected void write(int addr, int... bytes) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		for (int v : bytes) {
			stream.write(v);
		}
		writeMemory(addr, stream.toByteArray());
	}

	protected byte[] read(int addr, int length) {
		return readMemory(addr, length);
	}

	protected int readByte(int addr) {
		return read(addr, 1)[0] & 0xFF;
	}

	protected void stepFrom(int addr, int numInstr) {
		setPC(addr);
		step(numInstr);
	}

	protected void stepFrom(int addr) {
		stepFrom(addr, 1);
	}

	protected void step(int numInstr) {
		for (int i = 0; i < numInstr; ++i) {
			thread.stepInstruction();
		}
	}

	protected void step() {
		step(1);
	}

	private void writeMemory(int addr, byte[] data) {
		AddressSpace dyn = language.getDefaultSpace();
		Address entry = dyn.getAddress(addr);

		emulator.getSharedState().setVar(dyn, entry.getOffset(), data.length, true, data);
	}

	private byte[] readMemory(int addr, int length) {
		AddressSpace dyn = language.getDefaultSpace();

		return emulator.getSharedState().getVar(dyn, addr, length, true, Reason.INSPECT);
	}

	private void writeRegister(Register reg, int value) {
		thread.getState()
				.setVar(reg, Utils.longToBytes(value,
					reg.getNumBytes(), language.isBigEndian()));
	}

	private int readRegister(Register reg) {
		return (int) Utils.bytesToLong(thread.getState().getVar(reg, Reason.INSPECT),
			reg.getNumBytes(), language.isBigEndian());

	}

	protected class LocalPcodeUseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]> {
		private final SleighLanguage language;

		private LocalPcodeUseropLibrary(SleighLanguage language) {
			this.language = language;
		}

		@PcodeUserop
		public byte[] addDispl(@OpExecutor PcodeExecutor<byte[]> executor, byte[] reg,
				byte[] displ) {
			long regValue = Utils.bytesToLong(reg, reg.length, language.isBigEndian());
			long displValue = Utils.bytesToLong(displ, displ.length, language.isBigEndian());
			long ret = (regValue & 0xF000) | ((regValue + displValue) & 0x0FFF);
			return Utils.longToBytes(ret, 2, language.isBigEndian());
		}
	};

	private PcodeEmulator emulator = null;
	private PcodeThread<byte[]> thread = null;

	private Register regAC = null;
	private Register regSR = null;
	private Register regE = null;
	private Register regSERIAL = null;
	private Register regPC = null;
	private Register regP1 = null;
	private Register regP2 = null;
	private Register regP3 = null;
}
