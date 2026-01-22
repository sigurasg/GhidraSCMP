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
import java.nio.charset.Charset;

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
				return new LocalPcodeUseropLibrary(language, AbstractEmulatorTest.this);
			}
		};
		thread = emulator.newThread();
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
		writeRegister("AC", value);
	}

	protected void setSR(int value) {
		writeRegister("SR", value);
	}

	protected void setE(int value) {
		writeRegister("E", value);
	}

	protected void setSERIAL(int value) {
		writeRegister("SERIAL", value);
	}

	protected void setPC(int value) {
		writeRegister("PC", value);
		thread.setCounter(address(value));
	}

	protected void setP1(int value) {
		writeRegister("P1", value);
	}

	protected void setP2(int value) {
		writeRegister("P2", value);
	}

	protected void setP3(int value) {
		writeRegister("P3", value);
	}

	protected int getAC() {
		return readRegister("AC");
	}

	protected int getSR() {
		return readRegister("SR");
	}

	protected int getE() {
		return readRegister("E");
	}

	protected int getSERIAL() {
		return readRegister("SERIAL");
	}

	protected int getPC() {
		return readRegister("PC");
	}

	protected int getP1() {
		return readRegister("P1");
	}

	protected int getP2() {
		return readRegister("P2");
	}

	protected int getP3() {
		return readRegister("P3");
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

	private void writeRegister(String name, int value) {
		Register reg = language.getRegister(name);
		thread.getState()
				.setVar(language.getRegister(name), Utils.longToBytes(value,
					reg.getNumBytes(), language.isBigEndian()));
	}

	private int readRegister(String name) {
		Register reg = language.getRegister(name);

		return (int) Utils.bytesToLong(thread.getState().getVar(reg, Reason.INSPECT),
			reg.getNumBytes(), language.isBigEndian());

	}

	public class LocalPcodeUseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]> {
		private final static Charset UTF8 = Charset.forName("utf8");

		private final SleighLanguage language;
		private final AbstractEmulatorTest test;
		private final AddressSpace space;

		private LocalPcodeUseropLibrary(SleighLanguage language, AbstractEmulatorTest test) {
			this.language = language;
			this.test = test;
			this.space = language.getDefaultSpace();
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
}
