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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblyBuffer;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.utils.Utils;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;

public abstract class AbstractEmulatorTest extends AbstractIntegrationTest {
	public AbstractEmulatorTest(String lang) {
		super(lang);

		emulator = new PcodeEmulator(language);
		thread = emulator.newThread();
	}

	class FailOnMemoryFault implements MemoryFaultHandler {
		@Override
		public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) {
			return false;
		}

		@Override
		public boolean unknownAddress(Address address, boolean write) {
			return false;
		}
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

	private final class AddDisplBreakCallback extends BreakCallBack {
		@Override
		public boolean pcodeCallback(PcodeOpRaw op) {
			// Implements the addDispl segmentop for emulation.
			// For whatever reason the emulator doesn't heed
			// segmentop definitions from the pspec.
			MemoryState mem = emulate.getMemoryState();
			long ptr = mem.getValue(op.getInput(1));
			long displ = mem.getValue(op.getInput(2));

			mem.setValue(op.getOutput(), (ptr & 0xF000) | ((ptr + displ) & 0x0FFF));
			return true;
		}
	}

	void writeMemory(int addr, byte[] data) {
		AddressSpace dyn = language.getDefaultSpace();
		Address entry = dyn.getAddress(addr);

		emulator.getSharedState().setVar(dyn, entry.getOffset(), data.length, true, data);
	}

	byte[] readMemory(int addr, int length) {
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

		return (int)Utils.bytesToLong(thread.getState().getVar(reg, Reason.INSPECT),
				reg.getNumBytes(), language.isBigEndian());

	}

	@BeforeEach
	public void beforeEach() {
	}

	@AfterEach
	public void afterEach() {
	}

	private PcodeEmulator emulator = null;
	private PcodeThread<byte[]> thread = null;
}
