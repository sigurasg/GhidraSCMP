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

import db.Transaction;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractEmulatorTest extends AbstractIntegrationTest {
	public AbstractEmulatorTest(String lang) {
		super(lang);

		try (Transaction transaction = program.openTransaction("test")) {
			MemoryMapDB mem = program.getMemory();
			MemoryBlock block =
				mem.createUninitializedBlock("ram", address(0x0000), 0x10000, false);
			mem.convertToInitialized(block, (byte) 0x00);

			transaction.commit();
		}
		catch (Exception e) {
			fail("Failed to create RAM.", e);
		}
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
		Transaction transaction = program.openTransaction("test");
		Assembler asm = Assemblers.getAssembler(program);
		InstructionIterator assembled;
		try {
			assembled = asm.assemble(address(addr), code);
		}
		catch (Exception e) {
			fail("Assembly failed", e);
			transaction.abort();
			return 0;
		}
		transaction.commit();
		int len = 0;
		for (Instruction instr : assembled) {
			len += instr.getLength();
		}
		return len;
	}

	protected void setAC(int value) {
		emulator.writeRegister("AC", value);
	}

	protected void setSR(int value) {
		emulator.writeRegister("SR", value);
	}

	protected void setE(int value) {
		emulator.writeRegister("E", value);
	}

	protected void setSERIAL(int value) {
		emulator.writeRegister("SERIAL", value);
	}

	protected void setPC(int value) {
		emulator.writeRegister("PC", value);
	}

	protected void setP1(int value) {
		emulator.writeRegister("P1", value);
	}

	protected void setP2(int value) {
		emulator.writeRegister("P2", value);
	}

	protected void setP3(int value) {
		emulator.writeRegister("P3", value);
	}

	protected int getAC() {
		return emulator.readRegister("AC").intValue();
	}

	protected int getSR() {
		return emulator.readRegister("SR").intValue();
	}

	protected int getE() {
		return emulator.readRegister("E").intValue();
	}

	protected int getSERIAL() {
		return emulator.readRegister("SERIAL").intValue();
	}

	protected int getPC() {
		return emulator.readRegister("PC").intValue();
	}

	protected int getP1() {
		return emulator.readRegister("P1").intValue();
	}

	protected int getP2() {
		return emulator.readRegister("P2").intValue();
	}

	protected int getP3() {
		return emulator.readRegister("P3").intValue();
	}

	protected void write(int addr, int... bytes) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		for (int v : bytes) {
			stream.write(v);
		}
		emulator.writeMemory(address(addr), stream.toByteArray());
	}

	protected byte[] read(int addr, int length) {
		return emulator.readMemory(address(addr), length);
	}

	protected int readByte(int addr) {
		return read(addr, 1)[0] & 0xFF;
	}

	protected void stepFrom(int addr) {
		setPC(addr);
		step();
	}

	protected void step() {
		try {
			if (!emulator.step(TaskMonitor.DUMMY))
				fail("Step failed: " + emulator.getLastError());
		}
		catch (CancelledException e) {
			fail("Failed to step.", e);
		}
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

	@BeforeEach
	public void beforeEach() {
		emulator = new EmulatorHelper(program);
		emulator.setMemoryFaultHandler(new FailOnMemoryFault());
		emulator.registerCallOtherCallback("addDispl", new AddDisplBreakCallback());
	}

	@AfterEach
	public void afterEach() {
		emulator.dispose();
		emulator = null;
	}

	private EmulatorHelper emulator = null;
}