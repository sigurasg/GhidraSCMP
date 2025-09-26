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

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

import db.Transaction;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.framework.store.LockException;
import ghidra.pcode.emu.BytesPcodeThread;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.mem.MemoryConflictException;

class PcodeEmulatorTest {
	public PcodeEmulatorTest() {
		SleighLanguageProvider provider = SleighLanguageProvider.getSleighLanguageProvider();

		this.language = provider.getLanguage(new LanguageID("SCMP:BE:16:default"));
		ProgramDB program = null;
		try {
			program = new ProgramDB("test", language, language.getDefaultCompilerSpec(), this);

			try (Transaction transaction = program.openTransaction("test")) {
				program.getMemory()
						.createUninitializedBlock("ram", address(0x0000), 0x10000, false);
				transaction.commit();
			}
			catch (Exception e) {
				fail("Failed to create RAM.", e);
				return;
			}
		}
		catch (IOException e) {
			fail(e);
			return;
		}

		this.program = program;
		this.AC = program.getRegister("AC");
		this.SR = program.getRegister("SR");
		this.E = program.getRegister("E");
		this.PC = program.getRegister("PC");
		this.P1 = program.getRegister("P1");
		this.P2 = program.getRegister("P2");
		this.P3 = program.getRegister("P3");

		this.emulator = new PcodeEmulator(language);
		this.thread = (BytesPcodeThread)emulator.getThread("Thread 0", true);
		this.arithmetic = (BytesPcodeArithmetic)thread.getArithmetic();
	}

	protected void setAC(int value) {
		thread.getState().setVar(AC, arithmetic.fromConst(value, 1));
	}

	protected void setSR(int value) {
		thread.getState().setVar(SR, arithmetic.fromConst(value, 1));
	}

	protected void setE(int value) {
		thread.getState().setVar(E, arithmetic.fromConst(value, 1));
	}

	protected int getAC() {
		return (int) arithmetic.toLong(
			thread.getState().getVar(AC, PcodeExecutorStatePiece.Reason.INSPECT),
			PcodeArithmetic.Purpose.INSPECT);
	}

	protected int getSR() {
		return (int) arithmetic.toLong(
			thread.getState().getVar(SR, PcodeExecutorStatePiece.Reason.INSPECT),
			PcodeArithmetic.Purpose.INSPECT);
	}

	protected int getE() {
		return (int) arithmetic.toLong(
			thread.getState().getVar(E, PcodeExecutorStatePiece.Reason.INSPECT),
			PcodeArithmetic.Purpose.INSPECT);
	}

	protected int getPC() {
		return (int) arithmetic.toLong(
			thread.getState().getVar(PC, PcodeExecutorStatePiece.Reason.INSPECT),
			PcodeArithmetic.Purpose.INSPECT);
	}

	protected int getP1() {
		return (int) arithmetic.toLong(
			thread.getState().getVar(P1, PcodeExecutorStatePiece.Reason.INSPECT),
			PcodeArithmetic.Purpose.INSPECT);
	}

	protected int getP2() {
		return (int) arithmetic.toLong(
			thread.getState().getVar(P2, PcodeExecutorStatePiece.Reason.INSPECT),
			PcodeArithmetic.Purpose.INSPECT);
	}

	protected int getP3() {
		return (int) arithmetic.toLong(
			thread.getState().getVar(P3, PcodeExecutorStatePiece.Reason.INSPECT),
			PcodeArithmetic.Purpose.INSPECT);
	}

	@Test
	public void TestTest() {
		setAC(0x10);
		assertEquals(0x10, getAC());
	}

	protected Address address(int addr) {
		return language.getDefaultSpace().getAddress(addr);
	}

	private ProgramDB program;
	private Language language;
	private PcodeEmulator emulator;
	private BytesPcodeThread thread;
	private BytesPcodeArithmetic arithmetic;

	private Register AC;
	private Register SR;
	private Register E;
	private Register PC;
	private Register P1;
	private Register P2;
	private Register P3;
}