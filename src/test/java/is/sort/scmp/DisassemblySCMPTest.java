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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.beans.Transient;
import java.io.ByteArrayOutputStream;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;

public class DisassemblySCMPTest extends AbstractIntegrationTest {
	public DisassemblySCMPTest() {
		super("SCMP:BE:16:default");
	}


	@Test
	public void EA() {
		// PC-relative.
		// Zero, positive and negative offsets.
		test(0xC0, "LD 0x2",0x00);
		test(0xC0, "LD 0x81",0x7F);
		// Negative offset should wrap around modulo 0x1000.
		test(0xC0, "LD 0xf83",0x81);

		// Pointer-Relative.
		test(0xC1, "LD 0x0(P1)",0x00);
		test(0xC1, "LD 0x7f(P1)",0x7f);
		test(0xC1, "LD -0x7f(P1)",0x81);
		test(0xC1, "LD E(P1)",0x80);

		// Auto-Indexed.
		test(0xC5, "LD @0x0(P1)",0x00);
		test(0xC5, "LD @0x7f(P1)",0x7f);
		test(0xC5, "LD @-0x7f(P1)",0x81);
		test(0xC5, "LD @E(P1)",0x80);
	}

	@Test
	public void LD() {
		test(0xC0, "LD 0x10",0x0E);
		test(0xC1, "LD 0xe(P1)",0x0E);
		test(0xC2, "LD 0xe(P2)",0x0E);
		test(0xC3, "LD 0xe(P3)",0x0E);
		test(0xC3, "LD E(P3)",0x80);

		test(0xC5, "LD @0xe(P1)",0x0E);
		test(0xC6, "LD @0xe(P2)",0x0E);
		test(0xC7, "LD @0xe(P3)",0x0E);
		test(0xC5, "LD @E(P1)",0x80);
	}

	@Test
	public void ST() {
		test(0xC8, "ST 0x10",0x0E);
		test(0xC9, "ST 0xe(P1)",0x0E);
		test(0xCA, "ST 0xe(P2)",0x0E);
		test(0xCB, "ST 0xe(P3)",0x0E);
		test(0xCB, "ST E(P3)",0x80);

		test(0xCD, "ST @0xe(P1)",0x0E);
		test(0xCE, "ST @0xe(P2)",0x0E);
		test(0xCF, "ST @0xe(P3)",0x0E);
		test(0xCF, "ST @E(P3)",0x80);
	}

	@Test
	public void AND() {
		test(0xD0, "AND 0x10",0x0E);
		test(0xD1, "AND 0xe(P1)",0x0E);
		test(0xD2, "AND 0xe(P2)",0x0E);
		test(0xD3, "AND 0xe(P3)",0x0E);
		test(0xD3, "AND E(P3)",0x80);

		test(0xD5, "AND @0xe(P1)",0x0E);
		test(0xD6, "AND @0xe(P2)",0x0E);
		test(0xD7, "AND @0xe(P3)",0x0E);
		test(0xD7, "AND @E(P3)",0x80);
	}

	@Test
	public void OR() {
		test(0xD8, "OR 0x10",0x0E);
		test(0xD9, "OR 0xe(P1)",0x0E);
		test(0xDA, "OR 0xe(P2)",0x0E);
		test(0xDB, "OR 0xe(P3)",0x0E);
		test(0xDB, "OR E(P3)",0x80);

		test(0xDD, "OR @0xe(P1)",0x0E);
		test(0xDE, "OR @0xe(P2)",0x0E);
		test(0xDF, "OR @0xe(P3)",0x0E);
		test(0xDF, "OR @E(P3)",0x80);
	}

	@Test
	public void XOR() {
		test(0xE0, "XOR 0x10",0x0E);
		test(0xE1, "XOR 0xe(P1)",0x0E);
		test(0xE2, "XOR 0xe(P2)",0x0E);
		test(0xE3, "XOR 0xe(P3)",0x0E);
		test(0xE3, "XOR E(P3)",0x80);

		test(0xE5, "XOR @0xe(P1)",0x0E);
		test(0xE6, "XOR @0xe(P2)",0x0E);
		test(0xE7, "XOR @0xe(P3)",0x0E);
		test(0xE7, "XOR @E(P3)",0x80);
	}

	@Test
	public void DAD() {
		test(0xE8, "DAD 0x10",0x0E);
		test(0xE9, "DAD 0xe(P1)",0x0E);
		test(0xEA, "DAD 0xe(P2)",0x0E);
		test(0xEB, "DAD 0xe(P3)",0x0E);
		test(0xEB, "DAD E(P3)",0x80);

		test(0xED, "DAD @0xe(P1)",0x0E);
		test(0xEE, "DAD @0xe(P2)",0x0E);
		test(0xEF, "DAD @0xe(P3)",0x0E);
		test(0xEF, "DAD @E(P3)",0x80);
	}

	@Test
	public void ADD() {
		test(0xF0, "ADD 0x10",0x0E);
		test(0xF1, "ADD 0xe(P1)",0x0E);
		test(0xF2, "ADD 0xe(P2)",0x0E);
		test(0xF3, "ADD 0xe(P3)",0x0E);
		test(0xF3, "ADD E(P3)",0x80);

		test(0xF5, "ADD @0xe(P1)",0x0E);
		test(0xF6, "ADD @0xe(P2)",0x0E);
		test(0xF7, "ADD @0xe(P3)",0x0E);
		test(0xF7, "ADD @E(P3)",0x80);
	}

	@Test
	public void CAD() {
		test(0xF8, "CAD 0x10",0x0E);
		test(0xF9, "CAD 0xe(P1)",0x0E);
		test(0xFA, "CAD 0xe(P2)",0x0E);
		test(0xFB, "CAD 0xe(P3)",0x0E);
		test(0xFB, "CAD E(P3)",0x80);

		test(0xFD, "CAD @0xe(P1)",0x0E);
		test(0xFE, "CAD @0xe(P2)",0x0E);
		test(0xFF, "CAD @0xe(P3)",0x0E);
		test(0xFF, "CAD @E(P3)",0x80);
	}

	@Test
	public void LDE() {
		test(0x40, "LDE");
	}

	protected void test(int opCode, String expected, int... args) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();

		stream.write(opCode);
		for (int arg : args) {
			stream.write(arg);
		}

		byte[] bytes = stream.toByteArray();
		CodeUnit codeUnit = disassemble(bytes);

		assertNotNull(codeUnit);
		assertTrue(codeUnit instanceof Instruction);

		assertEquals(expected, codeUnit.toString());
		assertEquals(bytes.length, codeUnit.getLength());
	}
}
