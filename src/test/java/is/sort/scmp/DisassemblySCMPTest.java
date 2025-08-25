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
	public void ILD() {
		test(0xA8, "ILD 0x10", 0x0E);
		test(0xA9, "ILD 0xe(P1)", 0x0E);
		test(0xAA, "ILD 0xe(P2)", 0x0E);
		test(0xAB, "ILD 0xe(P3)", 0x0E);
	}
	
	@Test
	public void DLD() {
		test(0xB8, "DLD 0x10", 0x0E);
		test(0xB9, "DLD 0xe(P1)", 0x0E);
		test(0xBA, "DLD 0xe(P2)", 0x0E);
		test(0xBB, "DLD 0xe(P3)", 0x0E);
	}
	
	@Test
	public void LDI() {
		test(0xC4, "LDI 0xff", 0xFF);
	}

	@Test
	public void ANI() {
		test(0xD4, "ANI 0xff", 0xFF);
	}

	@Test
	public void ORI() {
		test(0xDC, "ORI 0xff", 0xFF);
	}

	@Test
	public void XRI() {
		test(0xE4, "XRI 0xff", 0xFF);
	}

	@Test
	public void DAI() {
		test(0xEC, "DAI 0xff", 0xFF);
	}

	@Test
	public void ADI() {
		test(0xF4, "ADI 0xff", 0xFF);
	}

	@Test
	public void CAI() {
		test(0xFC, "CAI 0xff", 0xFF);
	}

	@Test
	public void JMP() {
		test(0x90, "JMP 0x10", 0x0E);
		test(0x91, "JMP 0xe(P1)", 0x0E);
		test(0x92, "JMP 0xe(P2)", 0x0E);
		test(0x93, "JMP 0xe(P3)", 0x0E);
	}

	@Test
	public void JP() {
		test(0x94, "JP 0x10", 0x0E);
		test(0x95, "JP 0xe(P1)", 0x0E);
		test(0x96, "JP 0xe(P2)", 0x0E);
		test(0x97, "JP 0xe(P3)", 0x0E);
	}

	@Test
	public void JZ() {
		test(0x98, "JZ 0x10", 0x0E);
		test(0x99, "JZ 0xe(P1)", 0x0E);
		test(0x9A, "JZ 0xe(P2)", 0x0E);
		test(0x9B, "JZ 0xe(P3)", 0x0E);
	}

	@Test
	public void JNZ() {
		test(0x9C, "JNZ 0x10", 0x0E);
		test(0x9D, "JNZ 0xe(P1)", 0x0E);
		test(0x9E, "JNZ 0xe(P2)", 0x0E);
		test(0x9F, "JNZ 0xe(P3)", 0x0E);
	}

	@Test
	public void DLY() {
		test(0x8F, "DLY");
	}
	
	@Test
	public void LDE() {
		test(0x40, "LDE");
	}

	@Test
	public void XAE() {
		test(0x01, "XAE");
	}


	@Test
	public void ANE() {
		test(0x50, "ANE");
	}

	@Test
	public void ORE() {
		test(0x58, "ORE");
	}

	@Test
	public void XRE() {
		test(0x60, "XRE");
	}

	@Test
	public void DAE() {
		test(0x68, "DAE");
	}

		@Test
	public void ADE() {
		test(0x70, "ADE");
	}

	@Test
	public void CAE() {
		test(0x78, "CAE");
	}

	@Test
	public void XPAL() {
		test(0x30, "XPAL PC");
		test(0x31, "XPAL P1");
		test(0x32, "XPAL P2");
		test(0x33, "XPAL P3");
	}	

	@Test
	public void XPAH() {
		test(0x34, "XPAH PC");
		test(0x35, "XPAH P1");
		test(0x36, "XPAH P2");
		test(0x37, "XPAH P3");
	}	

	@Test
	public void XPPC() {
		test(0x3C, "XPPC PC");
		test(0x3D, "XPPC P1");
		test(0x3E, "XPPC P2");
		test(0x3F, "XPPC P3");
	}	

	@Test
	public void NOP() {
		test(0x08, "NOP");
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
