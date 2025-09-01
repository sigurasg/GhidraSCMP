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
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.beans.Transient;
import java.io.ByteArrayOutputStream;

import javax.management.relation.RoleResult;

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
		assertDisassemblesTo("LD 0x2", 0xC0, 0x00);
		assertDisassemblesTo("LD 0x81", 0xC0, 0x7F);
		// Negative offset should wrap around modulo 0x1000.
		assertDisassemblesTo("LD 0xf83", 0xC0, 0x81);

		// Test wraparound.
		assertDisassemblesAt("LD 0x7000", 0x7FFE, 0xC0, 0x00);
		assertDisassemblesAt("LD 0x707f", 0x7FFE, 0xC0, 0x7F);
		assertDisassemblesAt("LD 0x8f83", 0X8000, 0xC0, 0x81);

		// Pointer-Relative.
		assertDisassemblesTo("LD 0x0(P1)", 0xC1, 0x00);
		assertDisassemblesTo("LD 0x7f(P1)", 0xC1, 0x7f);
		assertDisassemblesTo("LD -0x7f(P1)", 0xC1, 0x81);
		assertDisassemblesTo("LD E(P1)", 0xC1, 0x80);

		// Auto-Indexed.
		assertDisassemblesTo("LD @0x0(P1)", 0xC5, 0x00);
		assertDisassemblesTo("LD @0x7f(P1)", 0xC5, 0x7f);
		assertDisassemblesTo("LD @-0x7f(P1)", 0xC5, 0x81);
		assertDisassemblesTo("LD @E(P1)", 0xC5, 0x80);
	}

	@Test
	public void LD() {
		assertDisassemblesTo("LD 0x10", 0xC0, 0x0E);
		assertDisassemblesTo("LD 0xe(P1)", 0xC1, 0x0E);
		assertDisassemblesTo("LD 0xe(P2)", 0xC2, 0x0E);
		assertDisassemblesTo("LD 0xe(P3)", 0xC3, 0x0E);
		assertDisassemblesTo("LD E(P3)", 0xC3, 0x80);

		assertDisassemblesTo("LD @0xe(P1)", 0xC5, 0x0E);
		assertDisassemblesTo("LD @0xe(P2)", 0xC6, 0x0E);
		assertDisassemblesTo("LD @0xe(P3)", 0xC7, 0x0E);
		assertDisassemblesTo("LD @E(P1)", 0xC5, 0x80);
	}

	@Test
	public void ST() {
		assertDisassemblesTo("ST 0x10", 0xC8, 0x0E);
		assertDisassemblesTo("ST 0xe(P1)", 0xC9, 0x0E);
		assertDisassemblesTo("ST 0xe(P2)", 0xCA, 0x0E);
		assertDisassemblesTo("ST 0xe(P3)", 0xCB, 0x0E);
		assertDisassemblesTo("ST E(P3)", 0xCB, 0x80);

		assertDisassemblesTo("ST @0xe(P1)", 0xCD, 0x0E);
		assertDisassemblesTo("ST @0xe(P2)", 0xCE, 0x0E);
		assertDisassemblesTo("ST @0xe(P3)", 0xCF, 0x0E);
		assertDisassemblesTo("ST @E(P3)", 0xCF, 0x80);
	}

	@Test
	public void AND() {
		assertDisassemblesTo("AND 0x10", 0xD0, 0x0E);
		assertDisassemblesTo("AND 0xe(P1)", 0xD1, 0x0E);
		assertDisassemblesTo("AND 0xe(P2)", 0xD2, 0x0E);
		assertDisassemblesTo("AND 0xe(P3)", 0xD3, 0x0E);
		assertDisassemblesTo("AND E(P3)", 0xD3, 0x80);

		assertDisassemblesTo("AND @0xe(P1)", 0xD5, 0x0E);
		assertDisassemblesTo("AND @0xe(P2)", 0xD6, 0x0E);
		assertDisassemblesTo("AND @0xe(P3)", 0xD7, 0x0E);
		assertDisassemblesTo("AND @E(P3)", 0xD7, 0x80);
	}

	@Test
	public void OR() {
		assertDisassemblesTo("OR 0x10", 0xD8, 0x0E);
		assertDisassemblesTo("OR 0xe(P1)", 0xD9, 0x0E);
		assertDisassemblesTo("OR 0xe(P2)", 0xDA, 0x0E);
		assertDisassemblesTo("OR 0xe(P3)", 0xDB, 0x0E);
		assertDisassemblesTo("OR E(P3)", 0xDB, 0x80);

		assertDisassemblesTo("OR @0xe(P1)", 0xDD, 0x0E);
		assertDisassemblesTo("OR @0xe(P2)", 0xDE, 0x0E);
		assertDisassemblesTo("OR @0xe(P3)", 0xDF, 0x0E);
		assertDisassemblesTo("OR @E(P3)", 0xDF, 0x80);
	}

	@Test
	public void XOR() {
		assertDisassemblesTo("XOR 0x10", 0xE0, 0x0E);
		assertDisassemblesTo("XOR 0xe(P1)", 0xE1, 0x0E);
		assertDisassemblesTo("XOR 0xe(P2)", 0xE2, 0x0E);
		assertDisassemblesTo("XOR 0xe(P3)", 0xE3, 0x0E);
		assertDisassemblesTo("XOR E(P3)", 0xE3, 0x80);

		assertDisassemblesTo("XOR @0xe(P1)", 0xE5, 0x0E);
		assertDisassemblesTo("XOR @0xe(P2)", 0xE6, 0x0E);
		assertDisassemblesTo("XOR @0xe(P3)", 0xE7, 0x0E);
		assertDisassemblesTo("XOR @E(P3)", 0xE7, 0x80);
	}

	@Test
	public void DAD() {
		assertDisassemblesTo("DAD 0x10", 0xE8, 0x0E);
		assertDisassemblesTo("DAD 0xe(P1)", 0xE9, 0x0E);
		assertDisassemblesTo("DAD 0xe(P2)", 0xEA, 0x0E);
		assertDisassemblesTo("DAD 0xe(P3)", 0xEB, 0x0E);
		assertDisassemblesTo("DAD E(P3)", 0xEB, 0x80);

		assertDisassemblesTo("DAD @0xe(P1)", 0xED, 0x0E);
		assertDisassemblesTo("DAD @0xe(P2)", 0xEE, 0x0E);
		assertDisassemblesTo("DAD @0xe(P3)", 0xEF, 0x0E);
		assertDisassemblesTo("DAD @E(P3)", 0xEF, 0x80);
	}

	@Test
	public void ADD() {
		assertDisassemblesTo("ADD 0x10", 0xF0, 0x0E);
		assertDisassemblesTo("ADD 0xe(P1)", 0xF1, 0x0E);
		assertDisassemblesTo("ADD 0xe(P2)", 0xF2, 0x0E);
		assertDisassemblesTo("ADD 0xe(P3)", 0xF3, 0x0E);
		assertDisassemblesTo("ADD E(P3)", 0xF3, 0x80);

		assertDisassemblesTo("ADD @0xe(P1)", 0xF5, 0x0E);
		assertDisassemblesTo("ADD @0xe(P2)", 0xF6, 0x0E);
		assertDisassemblesTo("ADD @0xe(P3)", 0xF7, 0x0E);
		assertDisassemblesTo("ADD @E(P3)", 0xF7, 0x80);
	}

	@Test
	public void CAD() {
		assertDisassemblesTo("CAD 0x10", 0xF8, 0x0E);
		assertDisassemblesTo("CAD 0xe(P1)", 0xF9, 0x0E);
		assertDisassemblesTo("CAD 0xe(P2)", 0xFA, 0x0E);
		assertDisassemblesTo("CAD 0xe(P3)", 0xFB, 0x0E);
		assertDisassemblesTo("CAD E(P3)", 0xFB, 0x80);

		assertDisassemblesTo("CAD @0xe(P1)", 0xFD, 0x0E);
		assertDisassemblesTo("CAD @0xe(P2)", 0xFE, 0x0E);
		assertDisassemblesTo("CAD @0xe(P3)", 0xFF, 0x0E);
		assertDisassemblesTo("CAD @E(P3)", 0xFF, 0x80);
	}

	@Test
	public void ILD() {
		assertDisassemblesTo("ILD 0x10", 0xA8, 0x0E);
		assertDisassemblesTo("ILD 0xe(P1)", 0xA9, 0x0E);
		assertDisassemblesTo("ILD 0xe(P2)", 0xAA, 0x0E);
		assertDisassemblesTo("ILD 0xe(P3)", 0xAB, 0x0E);
	}

	@Test
	public void DLD() {
		assertDisassemblesTo("DLD 0x10", 0xB8, 0x0E);
		assertDisassemblesTo("DLD 0xe(P1)", 0xB9, 0x0E);
		assertDisassemblesTo("DLD 0xe(P2)", 0xBA, 0x0E);
		assertDisassemblesTo("DLD 0xe(P3)", 0xBB, 0x0E);

		assertDisassemblesTo("DLD E(P3)", 0xBB, 0x80);
	}

	@Test
	public void LDI() {
		assertDisassemblesTo("LDI 0xff", 0xC4, 0xFF);
	}

	@Test
	public void ANI() {
		assertDisassemblesTo("ANI 0xff", 0xD4, 0xFF);
	}

	@Test
	public void ORI() {
		assertDisassemblesTo("ORI 0xff", 0xDC, 0xFF);
	}

	@Test
	public void XRI() {
		assertDisassemblesTo("XRI 0xff", 0xE4, 0xFF);
	}

	@Test
	public void DAI() {
		assertDisassemblesTo("DAI 0xff", 0xEC, 0xFF);
	}

	@Test
	public void ADI() {
		assertDisassemblesTo("ADI 0xff", 0xF4, 0xFF);
	}

	@Test
	public void CAI() {
		assertDisassemblesTo("CAI 0xff", 0xFC, 0xFF);
	}

	@Test
	public void JMP() {
		assertDisassemblesTo("JMP 0x10", 0x90, 0x0E);
		assertDisassemblesTo("JMP 0xe(P1)", 0x91, 0x0E);
		assertDisassemblesTo("JMP 0xe(P2)", 0x92, 0x0E);
		assertDisassemblesTo("JMP 0xe(P3)", 0x93, 0x0E);

		// Test wraparound.
		assertDisassemblesAt("JMP 0x700e", 0x7FFE, 0x90, 0x0E);
		assertDisassemblesAt("JMP 0x7f83", 0x7000, 0x90, 0x81);
	}

	@Test
	public void JP() {
		assertDisassemblesTo("JP 0x10", 0x94, 0x0E);
		assertDisassemblesTo("JP 0xe(P1)", 0x95, 0x0E);
		assertDisassemblesTo("JP 0xe(P2)", 0x96, 0x0E);
		assertDisassemblesTo("JP 0xe(P3)", 0x97, 0x0E);
	}

	@Test
	public void JZ() {
		assertDisassemblesTo("JZ 0x10", 0x98, 0x0E);
		assertDisassemblesTo("JZ 0xe(P1)", 0x99, 0x0E);
		assertDisassemblesTo("JZ 0xe(P2)", 0x9A, 0x0E);
		assertDisassemblesTo("JZ 0xe(P3)", 0x9B, 0x0E);
	}

	@Test
	public void JNZ() {
		assertDisassemblesTo("JNZ 0x10", 0x9C, 0x0E);
		assertDisassemblesTo("JNZ 0xe(P1)", 0x9D, 0x0E);
		assertDisassemblesTo("JNZ 0xe(P2)", 0x9E, 0x0E);
		assertDisassemblesTo("JNZ 0xe(P3)", 0x9F, 0x0E);
	}

	@Test
	public void DLY() {
		assertDisassemblesTo("DLY 0x8f", 0x8F, 0x8F);
	}

	@Test
	public void LDE() {
		assertDisassemblesTo("LDE", 0x40);
	}

	@Test
	public void XAE() {
		assertDisassemblesTo("XAE", 0x01);
	}

	@Test
	public void ANE() {
		assertDisassemblesTo("ANE", 0x50);
	}

	@Test
	public void ORE() {
		assertDisassemblesTo("ORE", 0x58);
	}

	@Test
	public void XRE() {
		assertDisassemblesTo("XRE", 0x60);
	}

	@Test
	public void DAE() {
		assertDisassemblesTo("DAE", 0x68);
	}

	@Test
	public void ADE() {
		assertDisassemblesTo("ADE", 0x70);
	}

	@Test
	public void CAE() {
		assertDisassemblesTo("CAE", 0x78);
	}

	@Test
	public void XPAL() {
		assertDisassemblesTo("XPAL PC", 0x30);
		assertDisassemblesTo("XPAL P1", 0x31);
		assertDisassemblesTo("XPAL P2", 0x32);
		assertDisassemblesTo("XPAL P3", 0x33);
	}

	@Test
	public void XPAH() {
		assertDisassemblesTo("XPAH PC", 0x34);
		assertDisassemblesTo("XPAH P1", 0x35);
		assertDisassemblesTo("XPAH P2", 0x36);
		assertDisassemblesTo("XPAH P3", 0x37);
	}

	@Test
	public void XPPC() {
		assertDisassemblesTo("XPPC PC", 0x3C);
		assertDisassemblesTo("XPPC P1", 0x3D);
		assertDisassemblesTo("XPPC P2", 0x3E);
		assertDisassemblesTo("XPPC P3", 0x3F);
	}

	@Test
	public void SIO() {
		assertDisassemblesTo("SIO", 0x19);
	}

	@Test
	public void SR() {
		assertDisassemblesTo("SR", 0x1C);
	}

	@Test
	public void SRL() {
		assertDisassemblesTo("SRL", 0x1D);
	}

	@Test
	public void RR() {
		assertDisassemblesTo("RR", 0x1E);
	}

	@Test
	public void RRL() {
		assertDisassemblesTo("RRL", 0x1F);
	}

	@Test
	public void HALT() {
		assertDisassemblesTo("HALT", 0x00);
	}

	@Test
	public void CCL() {
		assertDisassemblesTo("CCL", 0x02);
	}

	@Test
	public void SCL() {
		assertDisassemblesTo("SCL", 0x03);
	}

	@Test
	public void DINT() {
		assertDisassemblesTo("DINT", 0x04);
	}

	@Test
	public void IEN() {
		assertDisassemblesTo("IEN", 0x05);
	}

	@Test
	public void CSA() {
		assertDisassemblesTo("CSA", 0x06);
	}

	@Test
	public void CAS() {
		assertDisassemblesTo("CAS", 0x07);
	}

	@Test
	public void NOP() {
		assertDisassemblesTo("NOP", 0x08);
	}

	@Test
	public void InvalidOpCodes() {
		assertInvalidOpcode(0x09);
		assertInvalidOpcode(0x0A);
		assertInvalidOpcode(0x0B);
		assertInvalidOpcode(0x0C);
		assertInvalidOpcode(0x0D);
		assertInvalidOpcode(0x0E);
		assertInvalidOpcode(0x0F);
		assertInvalidOpcode(0x10);
		assertInvalidOpcode(0x11);
		assertInvalidOpcode(0x12);
		assertInvalidOpcode(0x13);
		assertInvalidOpcode(0x14);
		assertInvalidOpcode(0x15);
		assertInvalidOpcode(0x16);
		assertInvalidOpcode(0x17);
		assertInvalidOpcode(0x18);
		assertInvalidOpcode(0x1A);
		assertInvalidOpcode(0x1B);
		assertInvalidOpcode(0x20);
		assertInvalidOpcode(0x21);
		assertInvalidOpcode(0x22);
		assertInvalidOpcode(0x23);
		assertInvalidOpcode(0x24);
		assertInvalidOpcode(0x25);
		assertInvalidOpcode(0x26);
		assertInvalidOpcode(0x27);
		assertInvalidOpcode(0x28);
		assertInvalidOpcode(0x29);
		assertInvalidOpcode(0x2A);
		assertInvalidOpcode(0x2B);
		assertInvalidOpcode(0x2C);
		assertInvalidOpcode(0x2D);
		assertInvalidOpcode(0x2E);
		assertInvalidOpcode(0x2F);
		assertInvalidOpcode(0x38);
		assertInvalidOpcode(0x39);
		assertInvalidOpcode(0x3A);
		assertInvalidOpcode(0x3B);
		assertInvalidOpcode(0x41);
		assertInvalidOpcode(0x42);
		assertInvalidOpcode(0x43);
		assertInvalidOpcode(0x44);
		assertInvalidOpcode(0x45);
		assertInvalidOpcode(0x46);
		assertInvalidOpcode(0x47);
		assertInvalidOpcode(0x48);
		assertInvalidOpcode(0x49);
		assertInvalidOpcode(0x4A);
		assertInvalidOpcode(0x4B);
		assertInvalidOpcode(0x4C);
		assertInvalidOpcode(0x4D);
		assertInvalidOpcode(0x4E);
		assertInvalidOpcode(0x4F);
		assertInvalidOpcode(0x51);
		assertInvalidOpcode(0x52);
		assertInvalidOpcode(0x53);
		assertInvalidOpcode(0x54);
		assertInvalidOpcode(0x55);
		assertInvalidOpcode(0x56);
		assertInvalidOpcode(0x57);
		assertInvalidOpcode(0x59);
		assertInvalidOpcode(0x5A);
		assertInvalidOpcode(0x5B);
		assertInvalidOpcode(0x5C);
		assertInvalidOpcode(0x5D);
		assertInvalidOpcode(0x5E);
		assertInvalidOpcode(0x5F);
		assertInvalidOpcode(0x61);
		assertInvalidOpcode(0x62);
		assertInvalidOpcode(0x63);
		assertInvalidOpcode(0x64);
		assertInvalidOpcode(0x65);
		assertInvalidOpcode(0x66);
		assertInvalidOpcode(0x67);
		assertInvalidOpcode(0x69);
		assertInvalidOpcode(0x6A);
		assertInvalidOpcode(0x6B);
		assertInvalidOpcode(0x6C);
		assertInvalidOpcode(0x6D);
		assertInvalidOpcode(0x6E);
		assertInvalidOpcode(0x6F);
		assertInvalidOpcode(0x71);
		assertInvalidOpcode(0x72);
		assertInvalidOpcode(0x73);
		assertInvalidOpcode(0x74);
		assertInvalidOpcode(0x75);
		assertInvalidOpcode(0x76);
		assertInvalidOpcode(0x77);
		assertInvalidOpcode(0x79);
		assertInvalidOpcode(0x7A);
		assertInvalidOpcode(0x7B);
		assertInvalidOpcode(0x7C);
		assertInvalidOpcode(0x7D);
		assertInvalidOpcode(0x7E);
		assertInvalidOpcode(0x7F);
		assertInvalidOpcode(0x80);
		assertInvalidOpcode(0x81);
		assertInvalidOpcode(0x82);
		assertInvalidOpcode(0x83);
		assertInvalidOpcode(0x84);
		assertInvalidOpcode(0x85);
		assertInvalidOpcode(0x86);
		assertInvalidOpcode(0x87);
		assertInvalidOpcode(0x88);
		assertInvalidOpcode(0x89);
		assertInvalidOpcode(0x8A);
		assertInvalidOpcode(0x8B);
		assertInvalidOpcode(0x8C);
		assertInvalidOpcode(0x8D);
		assertInvalidOpcode(0x8E);
		assertInvalidOpcode(0xA0);
		assertInvalidOpcode(0xA1);
		assertInvalidOpcode(0xA2);
		assertInvalidOpcode(0xA3);
		assertInvalidOpcode(0xA4);
		assertInvalidOpcode(0xA5);
		assertInvalidOpcode(0xA6);
		assertInvalidOpcode(0xA7);
		assertInvalidOpcode(0xAC);
		assertInvalidOpcode(0xAD);
		assertInvalidOpcode(0xAE);
		assertInvalidOpcode(0xAF);
		assertInvalidOpcode(0xB0);
		assertInvalidOpcode(0xB1);
		assertInvalidOpcode(0xB2);
		assertInvalidOpcode(0xB3);
		assertInvalidOpcode(0xB4);
		assertInvalidOpcode(0xB5);
		assertInvalidOpcode(0xB6);
		assertInvalidOpcode(0xB7);
		assertInvalidOpcode(0xBC);
		assertInvalidOpcode(0xBD);
		assertInvalidOpcode(0xBE);
		assertInvalidOpcode(0xBF);
		// This oddball op code corresponds to the non-existent and
		// nonsensical STI or otherwise the likewise nonsensical
		// ST @disp8(PC).
		assertInvalidOpcode(0xCC);
	}

	protected void assertDisassemblesAt(String expected, int addr, int... code) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		for (int arg : code) {
			stream.write(arg);
		}

		byte[] bytes = stream.toByteArray();
		CodeUnit codeUnit = disassembleAt(addr, bytes);

		assertNotNull(codeUnit);
		assertTrue(codeUnit instanceof Instruction);

		assertEquals(expected, codeUnit.toString());
		assertEquals(bytes.length, codeUnit.getLength());
	}

	protected void assertDisassemblesTo(String expected, int... code) {
		assertDisassemblesAt(expected, 0, code);
	}

	protected void assertInvalidOpcode(int opCode) {
		byte[] bytes = { (byte) opCode, 0x01, 0x02, 0x03 };
		CodeUnit codeUnit = disassembleAt(0, bytes);
		assertFalse(codeUnit instanceof Instruction,
			"Unexpected instruction: " + codeUnit.toString());
	}
}
