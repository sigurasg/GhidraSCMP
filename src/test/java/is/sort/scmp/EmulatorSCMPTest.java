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

import org.junit.jupiter.api.Test;

public class EmulatorSCMPTest extends AbstractEmulatorTest {
	public EmulatorSCMPTest() {
		super("SCMP:BE:16:default");
	}

	@Test
	public void AutoIndexedEA() {
		final int PC = 0x0100;

		assemble(PC,
			"ST @0x10(P1)",		// Post-increment
			"LD @-0x10(P1)",
			"ST @-0x10(P1)",			// Pre-decrement
			"LD @0x10(P1)");

		setAC(0xAA);
		setP1(0x01000);
		stepFrom(PC);
		assertEquals(0x1010, getP1());
		assertEquals(0xAA, readByte(0x01000));

		setAC(0x00);
		step();
		assertEquals(0x01000, getP1());
		assertEquals(0xAA, getAC());

		step();
		assertEquals(0x1FF0, getP1());
		assertEquals(0xAA, readByte(0x1FF0));

		setAC(0x00);
		step();
		step();
		assertEquals(0x01000, getP1());
		assertEquals(0xAA, getAC());
	}

	@Test
	public void AutoIndexedEAWithE() {
		// Test that the @E(ptr) addressing mode pre-decrements
		// or post-increments, depending on the value of E.
		final int PC = 0x0100;

		assemble(PC,
			"ST @E(P1)",
			"LD @E(P1)");

		setAC(0xAA);
		setP1(0x01000);
		setE(0x10);
		stepFrom(PC);
		assertEquals(0x1010, getP1());
		assertEquals(0xAA, readByte(0x01000));

		setAC(0x00);
		setE(0xF0);
		step();
		assertEquals(0x01000, getP1());
		assertEquals(0xAA, getAC());
	}

	@Test
	public void LD_PCRel() {
		final int PC = 0x8100;

		assemble(PC, "LD 0x8111");

		write(0x8111, 0xFF);
		stepFrom(PC);
		assertEquals(getAC(), 0xFF);
	}

	@Test
	public void ADDI() {
		assemble(0x0100, "ADI 0x10");

		// Add with no carry.
		setSR(0x00);
		setAC(0x00);
		stepFrom(0x0100);
		assertEquals(0x00, getSR());
		assertEquals(0x10, getAC());

		// Add with carry set.
		setSR(0x80);
		setAC(0x00);
		stepFrom(0x0100);
		assertEquals(0x00, getSR());
		assertEquals(0x11, getAC());

		// Overflow.
		setSR(0x00);
		setAC(0x70);
		stepFrom(0x0100);
		assertEquals(0x40, getSR());
		assertEquals(0x80, getAC());

		// Overflow through carry.
		setSR(0x80);
		setAC(0x6F);
		stepFrom(0x0100);
		assertEquals(0x40, getSR());
		assertEquals(0x80, getAC());

		// Carry out.
		setSR(0x00);
		setAC(0xF0);
		stepFrom(0x0100);
		assertEquals(0x80, getSR());
		assertEquals(0x00, getAC());

		// Carry in & out.
		setSR(0x80);
		setAC(0xEF);
		stepFrom(0x0100);
		assertEquals(0x80, getSR());
		assertEquals(0x00, getAC());
	}

	@Test
	public void CAI() {
		// Cheat, knowing that the implementation is essentially
		// just ADI with complement.
		assemble(0x0100, "CAI 0xEF");

		// No carry.
		setSR(0x00);
		setAC(0x00);
		stepFrom(0x0100);
		assertEquals(0x00, getSR());
		assertEquals(0x10, getAC());
	}

	@Test
	public void DAE() {
		assemble(0x0100, "DAE");

		setSR(0x00);
		setAC(0x89);
		setE(0x11);
		stepFrom(0x0100);
		assertEquals(0x00, getAC());
		assertEquals(0x80, getSR());

		// TODO(siggi): Moar testing.
	}

	@Test
	public void JMP_PCRel() {
		final int PC = 0x8100;
		// PC-relative JMP.
		assemble(PC,
			"JMP 0x8112",
			"JMP 0x8102");

		stepFrom(PC);
		assertEquals(PC + 0x12, getPC());

		stepFrom(PC + 2);
		assertEquals(PC + 0x02, getPC());
	}

	@Test
	public void JMP_P1Rel() {
		// P1-relative JMP.
		setP1(0x0200);
		assemble(0x0100, "JMP 0x11(P1)");
		stepFrom(0x0100);
		assertEquals(0x0212, getPC());
	}

	@Test
	public void JMP_P1RelWithNoE() {
		// P1-relative JMP.
		setP1(0x0200);
		setE(0x20);
		// Note that a displacement of 0x80 does not imply E for
		// DLD/ILD/JMP instruction forms.
		assemble(0x0100, "JMP -0x80(P1)");
		stepFrom(0x0100);
		assertEquals(0x0181, getPC());
	}

	@Test
	public void JP() {
		assemble(0x0100, "JP 0x0112");

		// Test zero.
		setAC(0x00);
		stepFrom(0x0100);
		assertEquals(0x0112, getPC());

		// Test positive
		setAC(0x7F);
		stepFrom(0x0100);
		assertEquals(0x0112, getPC());

		// Test negative.
		setAC(0x81);
		stepFrom(0x0100);
		assertEquals(0x0102, getPC());
	}

	@Test
	public void JZ() {
		assemble(0x0100, "JZ 0x0112");

		// Test zero.
		setAC(0x00);
		stepFrom(0x0100);
		assertEquals(0x0112, getPC());

		// Test positive
		setAC(0x7F);
		stepFrom(0x0100);
		assertEquals(0x0102, getPC());

		// Test negative.
		setAC(0x81);
		stepFrom(0x0100);
		assertEquals(0x0102, getPC());
	}

	@Test
	public void JNZ() {
		assemble(0x0100, "JNZ 0x0112");

		// Test zero.
		setAC(0x00);
		stepFrom(0x0100);
		assertEquals(0x0102, getPC());

		// Test positive
		setAC(0x7F);
		stepFrom(0x0100);
		assertEquals(0x0112, getPC());

		// Test negative.
		setAC(0x81);
		stepFrom(0x0100);
		assertEquals(0x0112, getPC());
	}

	@Test
	public void DLY() {
		assertIsNOP(0x8F, 0x10);
	}

	@Test
	public void XAE() {
		assemble(0x0100, "XAE");
		setAC(0x01);
		setE(0x02);
		stepFrom(0x0100);
		assertEquals(0x02, getAC());
		assertEquals(0x01, getE());
	}

	@Test
	public void XPAL() {
		assemble(0x0100, "XPAL P1");

		setAC(0x01);
		setP1(0x0203);
		stepFrom(0x0100);

		assertEquals(0x03, getAC());
		assertEquals(0x0201, getP1());
	}

	@Test
	public void XPAH() {
		assemble(0x0100, "XPAH P1");

		setAC(0x01);
		setP1(0x0203);
		stepFrom(0x0100);

		assertEquals(0x02, getAC());
		assertEquals(0x0103, getP1());
	}

	@Test
	public void XPPC() {
		assemble(0x0100, "XPPC P1");

		setP1(0x0203);
		stepFrom(0x0100);

		// PC is incremented post-exchange.
		assertEquals(0x0204, getPC());
		assertEquals(0x0100, getP1());
	}

	@Test
	public void SIO() {
		assemble(0x0100, "SIO");

		setSERIAL(0x00);
		setE(0xAA);
		stepFrom((0x0100));
		assertEquals(0x55, getE());
		assertEquals(getSERIAL(), 0x00);

		// Shift serial bits in/out.
		setSERIAL(0x01);
		setE(0x55);
		stepFrom((0x0100));
		assertEquals(0xAA, getE());
		assertEquals(getSERIAL(), 0x81);
	}

	@Test
	public void SR() {
		assemble(0x0100, "SR");

		setAC(0xAA);
		setSR(0xFF);
		stepFrom((0x0100));
		assertEquals(0x55, getAC());
		assertEquals(0xFF, getSR());
	}

	@Test
	public void SRL() {
		assemble(0x0100, "SRL");

		setAC(0xAA);
		setSR(0xFF);
		stepFrom((0x0100));
		assertEquals(0xD5, getAC());
		assertEquals(0xFF, getSR());
	}

	@Test
	public void RR() {
		assemble(0x0100, "RR");

		setAC(0x41);
		setSR(0xFF);
		stepFrom((0x0100));
		assertEquals(0xA0, getAC());
		assertEquals(0xFF, getSR());
	}

	@Test
	public void RRL() {
		assemble(0x0100, "RRL");

		setAC(0x01);
		setSR(0xFF);
		stepFrom((0x0100));
		assertEquals(0x80, getAC());
		assertEquals(0xFF, getSR());

		setAC(0x01);
		setSR(0x00);
		stepFrom((0x0100));
		assertEquals(0x00, getAC());
		assertEquals(0x80, getSR());
	}

	@Test
	public void HALT() {
		assertIsNOP(0x00);
	}

	@Test
	public void CCL() {
		assemble(0x0000, "CCL");
		setSR(0xFF);
		stepFrom(0x0000);
		assertEquals(0x7F, getSR());
	}

	@Test
	public void SCL() {
		assemble(0x0000, "SCL");
		setSR(0x00);
		stepFrom(0x0000);
		assertEquals(0x80, getSR());
	}

	@Test
	public void DINT() {
		assemble(0x0000, "DINT");
		setSR(0xFF);
		stepFrom(0x0000);
		assertEquals(0xF7, getSR());
	}

	@Test
	public void IEN() {
		assemble(0x0000, "IEN");
		setSR(0x00);
		stepFrom(0x0000);
		assertEquals(0x08, getSR());
	}

	@Test
	public void CSA() {
		assemble(0x0000, "CSA");
		setSR(0xAA);
		setAC(0x00);
		stepFrom(0x0000);
		assertEquals(0xAA, getSR());
		assertEquals(0xAA, getAC());
	}

	@Test
	public void CAS() {
		assemble(0x0000, "CAS");
		setAC(0xAA);
		setSR(0x00);
		stepFrom(0x0000);
		assertEquals(0xAA, getSR());
		assertEquals(0xAA, getAC());
	}

	@Test
	public void NOP() {
		assertIsNOP(0x08);
	}

	protected void assertIsNOP(int... code) {
		setAC(0x00);
		setSR(0x00);
		setE(0x00);
		setP1(0x0010);
		setP2(0x0020);
		setP3(0x0030);

		write(0x0000, code);
		stepFrom(0x000);

		assertEquals(0x00, getAC());
		assertEquals(0x00, getSR());
		assertEquals(0x00, getE());
		assertEquals(0x0010, getP1());
		assertEquals(0x0020, getP2());
		assertEquals(0x0030, getP3());
		assertEquals(code.length, getPC());
	}
}
