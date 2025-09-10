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

import java.beans.Transient;

import org.junit.jupiter.api.Test;

public class EmulatorSCMPTest extends AbstractEmulatorTest {
	public EmulatorSCMPTest() {
		super("SCMP:BE:16:default");
	}

	@Test
	public void AutoIndexedEA() {
		final int PC = 0x0100;

		// Post-increment:
		// 	ST @0x10(P1)
		// 	LD @0x-10(P1)
		// Pre-decrement:
		//	ST @-0x10(P1)
		//	LD @0x10(P1)
		write(PC, 0xCD, 0x10, 0xC5, 0xF0, 0xCD, 0xF0, 0xC5, 0x10);

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

		// 	ST @E(P1)
		// 	LD @E(P1)
		write(PC, 0xCD, 0x80, 0xC5, 0x80);

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
		write(PC, 0xC0, 0x10);  // LD 0x8111
		write(0x8111, 0xFF);
		stepFrom(PC);
		assertEquals(getAC(), 0xFF);
	}

	@Test
	public void ADDI() {
		write(0x0100, 0xF4, 0x10);  // ADI 0x10

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
		write(0x0100, 0xFC, ~0x10);  // CAI 0x10

		// No carry.
		setSR(0x00);
		setAC(0x00);
		stepFrom(0x0100);
		assertEquals(0x00, getSR());
		assertEquals(0x10, getAC());
	}

	@Test
	public void DAE() {
		write(0x0100, 0x68);

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
		// JMP 0x8112
		// JMP 0x8102
		write(PC, 0x90, 0x10, 0x90, 0xFE);
		stepFrom(PC);
		assertEquals(PC + 0x12, getPC());

		stepFrom(PC + 2);
		assertEquals(PC + 0x02, getPC());
	}

	@Test
	public void JMP_P1Rel() {
		// P1-relative JMP.
		setP1(0x0200);
		write(0x0100, 0x91, 0x11);  // JMP 0x10(P1)
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
		write(0x0100, 0x91, 0x80);  // JMP -0x80(P1)
		stepFrom(0x0100);
		assertEquals(0x0181, getPC());
	}

	@Test
	public void JP() {
		write(0x0100, 0x94, 0x10);  // JP 0x0112

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
		write(0x0100, 0x98, 0x10);  // JZ 0x0112

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
		write(0x0100, 0x9C, 0x10);  // JNZ 0x0112

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
		write(0x0100, 0x01);	// XAE
		setAC(0x01);
		setE(0x02);
		stepFrom(0x0100);
		assertEquals(0x02, getAC());
		assertEquals(0x01, getE());
	}

	@Test
	public void XPAL() {
		write(0x0100, 0x31);  // XPAL P1.

		setAC(0x01);
		setP1(0x0203);
		stepFrom(0x0100);

		assertEquals(0x03, getAC());
		assertEquals(0x0201, getP1());
	}

	@Test
	public void XPAH() {
		write(0x0100, 0x35);  // XPAH P1.

		setAC(0x01);
		setP1(0x0203);
		stepFrom(0x0100);

		assertEquals(0x02, getAC());
		assertEquals(0x0103, getP1());
	}

	@Test
	public void XPPC() {
		write(0x0100, 0x3D);  // XPPC P1.

		setP1(0x0203);
		stepFrom(0x0100);

		// PC is incremented post-exchange.
		assertEquals(0x0204, getPC());
		assertEquals(0x0100, getP1());
	}

	@Test
	public void SIO() {
		write(0x0100, 0x19);  // SIO.

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
		write(0x0100, 0x1C);  // SR.

		setAC(0xAA);
		setSR(0xFF);
		stepFrom((0x0100));
		assertEquals(0x55, getAC());
		assertEquals(0xFF, getSR());
	}

	@Test
	public void SRL() {
		write(0x0100, 0x1D);  // SRL.

		setAC(0xAA);
		setSR(0xFF);
		stepFrom((0x0100));
		assertEquals(0xD5, getAC());
		assertEquals(0xFF, getSR());
	}

	@Test
	public void RR() {
		write(0x0100, 0x1E);  // RR.

		setAC(0x41);
		setSR(0xFF);
		stepFrom((0x0100));
		assertEquals(0xA0, getAC());
		assertEquals(0xFF, getSR());
	}

	@Test
	public void RRL() {
		write(0x0100, 0x1F);  // RRL.

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
		write(0x0000, 0x02);	// CCL
		setSR(0xFF);
		stepFrom(0x0000);
		assertEquals(0x7F, getSR());
	}

	@Test
	public void SCL() {
		write(0x0000, 0x03);	// SCL
		setSR(0x00);
		stepFrom(0x0000);
		assertEquals(0x80, getSR());
	}

	@Test
	public void DINT() {
		write(0x0000, 0x04);	// DINT
		setSR(0xFF);
		stepFrom(0x0000);
		assertEquals(0xF7, getSR());
	}

	@Test
	public void IEN() {
		write(0x0000, 0x05);	// IEN
		setSR(0x00);
		stepFrom(0x0000);
		assertEquals(0x08, getSR());
	}

	@Test
	public void CSA() {
		write(0x0000, 0x06);	// CSA
		setSR(0xAA);
		setAC(0x00);
		stepFrom(0x0000);
		assertEquals(0xAA, getSR());
		assertEquals(0xAA, getAC());
	}

	@Test
	public void CAS() {
		write(0x0000, 0x07);	// CAS
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
