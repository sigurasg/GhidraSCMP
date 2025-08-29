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
		setP1(0x1000);
		stepFrom(PC);
		assertEquals(0x1010, getP1());
		assertEquals(0xAA, readByte(0x1000));

		setAC(0x00);
		step();
		assertEquals(0x1000, getP1());
		assertEquals(0xAA, getAC());

		step();
		assertEquals(0x1FF0, getP1());
		assertEquals(0xAA, readByte(0x1FF0));

		setAC(0x00);
		step();
		step();
		assertEquals(0x1000, getP1());
		assertEquals(0xAA, getAC());
	}

	@Test
	public void NOP() {
		setAC(0x00);
		setSR(0x00);
		setE(0x00);
		setP1(0x0010);
		setP2(0x0020);
		setP3(0x0030);

		write(0x0000, 0x00);
		stepFrom(0x000);

		assertEquals(0x00, getAC());
		assertEquals(0x00, getSR());
		assertEquals(0x00, getE());
		assertEquals(0x0010, getP1());
		assertEquals(0x0020, getP2());
		assertEquals(0x0030, getP3());
		assertEquals(0X0001, getPC());
	}

	@Test
	public void LD_PCRel() {
		final int PC = 0x8100;
		write(PC, 0xC0, 0x10);
		write(0x8112, 0xFF);
		stepFrom(PC);
		assertEquals(getAC(), 0xFF);
	}

	@Test
	public void JMP_PCRel() {
		final int PC = 0x8100;
		// PC-relative JMP.
		write(PC, 0x90, 0x10, 0x90, 0xFF);
		stepFrom(PC);
		assertEquals(PC + 0x12, getPC());

		stepFrom(PC + 2);
		assertEquals(PC + 0x03, getPC());
	}

	@Test
	public void JMP_P1Rel() {
		// P1-relative JMP.
		setP1(0x0200);
		write(0x0100, 0x91, 0x12);
		stepFrom(0x0100);
		assertEquals(0x0212, getPC());
	}

	@Test
	public void JP() {
		write(0x100, 0x94, 0x10);

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
		write(0x100, 0x98, 0x10);

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
		write(0x100, 0x9C, 0x10);

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
	public void XPAL() {
		write(0x100, 0x31);  // XPAL P1.

		setAC(0x01);
		setP1(0x0203);
		stepFrom(0x100);

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

		assertEquals(0x0204, getPC());
		assertEquals(0x0100, getP1());

	}
}
