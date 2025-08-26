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
	public void NOP() {
		setAC(0x00);
		setSR(0x00);
		setE(0x00);
		setP1(0x0010);
		setP2(0x0020);
		setP3(0x0030);

		write(0x0000, 0x00);
		stepFrom(0x000);

		assertEquals(getAC(), 0x00);
		assertEquals(getSR(), 0x00);
		assertEquals(getE(), 0x00);
		assertEquals(getP1(), 0x0010);
		assertEquals(getP2(), 0x0020);
		assertEquals(getP3(), 0x0030);
		assertEquals(getPC(), 0X0001);
	}

	@Test
	public void LD_PCRel() {
		int PC = 0x8100;
		write(PC, 0xC0, 0x10);
		write(0x8112, 0xFF);
		stepFrom(PC);
		assertEquals(0xFF, getAC());
	}

	@Test
	public void JMP_PCRel() {
		int PC = 0x8100;
		// PC-relative JMP.
		write(PC, 0x90, 0x10, 0x90, 0xFF);
		stepFrom(PC);
		assertEquals(getPC(), PC + 0x12);

		PC += 2;
		stepFrom(PC);
		assertEquals(getPC(), PC + 0x01);
	}


	public void JMP_P1Rel() {
		// P1-relative JMP.
		setP1(0x0200);
		write(0x0100, 0x91, 0x12);
		stepFrom(0x0100);
		assertEquals(getPC(), 0x0212);
	}

	public void JP() {
		write(0x100, 0x94, 0x10);

		// Test zero.
		setAC(0x00);
		stepFrom(0x0100);
		assertEquals(getPC(), 0x0112);

		// Test positive
		setAC(0x7F);
		stepFrom(0x0100);
		assertEquals(getPC(), 0x0112);

		// Test negative.
		setAC(0x81);
		stepFrom(0x0100);
		assertEquals(getPC(), 0x0102);
	}

	public void JZ() {
		write(0x100, 0x98, 0x10);

		// Test zero.
		setAC(0x00);
		stepFrom(0x0100);
		assertEquals(getPC(), 0x0112);

		// Test positive
		setAC(0x7F);
		stepFrom(0x0100);
		assertEquals(getPC(), 0x0102);

		// Test negative.
		setAC(0x81);
		stepFrom(0x0100);
		assertEquals(getPC(), 0x0102);
	}

	public void JNZ() {
		write(0x100, 0x98, 0x10);

		// Test zero.
		setAC(0x00);
		stepFrom(0x0100);
		assertEquals(getPC(), 0x0102);

		// Test positive
		setAC(0x7F);
		stepFrom(0x0100);
		assertEquals(getPC(), 0x0112);

		// Test negative.
		setAC(0x81);
		stepFrom(0x0100);
		assertEquals(getPC(), 0x0112);
	}
}
