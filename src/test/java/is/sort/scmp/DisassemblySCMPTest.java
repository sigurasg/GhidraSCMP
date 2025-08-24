// Copyright 2024 Sigurdur Asgeirsson <siggi@sort.is>
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
	public void LD() {		
		test(0xC0, "LD 0x0E",0x0E);
	}

	protected void test(int opCode, String expected, int... args) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();

		stream.write(opCode);
		for (int arg : args) {
			stream.write(arg);
		}

		byte[] bytes = stream.toByteArray();
		CodeUnit codeUnit = disassemble(bytes);
		assertTrue(codeUnit instanceof Instruction);
		assertNotNull(codeUnit);

		System.err.println(codeUnit.toString());

		assertEquals(expected, codeUnit.toString());
		assertEquals(bytes.length, codeUnit.getLength());
	}
}
