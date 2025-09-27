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

public class SR {
  public static final int CYL = 0x80; // CY/L: Carry/Link
  public static final int OV = 0x40;  // OV: Overflow
  public static final int SB = 0x20;  // SB: Sense Bit B
  public static final int SA = 0x10;  // SA: Sense Bit A`
  public static final int IE = 0x08;  // IE: Interrupt Enable
  public static final int F2 = 0x04;  // F2: User Flag 2
  public static final int F1 = 0x02;  // F1: User Flag 1
  public static final int F0 = 0x01;  // F0: User Flag 0
}
