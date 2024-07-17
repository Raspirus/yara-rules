import "pe"


rule SIGNATURE_BASE_SUSP_THOR_Unsigned_Oct23_1 : FILE
{
	meta:
		description = "Detects unsigned version of THOR scanner, which could be a backdoored / modified version of the scanner"
		author = "Florian Roth"
		id = "2ca6a192-675e-5f02-a7b1-40369eeb9904"
		date = "2023-10-28"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_unsigned_thor.yar#L4-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "12303e3549071dd6c8896f7a1222eb5905f6b4d3f320134416a5b6d53857adeb"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "THOR APT Scanner" wide fullword
		$s2 = "Nextron Systems GmbH" wide fullword
		$sc1 = { 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 74 00 68 00 6F 00 72 }

	condition:
		uint16(0)==0x5a4d and all of them and pe.number_of_signatures==0
}