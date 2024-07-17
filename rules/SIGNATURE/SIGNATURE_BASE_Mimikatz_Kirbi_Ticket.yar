rule SIGNATURE_BASE_Mimikatz_Kirbi_Ticket : FILE
{
	meta:
		description = "KiRBi ticket for mimikatz"
		author = "Benjamin DELPY (gentilkiwi); Didier Stevens"
		id = "a37249e0-ab3b-50c2-9473-1e69185713cc"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_kirbi_mimkatz.yar#L10-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2a62c24954d64346e419985ef5bf2b357b2aee41ac6b33d379dbd65cf5c9f92b"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$asn1 = { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }
		$asn1_84 = { 76 84 ?? ?? ?? ?? 30 84 ?? ?? ?? ?? a0 84 00 00 00 03 02 01 05 a1 84 00 00 00 03 02 01 16 }

	condition:
		$asn1 at 0 or $asn1_84 at 0
}