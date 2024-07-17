rule SIGNATURE_BASE_SUSP_Email_Suspicious_Onenote_Attachment_Jan23_1 : FILE
{
	meta:
		description = "Detects suspicious OneNote attachment that embeds suspicious payload, e.g. an executable (FPs possible if the PE is attached separately)"
		author = "Florian Roth (Nextron Systems)"
		id = "492b74c2-3b81-5dff-9244-8528565338c6"
		date = "2023-01-27"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_onenote_phish.yar#L2-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c7c5fc86f1dbe54da2d3ff8f039c5e53c3d1f67c9271cb467b2318310f744f93"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$ge1 = "5xbjvWUmEUWkxI1NC3qer"
		$ge2 = "cW471lJhFFpMSNTQt6nq"
		$ge3 = "nFuO9ZSYRRaTEjU0Lep6s"
		$sp1 = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZG"
		$sp2 = "RoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2Rl"
		$sp3 = "UaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZ"
		$sp4 = "VGhpcyBwcm9ncmFtIG11c3QgYmUgcnVuIHVuZGVy"
		$sp5 = "RoaXMgcHJvZ3JhbSBtdXN0IGJlIHJ1biB1bmRlc"
		$sp6 = "UaGlzIHByb2dyYW0gbXVzdCBiZSBydW4gdW5kZX"
		$se1 = "QGVjaG8gb2Zm"
		$se2 = "BlY2hvIG9mZ"
		$se3 = "AZWNobyBvZm"
		$se4 = "PEhUQTpBUFBMSUNBVElPTi"
		$se5 = "xIVEE6QVBQTElDQVRJT04g"
		$se6 = "8SFRBOkFQUExJQ0FUSU9OI"
		$se7 = "TAAAAAEUAg"
		$se8 = "wAAAABFAIA"
		$se9 = "MAAAAARQCA"

	condition:
		filesize <5MB and 1 of ($ge*) and 1 of ($s*)
}