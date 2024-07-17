import "math"


rule SIGNATURE_BASE_WEBSHELL_Cookie_Post_Obfuscation : FILE
{
	meta:
		description = "Detects webshell using cookie POST"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "cc5ded80-5e58-5b25-86d1-1c492042c740"
		date = "2023-01-28"
		modified = "2023-04-05"
		reference = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_webshells.yar#L6861-L6887"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "d08a00e56feb78b7f6599bad6b9b1d8626ce9a6ea1dfdc038358f4c74e6f65c9"
		hash = "2ce5c4d31682a5a59b665905a6f698c280451117e4aa3aee11523472688edb31"
		hash = "ff732d91a93dfd1612aed24bbb4d13edb0ab224d874f622943aaeeed4356c662"
		hash = "a3b64e9e065602d2863fcab641c75f5d8ec67c8632db0f78ca33ded0f4cea257"
		hash = "d41abce305b0dc9bd3a9feb0b6b35e8e39db9e75efb055d0b1205a9f0c89128e"
		hash = "333560bdc876fb0186fae97a58c27dd68123be875d510f46098fc5a61615f124"
		hash = "2efdb79cdde9396ff3dd567db8876607577718db692adf641f595626ef64d3a4"
		hash = "e1bd3be0cf525a0d61bf8c18e3ffaf3330c1c27c861aede486fd0f1b6930f69a"
		hash = "f8cdedd21b2cc29497896ec5b6e5863cd67cc1a798d929fd32cdbb654a69168a"
		logic_hash = "87229859ca3ee8f8b79360603c421528cda2ecefcc46d4080236d09b2dd510fb"
		score = 75
		quality = 85
		tags = "FILE"
		importance = 70

	strings:
		$s1 = "]($_COOKIE, $_POST) as $"
		$s2 = "function"
		$s3 = "Array"

	condition:
		( uint16(0)==0x3f3c and filesize <100KB and ( all of them ))
}