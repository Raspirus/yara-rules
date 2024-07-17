rule SIGNATURE_BASE_SUSP_Xored_Mozilla : FILE
{
	meta:
		description = "Detects suspicious single byte XORed keyword 'Mozilla/5.0' - it uses yara's XOR modifier and therefore cannot print the XOR key. You can use the CyberChef recipe linked in the reference field to brute force the used key."
		author = "Florian Roth"
		id = "af7fc551-0d4e-589e-9152-95d9c4ab03bf"
		date = "2019-10-28"
		modified = "2023-11-25"
		reference = "https://gchq.github.io/CyberChef/#recipe=XOR_Brute_Force()"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_xor_hunting.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e1686e704c47391ee190f59d09bc2a5f633bb6589f671ecc5431f733c9ae0dba"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$xo1 = "Mozilla/5.0" xor(0x01-0xff) ascii wide
		$fp1 = "Sentinel Labs" wide
		$fp2 = "<filter object at" ascii

	condition:
		$xo1 and not 1 of ($fp*) and not uint32(0)==0x434d5953
}