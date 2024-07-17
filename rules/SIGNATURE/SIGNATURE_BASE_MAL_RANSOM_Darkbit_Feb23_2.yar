
rule SIGNATURE_BASE_MAL_RANSOM_Darkbit_Feb23_2 : FILE
{
	meta:
		description = "Detects Go based DarkBit ransomware (garbled code; could trigger on other obfuscated samples, too)"
		author = "Florian Roth"
		id = "f530815c-68e7-55f1-8e36-bc74a1059584"
		date = "2023-02-13"
		modified = "2023-12-05"
		reference = "https://www.hybrid-analysis.com/sample/9107be160f7b639d68fe3670de58ed254d81de6aec9a41ad58d91aa814a247ff?environmentId=160"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ransom_darkbit_feb23.yar#L25-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "577435536300902811612a3415e82420574c98345b91b21fb2bfd2bfde396bec"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "9107be160f7b639d68fe3670de58ed254d81de6aec9a41ad58d91aa814a247ff"

	strings:
		$s1 = "runtime.initLongPathSupport" ascii fullword
		$s2 = "reflect." ascii
		$s3 = "    \"processes\": []," ascii fullword
		$s4 = "^!* %!(!" ascii fullword
		$op1 = { 4d 8b b6 00 00 00 00 48 8b 94 24 40 05 00 00 31 c0 87 82 30 03 00 00 b8 01 00 00 00 f0 0f c1 82 00 03 00 00 48 8b 44 24 48 48 8b 0d ba 1f 32 00 }
		$op2 = { 49 8d 49 01 0f 1f 00 48 39 d9 7c e2 b9 0b 00 00 00 49 89 d8 e9 28 fc ff ff e8 89 6c d7 ff }

	condition:
		uint16(0)==0x5a4d and filesize <20000KB and all of them
}