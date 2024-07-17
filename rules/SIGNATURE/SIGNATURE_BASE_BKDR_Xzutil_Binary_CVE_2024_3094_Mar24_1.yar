rule SIGNATURE_BASE_BKDR_Xzutil_Binary_CVE_2024_3094_Mar24_1 : CVE_2024_3094 FILE
{
	meta:
		description = "Detects injected code used by the backdoored XZ library (xzutil) CVE-2024-3094."
		author = "Florian Roth"
		id = "6ccdeb6d-67c4-5358-a76b-aef7f047c997"
		date = "2024-03-30"
		modified = "2024-04-24"
		reference = "https://www.openwall.com/lists/oss-security/2024/03/29/4"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/bkdr_xz_util_cve_2024_3094.yar#L19-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ed364484ff598b0818f9b3249673e684b52394c25b14e47fbca25a5f96ecc970"
		score = 75
		quality = 85
		tags = "CVE-2024-3094, FILE"
		hash1 = "319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae"
		hash2 = "605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4"
		hash3 = "8fa641c454c3e0f76de73b7cc3446096b9c8b9d33d406d38b8ac76090b0344fd"
		hash4 = "b418bfd34aa246b2e7b5cb5d263a640e5d080810f767370c4d2c24662a274963"
		hash5 = "cbeef92e67bf41ca9c015557d81f39adaba67ca9fb3574139754999030b83537"
		hash6 = "5448850cdc3a7ae41ff53b433c2adbd0ff492515012412ee63a40d2685db3049"

	strings:
		$op1 = { 48 8d 7c 24 08 f3 ab 48 8d 44 24 08 48 89 d1 4c 89 c7 48 89 c2 e8 ?? ?? ?? ?? 89 c2 }
		$op2 = { 31 c0 49 89 ff b9 16 00 00 00 4d 89 c5 48 8d 7c 24 48 4d 89 ce f3 ab 48 8d 44 24 48 }
		$op3 = { 4d 8b 6c 24 08 45 8b 3c 24 4c 8b 63 10 89 85 78 f1 ff ff 31 c0 83 bd 78 f1 ff ff 00 f3 ab 79 07 }
		$xc1 = { F3 0F 1E FA 55 48 89 F5 4C 89 CE 53 89 FB 81 E7 00 00 00 80 48 83 EC 28 48 89 54 24 18 48 89 4C 24 10 }

	condition:
		uint16(0)==0x457f and ( all of ($op*) or $xc1)
}