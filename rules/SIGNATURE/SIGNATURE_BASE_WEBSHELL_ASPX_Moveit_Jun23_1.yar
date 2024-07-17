rule SIGNATURE_BASE_WEBSHELL_ASPX_Moveit_Jun23_1 : FILE
{
	meta:
		description = "Detects ASPX web shells as being used in MOVEit Transfer exploitation"
		author = "Florian Roth"
		id = "2c789b9c-5ec5-5fd1-84e3-6bf7735a9488"
		date = "2023-06-01"
		modified = "2023-12-05"
		reference = "https://www.rapid7.com/blog/post/2023/06/01/rapid7-observed-exploitation-of-critical-moveit-transfer-vulnerability/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vuln_moveit_0day_jun23.yar#L24-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "436f9a503ad938541faa8f34604310ba6d932e40a41dc189ccd293b7191a7621"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "2413b5d0750c23b07999ec33a5b4930be224b661aaf290a0118db803f31acbc5"
		hash2 = "48367d94ccb4411f15d7ef9c455c92125f3ad812f2363c4d2e949ce1b615429a"
		hash3 = "e8012a15b6f6b404a33f293205b602ece486d01337b8b3ec331cd99ccadb562e"

	strings:
		$s1 = "X-siLock-Comment" ascii fullword
		$s2 = "]; string x = null;" ascii
		$s3 = ";  if (!String.Equals(pass, " ascii

	condition:
		filesize <150KB and 2 of them
}