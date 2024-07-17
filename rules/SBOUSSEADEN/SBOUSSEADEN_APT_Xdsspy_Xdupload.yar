
rule SBOUSSEADEN_APT_Xdsspy_Xdupload : FILE
{
	meta:
		description = "No description has been set in the source file - SBousseaden"
		author = "SBousseaden"
		id = "ae38d017-6420-596c-af29-62f15cfe56b8"
		date = "2020-05-10"
		modified = "2020-10-05"
		reference = "https://www.welivesecurity.com/2020/10/02/xdspy-stealing-government-secrets-since-2011/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/apt_xdspy_xdupload.yara#L1-L11"
		license_url = "N/A"
		logic_hash = "648ea81d1b44d8514439683cf2f86a8027f9e1eb64abf76d42347fc2ce9c4e68"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "cmd.exe /u /c cd /d \"%s\" & dir /a /-c" wide
		$s2 = "commandC_dll.dll"
		$s3 = "cmd.exe /u /c del" wide

	condition:
		uint16(0)==0x5a4d and 2 of ($s*)
}