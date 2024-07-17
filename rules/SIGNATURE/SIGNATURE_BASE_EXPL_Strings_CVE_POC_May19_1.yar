rule SIGNATURE_BASE_EXPL_Strings_CVE_POC_May19_1 : FILE
{
	meta:
		description = "Detects strings used in CVE POC noticed in May 2019"
		author = "Florian Roth (Nextron Systems)"
		id = "df11e0b1-e907-5a24-a3e7-0e78acb379f7"
		date = "2019-05-31"
		modified = "2023-12-05"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_nansh0u.yar#L120-L136"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b470e9f5716130d810e519abb8d4e1058b5a806d59ddae53a40cac5597fbb874"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "01c3882e8141a25abe37bb826ab115c52fd3d109c4a1b898c0c78cee8dac94b4"

	strings:
		$x1 = "\\Debug\\poc_cve_20" ascii
		$x2 = "\\Release\\poc_cve_20" ascii
		$x3 = "alloc fake fail: %x!" fullword ascii
		$x4 = "Allocate fake tagWnd fail!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 1 of them
}