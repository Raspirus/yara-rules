import "pe"


rule SIGNATURE_BASE_APT_MAL_NK_3CX_Macos_Elextron_App_Mar23_1 : FILE
{
	meta:
		description = "Detects macOS malware used in the 3CX incident"
		author = "Florian Roth (Nextron Systems)"
		id = "7a3755d4-37e5-5d3b-93aa-34edb557f2d5"
		date = "2023-03-31"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_mal_3cx_compromise_mar23.yar#L306-L328"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "00dd28c3edd94e04e35ee9e3a43c30b5a0a1ad21ec8ecf2099bbeb9de2fca8d0"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "51079c7e549cbad25429ff98b6d6ca02dc9234e466dd9b75a5e05b9d7b95af72"
		hash2 = "f7ba7f9bf608128894196cf7314f68b78d2a6df10718c8e0cd64dbe3b86bc730"

	strings:
		$a1 = "com.apple.security.cs.allow-unsigned-executable-memory" ascii
		$a2 = "com.electron.3cx-desktop-app" ascii fullword
		$s1 = "s8T/RXMlALbXfowom9qk15FgtdI=" ascii
		$s2 = "o8NQKPJE6voVZUIGtXihq7lp0cY=" ascii

	condition:
		uint16(0)==0xfacf and filesize <400KB and ( all of ($a*) and 1 of ($s*))
}