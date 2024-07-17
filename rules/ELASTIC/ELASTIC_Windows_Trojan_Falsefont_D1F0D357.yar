
rule ELASTIC_Windows_Trojan_Falsefont_D1F0D357 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Falsefont (Windows.Trojan.FalseFont)"
		author = "Elastic Security"
		id = "d1f0d357-26cb-4dab-8ca6-65f17109982b"
		date = "2024-03-26"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_FalseFont.yar#L1-L26"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "364275326bbfc4a3b89233dabdaf3230a3d149ab774678342a40644ad9f8d614"
		logic_hash = "af356dec77f773cec01626a3823dbea7e9d3719b9d152ec4057c0b97efabf0df"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ad63447832e9a160d479fccd780de89b9c29b9697f69ac3553e39bc388d49b83"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$s1 = "KillById"
		$s2 = "KillByName"
		$s3 = "SignalRHub"
		$s4 = "ExecUseShell"
		$s5 = "ExecAndKeepAlive"
		$s6 = "SendAllDirectoryWithStartPath"
		$s7 = "AppLiveDirectorySendHard"
		$s8 = "AppLiveDirectorySendScreen"

	condition:
		4 of them
}