import "pe"


rule EMBEERESEARCH_Win_Remcos_Rat_Unpacked : FILE
{
	meta:
		description = "Detects strings present in remcos rat Samples."
		author = "Matthew @ Embee_Research"
		id = "d4282638-592a-5c07-b07b-937e2a7879e4"
		date = "2023-08-27"
		modified = "2023-10-18"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_remcos_rat_unpacked_aug_2023.yar#L2-L32"
		license_url = "N/A"
		hash = "ec901217558e77f2f449031a6a1190b1e99b30fa1bb8d8dabc3a99bc69833784"
		logic_hash = "c6d1772a5517b104de3022f4bab55d92784d35c3a252a4e0516083d8bd28cad0"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$r0 = " ______                              " ascii
		$r1 = "(_____ \\                             " ascii
		$r2 = " _____) )_____ ____   ____ ___   ___ " ascii
		$r3 = "|  __  /| ___ |    \\ / ___) _ \\ /___)" ascii
		$r4 = "| |  \\ \\| ____| | | ( (__| |_| |___ |" ascii
		$r5 = "|_|   |_|_____)_|_|_|\\____)___/(___/ " ascii
		$s1 = "Watchdog module activated" ascii
		$s2 = "Remcos restarted by watchdog!" ascii
		$s3 = " BreakingSecurity.net" ascii

	condition:
		(( all of ($r*)) or ( all of ($s*)))
}