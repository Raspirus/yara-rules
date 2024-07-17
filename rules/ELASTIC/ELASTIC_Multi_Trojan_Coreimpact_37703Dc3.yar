
rule ELASTIC_Multi_Trojan_Coreimpact_37703Dc3 : FILE MEMORY
{
	meta:
		description = "Detects Multi Trojan Coreimpact (Multi.Trojan.Coreimpact)"
		author = "Elastic Security"
		id = "37703dc3-9485-4026-a8b7-82e753993757"
		date = "2022-08-10"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Multi_Trojan_Coreimpact.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2d954908da9f63cd3942c0df2e8bb5fe861ac5a336ddef2bd0a977cebe030ad7"
		logic_hash = "0695f22d6eb8c1b335c43213087539db419562bebd6f5b948cbb168c454bd37c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5a4d7af7d0fecc05f87ba51f976d78e77622f8afb1eafc175444f45839490109"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$str1 = "Uh, oh, exit() failed" fullword
		$str2 = "agent_recv" fullword
		$str3 = "needroot" fullword
		$str4 = "time is running backwards, corrected" fullword
		$str5 = "junk pointer, too low to make sense" fullword

	condition:
		3 of them
}