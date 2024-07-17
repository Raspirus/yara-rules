
rule ELASTIC_Windows_Infostealer_Phemedronestealer_Bed8Ea8A : FILE MEMORY
{
	meta:
		description = "Detects Windows Infostealer Phemedronestealer (Windows.Infostealer.PhemedroneStealer)"
		author = "Elastic Security"
		id = "bed8ea8a-f2a3-4a51-ae57-4986da4d21aa"
		date = "2024-03-21"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Infostealer_PhemedroneStealer.yar#L1-L30"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "38279fdad25c7972be9426cadb5ad5e3ee7e9761b0a41ed617945cb9a3713702"
		logic_hash = "88fc33abfe6c7a611aa0c354645b06e9e74121ffc9a5acd20b4d3a59287489d6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "29702a2dc8b20c230ffef00dfff725133b707e35523e075ff85484a20da3c760"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "<KillDebuggers>b_"
		$a2 = "<Key3Database>b_"
		$a3 = "<IsVM>b_"
		$a4 = "<ParseDatWallets>b_"
		$a5 = "<ParseExtensions>b_"
		$a6 = "<ParseDiscordTokens>b_"
		$b1 = "Phemedrone.Senders"
		$b2 = "Phemedrone.Protections"
		$b3 = "Phemedrone.Extensions"
		$b4 = "Phemedrone.Cryptography"
		$b5 = "Phemedrone-Report.zip"
		$b6 = "Phemedrone Stealer Report"

	condition:
		all of ($a*) or all of ($b*)
}