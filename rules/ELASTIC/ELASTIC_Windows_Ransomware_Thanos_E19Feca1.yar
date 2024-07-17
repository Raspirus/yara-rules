
rule ELASTIC_Windows_Ransomware_Thanos_E19Feca1 : BETA FILE MEMORY
{
	meta:
		description = "Identifies THANOS (Hakbit) ransomware"
		author = "Elastic Security"
		id = "e19feca1-b131-4045-be0c-d69d55f9a83e"
		date = "2020-11-03"
		modified = "2021-08-23"
		reference = "https://labs.sentinelone.com/thanos-ransomware-riplace-bootlocker-and-more-added-to-feature-set/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Thanos.yar#L46-L77"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "1f5a69b6749e887a5576843abb83388d5364e47601cf11fcac594008ace8e973"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "d6654d0b3155d9c64fd4e599ba34d51f110d9dfda6fa1520b686602d9f608f92"
		threat_name = "Windows.Ransomware.Thanos"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "<GetIPInfo>b__"
		$a2 = "<Killproc>b__"
		$a3 = "<Crypt>b__"
		$a4 = "<Encrypt2>b__"
		$b1 = "Your files are encrypted."
		$b2 = "I will treat you good if you treat me good too."
		$b3 = "I don't want to loose your files too"
		$b4 = "/c rd /s /q %SYSTEMDRIVE%\\$Recycle.bin" wide fullword
		$b5 = "\\HOW_TO_DECYPHER_FILES.txt" wide fullword
		$b6 = "c3RvcCBTUUxURUxFTUVUUlkkRUNXREIyIC95" wide fullword
		$b7 = "c3RvcCBNQkFNU2VydmljZSAveQ==" wide fullword
		$b8 = "L0MgY2hvaWNlIC9DIFkgL04gL0QgWSAvVCAzICYgRGVsIA==" wide fullword
		$b9 = "c3RvcCBjY0V2dE1nciAveQ==" wide fullword

	condition:
		(4 of ($a*)) or (3 of ($b*))
}