
rule ELASTIC_Linux_Ransomware_Blackbasta_96Eb3F20 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Blackbasta (Linux.Ransomware.BlackBasta)"
		author = "Elastic Security"
		id = "96eb3f20-9c40-4d40-8a6c-568a51c52d4d"
		date = "2022-08-06"
		modified = "2022-08-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_BlackBasta.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "96339a7e87ffce6ced247feb9b4cb7c05b83ca315976a9522155bad726b8e5be"
		logic_hash = "a5e0b60ba51490f70af53c9fba91e3349c712bebb10574eb4bed028ab961ae74"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5146ad9def7ccaba4b4896f345b0950c587ad5f96a106ec461caeb028d809ead"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "Done time: %.4f seconds, encrypted: %.4f gb" ascii fullword
		$a2 = "Your data are stolen and encrypted" ascii fullword
		$a3 = "fileEncryptionPercent" ascii fullword
		$a4 = "fileQueueLocker" ascii fullword
		$a5 = "totalBytesEncrypted" ascii fullword
		$seq_encrypt_block = { 41 56 31 D2 41 55 41 54 49 89 FE 55 53 48 89 F5 49 63 D8 4C }
		$seq_encrypt_thread = { 4C 8B 74 24 ?? 31 DB 45 31 FF 4D 8B 6E ?? 49 83 FD ?? 0F 87 ?? ?? ?? ?? 31 C0 4D 39 EF 0F 82 ?? ?? ?? ?? 48 01 C3 4C 39 EB 0F 83 ?? ?? ?? ?? }

	condition:
		3 of ($a*) and 1 of ($seq*)
}