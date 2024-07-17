
rule ELASTIC_Windows_Generic_Threat_3F390999 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "3f390999-601f-464e-8982-09553adee303"
		date = "2024-03-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3184-L3202"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1b6fc4eaef3515058f85551e7e5dffb68b9a0550cd7f9ebcbac158dac9ababf1"
		logic_hash = "462a7a38ebbb39515ac2c0a10353660d0cadcfb99360adcd200edc1db5a716ba"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ccfd5fb305ea48d66f299311c5332587355258bdeeb25cb90c450e8e96df3052"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 10 48 89 D9 48 8B 59 10 FF 61 08 0F 1F 40 00 49 89 CB C3 49 89 CA 41 8B 43 08 41 FF 23 C3 90 48 C1 E1 04 31 C0 81 E1 F0 0F 00 00 49 01 C8 4C 8D 0C 02 4E 8D 14 00 31 C9 45 8A 1C 0A 48 }

	condition:
		all of them
}