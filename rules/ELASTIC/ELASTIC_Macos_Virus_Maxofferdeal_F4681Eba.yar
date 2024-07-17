
rule ELASTIC_Macos_Virus_Maxofferdeal_F4681Eba : FILE MEMORY
{
	meta:
		description = "Detects Macos Virus Maxofferdeal (MacOS.Virus.Maxofferdeal)"
		author = "Elastic Security"
		id = "f4681eba-20f5-4e92-9f99-00cd57412c45"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Virus_Maxofferdeal.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ecd62ef880da057726ca55c6826ce4e1584ec6fc3afaabed7f66154fc39ffef8"
		logic_hash = "cf478ec5313b40d74d110e4d6e97da5f671d5af331adc3ab059a69616e78c76c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b6663c326e9504510b804bd9ff0e8ace5d98826af2bb2fa2429b37171b7f399d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { BA A4 C8 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 AC AD AE A9 BD A4 BC 97 }

	condition:
		all of them
}