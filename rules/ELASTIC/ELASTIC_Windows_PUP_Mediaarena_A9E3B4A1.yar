rule ELASTIC_Windows_PUP_Mediaarena_A9E3B4A1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Pup Mediaarena (Windows.PUP.MediaArena)"
		author = "Elastic Security"
		id = "a9e3b4a1-fd87-4f8f-a9d4-d93f9c018270"
		date = "2023-06-02"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_PUP_MediaArena.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c071e0b67e4c105c87b876183900f97a4e8bc1a7c18e61c028dee59ce690b1ac"
		logic_hash = "8e52b29f2848498aae2fd7ad35494362d6c07f0e752b628840a256923aca32c7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0535228889b1d2a7c317a7ce939621d3d20e2a454ec6d31915c25884931d62b9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Going to change default browser to be MS Edge ..." wide
		$a2 = "https://www.searcharchiver.com/eula" wide
		$a3 = "Current default browser is unchanged!" wide
		$a4 = "You can terminate your use of the Search Technology and Search Technology services"
		$a5 = "The software may also offer to change your current web navigation access points"
		$a6 = "{{BRAND_NAME}} may have various version compatible with different platform,"
		$a7 = "{{BRAND_NAME}} is a powerful search tool" wide

	condition:
		2 of them
}