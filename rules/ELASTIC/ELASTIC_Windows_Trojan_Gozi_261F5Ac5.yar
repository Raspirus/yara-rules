rule ELASTIC_Windows_Trojan_Gozi_261F5Ac5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Gozi (Windows.Trojan.Gozi)"
		author = "Elastic Security"
		id = "261f5ac5-7800-4580-ac37-80b71c47c270"
		date = "2019-08-02"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Gozi.yar#L34-L60"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "31835c6350177eff88265e81335a50fcbe0dc46771bf031c836947851dcebb4f"
		logic_hash = "23a7427e162e2f77ee0a281fe4bc54eab29a3bdca8e51015147e8eb223e7e2f7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cbc8fec8fbaa809cfc7da7db72aeda43d4270f907e675016cbbc2e28e7b8553c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x"
		$a2 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s"
		$a3 = "Content-Disposition: form-data; name=\"upload_file\"; filename=\"%.4u.%lu\""
		$a4 = "&tor=1"
		$a5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT %u.%u%s)"
		$a6 = "http://constitution.org/usdeclar.txt"
		$a7 = "grabs="
		$a8 = "CHROME.DLL"
		$a9 = "Software\\AppDataLow\\Software\\Microsoft\\"

	condition:
		4 of ($a*)
}