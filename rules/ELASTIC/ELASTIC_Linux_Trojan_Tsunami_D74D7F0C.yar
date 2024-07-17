
rule ELASTIC_Linux_Trojan_Tsunami_D74D7F0C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "d74d7f0c-70f8-4dd7-aaf4-fd5ab94bb8b2"
		date = "2021-12-13"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L480-L498"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b0a8b2259c00d563aa387d7e1a1f1527405da19bf4741053f5822071699795e2"
		logic_hash = "6f5313fc9e838bd06bd4e797ea7fb448073849dc714ecf18809f94900fa11ca2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0a175d0ff64186d35b64277381f47dfafe559a42a3296a162a951f1b2add1344"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 20 79 6F 2C 0A 59 6A 02 5B 6A 04 58 CD 80 B3 7F 6A 01 58 CD }

	condition:
		all of them
}