rule ELASTIC_Windows_Trojan_Caesarkbd_32Bb198B : FILE
{
	meta:
		description = "Detects Windows Trojan Caesarkbd (Windows.Trojan.CaesarKbd)"
		author = "Elastic Security"
		id = "32bb198b-ec03-4628-8e9b-bc36c2525ec7"
		date = "2022-04-04"
		modified = "2022-06-09"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CaesarKbd.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d4335f4189240a3bcafa05fab01f0707cc8e3dd7a2998af734c24916d9e37ca8"
		logic_hash = "f708706524515f98ebf612ac98318ee7172347096251d9ccd723f439070521de"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "54ed92761bb619ae4dcec9c27127d6c2a74a575916249cd5db24b8deb2ee0588"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "CaesarKbd_IOCtrl"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}