
rule ELASTIC_Macos_Backdoor_Useragent_1A02Fc3A : FILE MEMORY
{
	meta:
		description = "Detects Macos Backdoor Useragent (MacOS.Backdoor.Useragent)"
		author = "Elastic Security"
		id = "1a02fc3a-a394-457b-8af5-99f7f22b0a3b"
		date = "2021-11-11"
		modified = "2022-07-22"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Backdoor_Useragent.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
		logic_hash = "90debdfc24ef100952302808a2e418bca2a46be3e505add9a0ccf4c49aff5102"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "22afa14a3dc6f8053b93bf3e971d57808a9cc19e676f9ed358ba5f1db9292ba4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$s1 = "/Library/LaunchAgents/com.UserAgent.va.plist"
		$s2 = "this is not root"
		$s3 = "rm -Rf "
		$s4 = "/start.sh"
		$s5 = ".killchecker_"

	condition:
		4 of them
}