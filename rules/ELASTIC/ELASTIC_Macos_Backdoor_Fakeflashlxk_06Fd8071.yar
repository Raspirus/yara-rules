rule ELASTIC_Macos_Backdoor_Fakeflashlxk_06Fd8071 : FILE MEMORY
{
	meta:
		description = "Detects Macos Backdoor Fakeflashlxk (MacOS.Backdoor.Fakeflashlxk)"
		author = "Elastic Security"
		id = "06fd8071-0370-4ae8-819a-846fa0a79b3d"
		date = "2021-11-11"
		modified = "2022-07-22"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Backdoor_Fakeflashlxk.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "107f844f19e638866d8249e6f735daf650168a48a322d39e39d5e36cfc1c8659"
		logic_hash = "853d44465a472786bb48bbe1009e0ff925f79e4fd72f0eac537dd271c1ec3703"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a0e6763428616b46536c6a4eb080bae0cc58ef27678616aa432eb43a3d9c77a1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$s1 = "/Users/lxk/Library/Developer/Xcode/DerivedData"
		$s2 = "Desktop/SafariFlashActivity/SafariFlashActivity/SafariFlashActivity/"
		$s3 = "/Debug/SafariFlashActivity.build/Objects-normal/x86_64/AppDelegate.o"

	condition:
		2 of them
}