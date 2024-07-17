rule TRELLIX_ARC_Ransom_Note_Kraken_Cryptor_Ransomware : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect the ransom note delivered by Kraken Cryptor Ransomware"
		author = "Marc Rivero | McAfee ATR Team"
		id = "dec9d364-daf9-5a1d-8e72-ed4dd2aeecdf"
		date = "2018-09-30"
		modified = "2020-08-14"
		reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Kraken.yar#L66-L108"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "d4acdf0716320b0f757b8dbc97bb9d407460b2d69dc8e12292539e823be0f57d"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Kraken"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$s1 = "No way to recovery your files without \"KRAKEN DECRYPTOR\" software and your computer \"UNIQUE KEY\"!" fullword ascii
		$s2 = "Are you want to decrypt all of your encrypted files? If yes! You need to pay for decryption service to us!" fullword ascii
		$s3 = "The speed, power and complexity of this encryption have been high and if you are now viewing this guide." fullword ascii
		$s4 = "Project \"KRAKEN CRYPTOR\" doesn't damage any of your files, this action is reversible if you follow the instructions above." fullword ascii
		$s5 = "https://localBitcoins.com" fullword ascii
		$s6 = "For the decryption service, we also need your \"KRAKEN ENCRYPTED UNIQUE KEY\" you can see this in the top!" fullword ascii
		$s7 = "-----BEGIN KRAKEN ENCRYPTED UNIQUE KEY----- " fullword ascii
		$s8 = "All your files has been encrypted by \"KRAKEN CRYPTOR\"." fullword ascii
		$s9 = "It means that \"KRAKEN CRYPTOR\" immediately removed form your system!" fullword ascii
		$s10 = "After your payment made, all of your encrypted files has been decrypted." fullword ascii
		$s11 = "Don't delete .XKHVE files! there are not virus and are your files, but encrypted!" fullword ascii
		$s12 = "You can decrypt one of your encrypted smaller file for free in the first contact with us." fullword ascii
		$s13 = "You must register on this site and click \"BUY Bitcoins\" then choose your country to find sellers and their prices." fullword ascii
		$s14 = "-----END KRAKEN ENCRYPTED UNIQUE KEY-----" fullword ascii
		$s15 = "DON'T MODIFY \"KRAKEN ENCRYPT UNIQUE KEY\"." fullword ascii
		$s16 = "# Read the following instructions carefully to decrypt your files." fullword ascii
		$s17 = "We use best and easy way to communications. It's email support, you can see our emails below." fullword ascii
		$s18 = "DON'T USE THIRD PARTY, PUBLIC TOOLS/SOFTWARE TO DECRYPT YOUR FILES, THIS CAUSE DAMAGE YOUR FILES PERMANENTLY." fullword ascii
		$s19 = "https://en.wikipedia.org/wiki/Bitcoin" fullword ascii
		$s20 = "Please send your message with same subject to both address." fullword ascii

	condition:
		uint16(0)==0x4120 and filesize <9KB and all of them
}