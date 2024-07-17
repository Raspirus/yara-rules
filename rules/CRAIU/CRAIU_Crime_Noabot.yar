rule CRAIU_Crime_Noabot : FILE
{
	meta:
		description = "Noabot is a clone of Mirai"
		author = "Costin G. Raiu, Art of Noh, craiu@noh.ro"
		id = "8626783b-898c-587d-9b23-c8c9111cde66"
		date = "2024-01-11"
		modified = "2024-01-11"
		reference = "https://www.akamai.com/blog/security-research/mirai-based-noabot-crypto-mining"
		source_url = "https://github.com/craiu/yararules/blob/68bc7e129467d2c027f06918f28c3196e5c684a1/files/crime_noabot.yara#L2-L57"
		license_url = "https://github.com/craiu/yararules/blob/68bc7e129467d2c027f06918f28c3196e5c684a1/LICENSE"
		hash = "1603202a9115b83224233697f2ca1d36fef60113b94a73a15afed79a459aacc3"
		hash = "16a28951acfe78b81046bfedb0b489efb4c9d3d1d3b8475c39b93cd5105dc866"
		hash = "3da983ef3580a4b1b3b041cd991019b900f7995791c0acb32035ac5706085a63"
		hash = "648a4f33b2c268523378929179af529bc064538326a1202dcdfcd9ee12ae8f6c"
		hash = "829b3c298f7003f49986fb26920f7972e52982651ae6127c6e8e219a86f46890"
		hash = "c723a221cff37a700e0e3b9dc5f69cdd6a4cc82502ac7c144d6ca1eaf963e800"
		hash = "c8d3c0b87176b7f8d5667d479cb40d1b9f030d30afe588826254f26ebb4ac58e"
		logic_hash = "51c63f45f891ee80c5e8428575f12cb5881665cb9fe26018d173335db0f02012"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.1"

	strings:
		$a1a = "(crontab -l; printf '@reboot %s noa"
		$a1b = "(crontab -l; printf '@reboot %s \"%s\" noa"
		$a2 = {40 6D 61 67 69 63 40 [1-8] 6E 6F 61 [1-8] 0A 0A 49 20 61 69 6E 74 20 79 6F 75 72 20 61 76}
		$a3 = {31 32 33 34 35 36 [1-8] 41 64 6D 69 6E 21 40 23 [1-8] 7A 68 61 6E 67 6A 69 65 31 32 33 [1-8] 43 75 6D 75 6C 75 73 4C 69 6E 75 78 21 [1-8] 61 62 63 31 32 33 24 [1-8] 77 65 62 40 31 32 33 [1-8] 6D 70 69 75 73 65 72 [1-8] 61 74 75 61 6C 69 7A 61}
		$a4 = "HACKED: %s:%d:%s:%s"
		$a5 = {25 64 7C 25 64 00 31 76 57 3F 3E 55 00 26 25 2423 00 67 76 64 64 60 78 65 73 00 00 26 25 24 00}
		$b1 = "ufw allow 24816"
		$b2 = "iptables -I INPUT -p tcp --dport 24816 -j ACCEPT"
		$b3 = "iptables -I OUTPUT -p tcp --dport 24816 -j ACCEPT"
		$b4 = "firewall-cmd --permanent --add-port 24816/tcp"
		$b5 = "magicPussyMommy"
		$c1 = "SOCKET_CREATING_ERROR SCANNER"
		$c2 = "SOCKET_CREATING_ERROR RECYCLE"

	condition:
		filesize <10MB and ( uint32(0)==0x464c457f) and (( any of ($a*)) or ( all of ($b*)) or ( all of ($c*)))
}