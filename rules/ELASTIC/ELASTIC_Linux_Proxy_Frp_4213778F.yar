rule ELASTIC_Linux_Proxy_Frp_4213778F : FILE MEMORY
{
	meta:
		description = "Detects Linux Proxy Frp (Linux.Proxy.Frp)"
		author = "Elastic Security"
		id = "4213778f-d05e-4af8-9650-2d813d5a64e5"
		date = "2021-10-20"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Proxy_Frp.yar#L1-L28"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "16294086be1cc853f75e864a405f31e2da621cb9d6a59f2a71a2fca4e268b6c2"
		logic_hash = "83eeb632026c38ac08357c27d971da31fbc9a0500ecf489e8332ac5862a77b85"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "70bb186a9719767a9a60786fbe10bf4cc2f04c19ea58aaaa90018ec89a9f9b84"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$s1 = "github.com/fatedier/frp/client/proxy.TcpProxy"
		$s2 = "frp/cmd/frpc/sub/xtcp.go"
		$s3 = "frp/client/proxy/proxy_manager.go"
		$s4 = "fatedier/frp/models/config/proxy.go"
		$s5 = "github.com/fatedier/frp/server/proxy"
		$s6 = "frp/cmd/frps/main.go"
		$p1 = "json:\"remote_port\""
		$p2 = "remote_port"
		$p3 = "remote_addr"
		$p4 = "range section [%s] local_port and remote_port is necessary[ERR]"

	condition:
		2 of ($s*) and 2 of ($p*)
}