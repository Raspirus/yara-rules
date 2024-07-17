
rule VOLEXITY_Webshell_Jsp_Regeorg : WEBSHELL COMMODITY
{
	meta:
		description = "Detects the reGeorg webshells' JSP version."
		author = "threatintel@volexity.com"
		id = "205ee383-4298-5469-a509-4ce3eaf9dd0e"
		date = "2022-03-08"
		modified = "2022-08-10"
		reference = "https://github.com/SecWiki/WebShell-2/blob/master/reGeorg-master/tunnel.jsp"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L47-L70"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "cecb71605d9112d509823c26e40e1cf9cd6db581db448db5c9ffc63a2bfe529e"
		score = 75
		quality = 80
		tags = "WEBSHELL, COMMODITY"
		hash1 = "f9b20324f4239a8c82042d8207e35776d6777b6305974964cd9ccc09d431b845"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 1

	strings:
		$magic = "socketChannel.connect(new InetSocketAddress(target, port))" ascii
		$a1 = ".connect(new InetSocketAddress" ascii
		$a2 = ".configureBlocking(false)" ascii
		$a3 = ".setHeader(" ascii
		$a4 = ".getHeader(" ascii
		$a5 = ".flip();" ascii

	condition:
		$magic or all of ($a*)
}