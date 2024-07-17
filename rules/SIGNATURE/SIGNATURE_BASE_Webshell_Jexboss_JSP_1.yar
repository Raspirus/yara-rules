rule SIGNATURE_BASE_Webshell_Jexboss_JSP_1 : FILE
{
	meta:
		description = "Detects JexBoss JSPs"
		author = "Florian Roth (Nextron Systems)"
		id = "4fe7a20b-dc2b-509b-bcf8-e3bfbbe7431a"
		date = "2018-11-08"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-webshells.yar#L9855-L9872"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f540bbc88bffd0c961837416bd5166fd3cb54b6124ffffbf1cd60e49ab01bd30"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "41e0fb374e5d30b2e2a362a2718a5bf16e73127e22f0dfc89fdb17acbe89efdf"

	strings:
		$x1 = "equals(\"jexboss\")"
		$x2 = "%><pre><%if(request.getParameter(\"ppp\") != null &&" ascii
		$s1 = "<%@ page import=\"java.util.*,java.io.*\"%><pre><% if (request.getParameter(\""
		$s2 = "!= null && request.getHeader(\"user-agent\"" ascii
		$s3 = "String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); }}%>" fullword ascii

	condition:
		uint16(0)==0x253c and filesize <1KB and 1 of ($x*) or 2 of them
}