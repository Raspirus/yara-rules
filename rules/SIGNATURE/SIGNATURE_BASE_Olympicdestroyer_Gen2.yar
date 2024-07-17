import "pe"


rule SIGNATURE_BASE_Olympicdestroyer_Gen2 : FILE
{
	meta:
		description = "Detects Olympic Destroyer malware"
		author = "Florian Roth (Nextron Systems)"
		id = "8d0cbb7b-6650-53ed-8d58-176f8b4af880"
		date = "2018-02-12"
		modified = "2023-12-05"
		reference = "http://blog.talosintelligence.com/2018/02/olympic-destroyer.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_olympic_destroyer.yar#L30-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1bcf0e95d9de62271a09f6ac64ce65debc91e541e1fccfe5c31661466c00bd5e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d934cb8d0eadb93f8a57a9b8853c5db218d5db78c16a35f374e413884d915016"
		hash2 = "3e27b6b287f0b9f7e85bfe18901d961110ae969d58b44af15b1d75be749022c2"
		hash3 = "edb1ff2521fb4bf748111f92786d260d40407a2e8463dcd24bb09f908ee13eb9"
		hash4 = "28858cc6e05225f7d156d1c6a21ed11188777fa0a752cb7b56038d79a88627cc"

	strings:
		$x1 = "cmd.exe /c (ping 0.0.0.0 > nul) && if exist %programdata%\\evtchk.txt" fullword wide
		$x2 = "cmd.exe /c (echo strPath = Wscript.ScriptFullName & echo.Set FSO = CreateObject^(\"Scripting.FileSystemObject\"^)" wide
		$x3 = "del %programdata%\\evtchk.txt" fullword wide
		$x4 = "Pyeongchang2018.com\\svc_all_swd_installc" fullword ascii
		$s1 = "<STARTCRED>" fullword wide
		$s2 = "SELECT ds_cn FROM ds_computer" fullword wide
		$s3 = "\\system32\\notepad.exe" wide
		$s4 = "%s \\\\%s -u \"%s\" -p \"%s\" -accepteula -d %s %s \"%s\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and (pe.imphash()=="fd7200dcd5c0d9d4d277a26d951210aa" or pe.imphash()=="975087e9286238a80895b195efb3968d" or pe.imphash()=="da1c2d7acfe54df797bfb1f470257bc3" or 1 of ($x*) or 3 of them )
}