meta_dotnet.py
================

This module obtains the Typelib ID and Module Version ID located in .NET Windows PE files. Thanks to the guys at Cylance for developing getnetguids which is the basis for 
this module. You can read about it at https://www.virusbulletin.com/virusbulletin/2015/06/using-net-guids-help-hunt-malware 

**Flags Set:** yara rule hits (optional; prefixed with "yr:")

**Output Objects:** None

Installation
---
* Install getnetguids (https://github.com/CylanceSPEAR/GetNETGUIDs)
```
git glone https://github.com/CylanceSPEAR/GetNETGUIDs.git

cd GetNETGUIDs

python setup.py install 
```
* Put meta_dotnet.py in the laikaboss module installation directory:
  * /usr/local/lib/python2.7/dist-packages/laikaboss-2.0-py2.7.egg/laikaboss/modules/
* Modify dispatch.yara to include the module
```
rule type_is_dotnet
{
    meta:
        scan_modules = "META_DOTNET"
        file_type = "pe dotnet"

        strings:
                $lib = "mscoree.dll"
                $func = "_CorExeMain"
    condition:
        type_is_mz and $lib and $func
}

```

Testing
---
You can test this LaikaBOSS module by using laika.py and the command line switch -m. 
```
laika.py -o . -m META_DOTNET A3F755F816406599F1A1132E32449ABB.danger
```

Sample output
```
"META_DOTNET": {
  "DotNet_GUIDs": {
	"Typelib_ID": "a5314025-d172-45af-8e3d-cf2aa06d15cb",
	"MVID": "6004e92e-7cc5-4594-920a-4b0bf8092bdd"
  }
```

Optional Dispatch Configuration for Metadata Matching
---
You may have a use case where you want to flag on specific, known malicious Typelib IDs. This can be accomplished by using a yara rule that will 
run only against the metadata output of META_DOTNET. In order to flag on a "malicius" Typelib ID, you need to first create your yara rule.

```
rule malicious_netguids
{
    strings:

        $ = "a5314025-d172-45af-8e3d-cf2aa06d15cb"

    condition:
		any of them
}
```

You can then place your yara rule in /etc/laikaboss/modules/scan-yara/ (if following a standard installation) or put it in signatures.yara. I chose
to keep it as a separate rule named it malicious_netguids.yara.

You can then add the statement below to /etc/laikaboss/modules/scan-yara/signatures.yara

```
include "malicious_netguids.yara"
```

We now need to update the dispatch rule in /etc/laikaboss/dispatch.yara for "type_is_dotnet" to include the SCAN_YARA module as seen below. While you can add SCAN_YARA
as a module, you need to provide it with some optional arguments in order for it to run yara rules against metadata output. If you include SCAN_YARA with no arguments,
it will run all your defined yara rules against the object, in our case the .NET PE file. This is not what we want.

The SCAN_YARA module accepts optional arguments. The format for our use case is:

SCAN_YARA(meta_scan=[metadata field location in scan output], rule=[location of yara rule name])

As we can see below, we are targeting the META_DOTNET.DotNet_GUIDs.Typelib_ID field and will have our malicious_netguids.yara file scan that field for matches.

```
rule type_is_dotnet
{
    meta:
        scan_modules = "META_DOTNET SCAN_YARA(meta_scan=META_DOTNET.DotNet_GUIDs.Typelib_ID,rule=/etc/laikaboss/modules/scan-yara/malicious_netguids.yara)"
        file_type = "pe dotnet"

        strings:
                $lib = "mscoree.dll"
                $func = "_CorExeMain"
    condition:
        type_is_mz and $lib and $func
}
```
