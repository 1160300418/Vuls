# Overview
Vendor of the products: D-Link (https://www.dlink.com/)

Reported by: xsz of HIT-IDS ChunkL Team

Product: D-Link DIR-605L

Affected firmware Version: 2.13B01 BETA

Firmware: https://support.dlink.com/resource/SECURITY_ADVISEMENTS/DIR-605L/REVB/DIR-605L_REVB_FIRMWARE_v2.13B01_BETA.zip

![product](../../imgs/product.png)

# Vulnerability Details
A stack-based buffer overflow vulnerability exsist in D-Link N300 WI-FI Router DIR-605L (firmware version v2.13 B01 Beta) which may result in remote code excution or deninal of service. The issue exists in the binary "boa" which resides in "/bin" folder, and the binary is responsible for serving http connection received by the device. 

While processing the post reuqest "/goform/formWlanSetup", the value of "webpage" parameter which can be arbitrarily long is eventually copied onto stack memory by "sprintf" function, and could lead to a buffer overflow. The value of "webpage" parameter is first assigned to the global variable by the strcpy function (as shown at line 34-35 of Figure A), and then this global variable is finally passed to the sprintf function as an argument (as shown in Figure B-D). The attackers can construct a payload to carry out arbitrary code attacks.

![Fig1](imgs/Fig1.png)

Figure A: The decompiled code of function which read value of parameter "webpage" and call strcpy function to assign the value to the global variable "last_url".

![fig2](imgs/fig2.png)

Figure B: The decompiled code of function which call websRedirect function with the global variable "last_url" as a parameter.

![fig3](imgs/fig3.png)

Figure C: The decompiled code of function websRedirect.

![fig4](imgs/fig4.png)

Figure D: The decompiled code of function send_r_moved_perm.

# Reproduce and POC
To reproduce the vulnerability, the following steps can be followed:
1. Start frimware through QEMU system or other methods (real device)
2. Use the default username and password to login web.
3. Execute the poc script as follows:

```shell
python3 POC_for_formWlanSetup.py <target_ip>
```

# Reply by Official
Already reported to the vendor, no response yet...