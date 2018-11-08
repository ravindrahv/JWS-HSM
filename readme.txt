********************************************************************************************************************************************************
1)
Jar-Dependencies :
------------------
a)
nimbus-jose-jwt-6.2.jar
json-smart-2.3.jar
accessors-smart-1.2.jar
asm-5.0.4.jar
jcip-annotations-1.0-1.jar

b)
bcprov-jdk15on-1.60.jar


2)
Requires the Nitro-HSM (or an equivalent hardware-encryption-device) to be plugged in for the PKCS11 interface to pick it up.

3)
Nitro-HSM itself requires OpenSC software (pkcs11-interface)

4)
The pkcs11-provider configuration file has been included for reference ... (nitrohsm-sunpkcs11.cfg)

5)
Opensc-pkcs11.dll has also been provided but not tested without open-sc installation.

********************************************************************************************************************************************************

Related links :
===============
1) https://www.nitrokey.com/tags/nitrokey-hsm
2) https://raymii.org/s/articles/Get_Started_With_The_Nitrokey_HSM.html
3) https://github.com/OpenSC/OpenSC/wiki
********************************************************************************************************************************************************

Notes: 
1) The gradle project is primarily to download dependencies.
2) The Junit test cases are required to be run manually through eclipse.
3) The test cases can also be run as plain java classes ('helloworld' style).
4) Requires Nitro-Key HSM USB (or equivalent) to be plugged in.
5) Nitro-Key itself has its own setup and initialization procedure!

Date : 08-Nov-2018
********************************************************************************************************************************************************
********************************************************************************************************************************************************
