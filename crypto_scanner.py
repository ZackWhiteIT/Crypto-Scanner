import os
import sys
import datetime

VERSION = 'v1.0'

USAGE = '''
Usage:
    python crypto_scanner.py [options] [> output.txt]

Options:
    -dir      Set the root directory or UNC path of the scan\t\t\t      Default: -dir=C:\\Users
    -help   Software information
    -s         Shutdown machine after scan if a threat is detected\t\t Default: False
    -v         Verbose logging\t\t\t\t\t\t\t\t\t\t\tDefault: False
    
    For example, to set the directory to the C: drive, enable verbose logging, and output to report.txt, enter:
    python crypto_scanner.py -dir=C:\ -v > report.txt
'''
INFO = '''
Crypto Scanner ''' + VERSION + '''

Description:
    Crypto Scanner is a basic Python script that scans a directory and all subdirectories for typical 
    cryptovirus files and extensions. Upon malware detection, the script may shutdown the machine 
    to prevent further infection if the user chooses.

''' + USAGE + '''
Contact Information:
    Website:\t http://zackwhiteit.com
    Twitter:\t @ZackWhiteIT

This software is protected by copyright under the MIT License (MIT).

Copyright (c) 2016 David Mize and Zack White

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files 
(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished 
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO 
THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''


MALICIOUS_EXTENSIONS = ['.encoderpass','.k','.key','.ecc','.ezz','.exx','.zzz','.xyz','.aaa','.abc','.ccc','.vvv','.xxx','.ttt','.micro','.encrypted','.locked','.crypto','._crypt','.crinf','.r5a','.xrtn','.XTBL','.crypt','.R16M01D05','.pzdc','.good','.LOL!','.OMG!','.RDM','.RRK','.encryptedRSA','.crjoker','.EnCiPhErEd','.LeChiffre','.keybtc@inbox.com','.0x0','.bleep','.1999','.vault','.HA3','.toxcrypt','.magic','.SUPERCRYPT','.CTBL','.CTB2']
MALICIOUS_FILES = ['HELPDECRYPT.TXT','HELPDECRYPT.TXT','HELPDECRYPT.txt','HELP_YOUR_FILES.TXT','HELP_YOUR_FILES.TXT','HELP_YOUR_FILES.txt','HELP_TO_DECRYPT_YOUR_FILES.txt','HELP_TO_DECRYPT_YOUR_FILES.txt','HELP_TO_DECRYPT_YOUR_FILES.txt','RECOVERY_KEY.txt','RECOVERY_KEY.txt','RECOVERY_KEY.txt','HELP_RESTORE_FILES.txt','HELP_RESTORE_FILES.txt','HELP_RESTORE_FILES.txt','HELP_RECOVER_FILES.txt','HELP_RECOVER_FILES.txt','HELP_RECOVER_FILES.txt','HELP_TO_SAVE_FILES.txt','HELP_TO_SAVE_FILES.txt','HELP_TO_SAVE_FILES.txt','DecryptAllFiles.txt','DecryptAllFiles.txt','DecryptAllFiles.txt','DECRYPT_INSTRUCTIONS.TXT','DECRYPT_INSTRUCTIONS.TXT','DECRYPT_INSTRUCTIONS.txt','INSTRUCCIONES_DESCIFRADO.TXT','INSTRUCCIONES_DESCIFRADO.TXT','INSTRUCCIONES_DESCIFRADO.txt','How_To_Recover_Files.txt','How_To_Recover_Files.txt','How_To_Recover_Files.txt','YOUR_FILES.HTML','YOUR_FILES.HTML','YOUR_FILES.html','YOUR_FILES.url','YOUR_FILES.url','YOUR_FILES.URL','encryptor_raas_readme_liesmich.txt','encryptor_raas_readme_liesmich.txt','encryptor_raas_readme_liesmich.txt','Help_Decrypt.txt','Help_Decrypt.txt','Help_Decrypt.txt','DECRYPT_INSTRUCTION.TXT','DECRYPT_INSTRUCTION.TXT','DECRYPT_INSTRUCTION.txt','HOW_TO_DECRYPT_FILES.TXT','HOW_TO_DECRYPT_FILES.TXT','HOW_TO_DECRYPT_FILES.txt','ReadDecryptFilesHere.txt','ReadDecryptFilesHere.txt','ReadDecryptFilesHere.txt','Coin.Locker.txt','Coin.Locker.txt','Coin.Locker.txt','_secret_code.txt','_secret_code.txt','_secret_code.txt','DECRYPT_ReadMe.TXT','DECRYPT_ReadMe.TXT','DECRYPT_ReadMe.txt','DecryptAllFiles.txt','DecryptAllFiles.txt','DecryptAllFiles.txt','FILESAREGONE.TXT','FILESAREGONE.TXT','FILESAREGONE.txt','IAMREADYTOPAY.TXT','IAMREADYTOPAY.TXT','IAMREADYTOPAY.txt','HELLOTHERE.TXT','HELLOTHERE.TXT','HELLOTHERE.txt','READTHISNOW!!!.TXT','READTHISNOW!!!.TXT','READTHISNOW!!!.txt','SECRETIDHERE.KEY','SECRETIDHERE.KEY','SECRETIDHERE.KEY','IHAVEYOURSECRET.KEY','IHAVEYOURSECRET.KEY','IHAVEYOURSECRET.KEY','SECRET.KEY','SECRET.KEY','SECRET.KEY','HELPDECYPRT_YOUR_FILES.HTML','HELPDECYPRT_YOUR_FILES.HTML','HELPDECYPRT_YOUR_FILES.html','help_decrypt_your_files.html','help_decrypt_your_files.html','help_decrypt_your_files.html','HELP_TO_SAVE_FILES.txt','HELP_TO_SAVE_FILES.txt','HELP_TO_SAVE_FILES.txt','RECOVERY_FILES.txt','RECOVERY_FILES.txt','RECOVERY_FILES.txt','RECOVERY_FILE.TXT','RECOVERY_FILE.TXT','RECOVERY_FILE.txt','RECOVERY_FILE*.txt','RECOVERY_FILE*.txt','RECOVERY_FILE*.txt','HowtoRESTORE_FILES.txt','HowtoRESTORE_FILES.txt','HowtoRESTORE_FILES.txt','HowtoRestore_FILES.txt','HowtoRestore_FILES.txt','HowtoRestore_FILES.txt','howto_recover_file.txt','howto_recover_file.txt','howto_recover_file.txt','restorefiles.txt','restorefiles.txt','restorefiles.txt','howrecover+*.txt','howrecover+*.txt','howrecover+*.txt','_how_recover.txt','_how_recover.txt','_how_recover.txt','recoveryfile*.txt','recoveryfile*.txt','recoveryfile*.txt','recoverfile*.txt','recoverfile*.txt','recoverfile*.txt','Howto_Restore_FILES.TXT','Howto_Restore_FILES.TXT','Howto_Restore_FILES.txt','help_recover_instructions+*.txt','help_recover_instructions+*.txt','help_recover_instructions+*.txt','_Locky_recover_instructions.txt','_Locky_recover_instructions.txt','_Locky_recover_instructions.txt']

def main(argv):
    #Default settings
    ROOT_DIR = "C:\\Users" #Use \\\\server\share for servers or unc paths
    VERBOSE_LOGGING = False #Displays file counter
    SHUTDOWN_ON_DETECTION = False #Shutdown the computer if a virus is detected
    
    for option in (sys.argv[1:]):
        if option == '-help':
            print(INFO)
            return 3
        elif '-dir=' in option:
            ROOT_DIR = option[5:] #Use \\\\server\share for servers or unc paths
        elif option == '-s':
            SHUTDOWN_ON_DETECTION = True #Shutdown the computer if a virus is detected
        elif option == '-v':
            VERBOSE_LOGGING = True #Displays file counter
        else:
            #Error handling
            print('ERROR: Missing or invalid arguments')
            return 1

    files_scanned = 0
    threats_found = 0
    total_files = sum([len(files) for root, dirs, files in os.walk(ROOT_DIR)]) + 1
    infected_files = []

    scan_start_time = datetime.datetime.now()

    #Scan each file
    for root, dirs, files in os.walk(ROOT_DIR):
        for file in files:
            files_scanned += 1
            
            if VERBOSE_LOGGING:
                print('Scanning file ', files_scanned, ' out of ', total_files,'...')
                
            #Scan for malicious extensions
            for ext in MALICIOUS_EXTENSIONS:
                if file.endswith(ext):
                    infected_files.append(os.path.join(root, file)+"\n")
                    threats_found += 1

            #Scan for malicious files
            for filename in MALICIOUS_FILES:
                if file == filename:
                    infected_files.append(os.path.join(root, file)+"\n")
                    threats_found += 1

    scan_end_time = datetime.datetime.now()

    #Print report
    print('\nCryptovirus scan start time: ',scan_start_time)
    print('Cryptovirus scan end time: ',scan_end_time)
    print('Scan directory: ',ROOT_DIR)
    print('Verbose logging: ',VERBOSE_LOGGING)
    print('Shutdown on detection: ', SHUTDOWN_ON_DETECTION)
    print('Files scanned: ', files_scanned)
    print('Threats found: ', threats_found)

    if threats_found > 0:
        print('\nInfected files: ')
        for filename in infected_files:
            print(filename)

        if SHUTDOWN_ON_DETECTION:
            os.system("shutdown /s /f /c \"Your computer has been infected with a cryptovirus. It will now shutdown. DO NOT TURN THE COMPUTER BACK ON. Contact IT for additional help.\" /t 60")
    
    return 0

#Execute script
if __name__ == '__main__':
    main(sys.argv[1:])
