# Crypto-Scanner
A Python utility to scan computers for crypto virus infections, such as Locky

# Usage:
    python crypto_scanner.py [options] [> output.txt]

# Options:
    -dir    Set the root directory or UNC path of the scan          Default: -dir=C:\Users
    -help   Software information
    -s      Shutdown machine after scan if a threat is detected     Default: False
    -v      Verbose logging                                         Default: False
    
    For example, to set the directory to the C: drive, enable verbose logging, and output to report.txt, enter:
    python crypto_scanner.py -dir=C:\ -v > report.txt

# Description:
    Crypto Scanner is a basic Python script that scans a directory and all subdirectories for typical 
    cryptovirus files and extensions. Upon malware detection, the script may shutdown the machine 
    to prevent further infection if the user chooses.

# Contact Information:
    Website: http://zackwhiteit.com
    Twitter: @ZackWhiteIT

# MIT License
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
