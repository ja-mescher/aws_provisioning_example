import pathlib
import glob
import re


cryptoauthlib_dir = pathlib.Path('../..')

copyright = (
    '(c) 2017 Microchip Technology Inc. and its subsidiaries.\n'
    'You may use this software and any derivatives exclusively with\n'
    'Microchip products.')

license = (
    '(c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this\n'
    'software and any derivatives exclusively with Microchip products.\n'
    '\n'
    'THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER\n'
    'EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED\n'
    'WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A\n'
    'PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION\n'
    'WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.\n'
    '\n'
    'IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,\n'
    'INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND\n'
    'WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS\n'
    'BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE\n'
    'FULLEST EXTENT ALLOWED BY LAW, MICROCHIP''S TOTAL LIABILITY ON ALL CLAIMS IN\n'
    'ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,\n'
    'THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.\n'
    '\n'
    'MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE\n'
    'TERMS.')

all_file_paths = []
all_file_paths += cryptoauthlib_dir.glob('lib/**/*.c')
all_file_paths += cryptoauthlib_dir.glob('lib/**/*.h')
all_file_paths += cryptoauthlib_dir.glob('test/**/*.c')
all_file_paths += cryptoauthlib_dir.glob('test/**/*.h')
all_file_paths += cryptoauthlib_dir.glob('app/**/*.c')
all_file_paths += cryptoauthlib_dir.glob('app/**/*.h')

# Parse all the c files
for file_path in all_file_paths:
    print('\nProcessing {}'.format(file_path))
    
    with open(file_path, 'r') as f:
        contents = f.read()
        
    if not re.search(r'\\copyright[^\n]+Microchip', contents, re.IGNORECASE):
        print('No microchip copyright found, skipping.')
        continue # We assume the lack of a Microchip copyright means its not a microchip file


    # Update doxygen copyright
    result = re.search(r'([^\\\n]+)(\\copyright )(.*?)(\s*\*\s*\n)', contents, re.DOTALL)
    if not result:
        raise RuntimeError('Failed to find appropriate copyright to replace.')

    # Format copyright to match doxygen style of existing one
    new_copyright = ''
    for line in copyright.splitlines(keepends=True):
        if not new_copyright:
            new_copyright = result.group(1) + result.group(2) + line
        else:
            new_copyright += result.group(1) + ' '*len(result.group(2)) + line
    new_copyright += result.group(4)

    contents = contents.replace(result.group(0), new_copyright, 1)


    # Update doxygen license
    result = re.search(r'([^\\\n]+)(\\page\s+License)(.*?)(\s*\*/)', contents, re.DOTALL)
    if not result:
        raise RuntimeError('Failed to find appropriate license to replace.')

    # Format license to match doxygen style of existing one
    new_license = result.group(1) + '\\page License\n' + result.group(1) + '\n'
    for line in license.splitlines(keepends=True):
        new_license += result.group(1) + line
    new_license += result.group(4)

    contents = contents.replace(result.group(0), new_license, 1)


    # Update file with new contents
    with open(file_path, 'w') as f:
        f.write(contents)

