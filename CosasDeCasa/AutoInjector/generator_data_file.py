#!python3
#-*- coding: utf-8 -*-

__author__ = "Fare9"
__credits__ = ["Fare9"]
__license__ = "GPL"
__version__ = "2.0.0"
__maintainer__ = "Fare9"
__email__ = "farenain9@gmail.com"
__status__ = "Production"


import os    # standard library
import sys
import random
import string

file_name = "data.cpp"

file_to_generate = '''
#include "common.h"

std::string key = "%s";

uint64_t file_size = 0x%X;

uint8_t encrypted_file[] = {%s};
'''

def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters =  string.ascii_letters + string.hexdigits
    return ''.join(random.choice(letters) for i in range(stringLength))


def crypt(key, data):
    S = list(range(256))
    j = 0

    for i in list(range(256)):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    j = 0
    y = 0
    out = []

    for char in data:
        j = (j + 1) % 256
        y = (y + S[j]) % 256
        S[j], S[y] = S[y], S[j]

        if sys.version_info.major == 2:
            out.append(unichr(ord(char) ^ S[(S[j] + S[y]) % 256]))

        if sys.version_info.major == 3:            
            out.append(char ^ S[(S[j] + S[y]) % 256])

    sys.stdout.write('Real buffer = ')
    for a in data[0:10]:
        sys.stdout.write('%X ' % a)
    print("")
    sys.stdout.write('Encrypted buffer = ')
    for a in out[0:10]:
        sys.stdout.write('%X ' % a)
    print("")
    print("key: %s" % key)

    return out


def read_file_and_get_data(file_to_open=""):
    '''
    Method to read the file and generate the data to generate the file
    '''
    exists = os.path.isfile(file_to_open)

    file_size = 0
    file_content = ""
    key = ""

    if exists:
        if (file_to_open.endswith('.exe')):
            file_ = open(file_to_open,'rb')

            data = file_.read()

            file_size = len(data)

            file_.close()

            counter = 0

            key = randomString(15)

            data = crypt(key,data)

            for c in data:
                file_content += '0x%X,' % c
                counter += 1
                if counter == 10:
                    file_content += '\n'
                    counter = 0

            if file_content[-1] == ',':
                file_content = file_content[0:-1]

        else:
            print ('File must be .exe file')

    else:
        print ("File '%s' does not exists..." % (file_to_open))

    return file_size, file_content, key


def main():

    if len(sys.argv) != 2:
        print ("USAGE: generator_data_file.py <exe_file_to_generate_data>")
        sys.exit(-1)

    file_size, file_content, key = read_file_and_get_data(str(sys.argv[1]))

    if file_size == 0 or file_content == "":
        print ("Error generating data file")
        sys.exit(-1)

    data_file_content = file_to_generate % (key, file_size, file_content)

    opened_file = open(file_name, 'w')

    opened_file.write(data_file_content)

    opened_file.close()

if __name__ == '__main__':
    main()
#!python3
#-*- coding: utf-8 -*-

__author__ = "Fare9"
__credits__ = ["Fare9"]
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Fare9"
__email__ = "farenain9@gmail.com"
__status__ = "Production"


import os    # standard library
import sys
import random
import string

file_name = "data.cpp"

file_to_generate = '''
#include "common.h"

std::string key = "%s"

uint64_t file_size = 0x%X;

uint8_t encrypted_file[] = {%s};
'''

def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters =  string.ascii_letters + string.hexdigits
    return ''.join(random.choice(letters) for i in range(stringLength))


def crypt(key, data):
    S = list(range(256))
    j = 0

    for i in list(range(256)):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    j = 0
    y = 0
    out = []

    for byte in data:
        j = (j + 1) % 256
        y = (y + S[j]) % 256
        S[j], S[y] = S[y], S[j]

        if sys.version_info.major == 2:
            out.append(unichr(ord(byte) ^ S[(S[j] + S[y]) % 256]))

        if sys.version_info.major == 3:
            out.append(byte ^ S[(S[j] + S[y]) % 256])

    print("Real data = ")
    for a in data[0:10]:
        sys.stdout.write('%X ' % a)

    print ("")

    print ("Encrypted data = ")
    for a in out[0:10]:
        sys.stdout.write('%X ' % a)
    print("")
    print ("Key = %s" % key)
    return out


def read_file_and_get_data(file_to_open=""):
    '''
    Method to read the file and generate the data to generate the file
    '''
    exists = os.path.isfile(file_to_open)

    file_size = 0
    file_content = ""
    key = ""

    if exists:
        if (file_to_open.endswith('.exe')):
            file_ = open(file_to_open,'rb')

            data = file_.read()

            file_size = len(data)

            file_.close()

            counter = 0

            key = randomString(15)

            data = crypt(key,data)

            for c in data:
                file_content += '0x%X,' % c
                counter += 1
                if counter == 10:
                    file_content += '\n'
                    counter = 0

            if file_content[-1] == ',':
                file_content = file_content[0:-1]

        else:
            print ('File must be .exe file')

    else:
        print ("File '%s' does not exists..." % (file_to_open))

    return file_size, file_content, key

def main():

    if len(sys.argv) != 2:
        print ("USAGE: generator_data_file.py <exe_file_to_generate_data>")
        sys.exit(-1)

    file_size, file_content, key = read_file_and_get_data(str(sys.argv[1]))

    if file_size == 0 or file_content == "":
        print ("Error generating data file")
        sys.exit(-1)

    data_file_content = file_to_generate % (key, file_size, file_content)

    opened_file = open(file_name, 'w')

    opened_file.write(data_file_content)

    opened_file.close()

if __name__ == '__main__':
    main()
