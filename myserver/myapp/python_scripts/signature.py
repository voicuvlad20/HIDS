
import hashlib
import os
from posixpath import abspath

print("signature file cwd: ", os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Method to parse a list of md5 files and save the hashcodes in a set.
def create_md5_set():

    md5_set = set()

    for file_index in range(0, 50): # change this to max file + 1
        if file_index < 10:
            filename = f'files/00{str(file_index)}.txt'
        elif file_index < 100:
            filename = f'files/0{str(file_index)}.txt'
        else:
            filename = f'files/{str(file_index)}.txt'

        with open(filename) as f:

            lines = f.readlines()[6:]
            for line in lines:
                md5_set.add(line[:-1])

    return md5_set

# Method to generate and MD5 hashcode for a given file.
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Method to go through all files in a given folder, generate a MD5 code for each and check if the code is in the set of known attack hashcodes.
def check_folder(md5_set, given_folder):
    files = next(os.walk(given_folder), (None, None, []))[2]
    os.chdir(given_folder)

    for file in files:

        if md5(file) in md5_set:
            print(file, md5(file), "Attack")
        else:
            print(file, md5(file), "Non Attack")

md5_set = create_md5_set()
test_folder = abspath('.') # Change this to folder that needs tested
test_folder = '/home/vladvoicu/third_year_project/python_scripts/input'
#test_folder = '/home/vladvoicu/Downloads'
check_folder(md5_set, test_folder)

def logtext():
    return print("testing")



        