
# Am luat in parte fiecare folder si dupa fiecare fiecare fisier din fiecare folder si dupa am calculat cel mai mare nr de calluri din toate fisierelele.
#Dupa nr rep numarul de featur uri si am creat 2 dictionare. ! cu lista de syscalluri si altul cu daca e atac sau nu
#am combinat dictionarele intr un data fra,e in care fiecare eu am nr de col care e nr max de syscall plus 2 si dupa numele fisierilui si dupa boolean flag cu dacae atac sau nu
#unde fisierle au un nr mai mic de sys calluri  decat nr max, atunci am inlocuit null urile cu -1
# n coloanele o sa fie features si outputul o sa fie boolean flagul cu daca e atac sau nu
#o sa le impart random in training validation si testing
#testing e pt acuratetea finala, validation e pt parameter tuning pt random forest si traing e ca sa faca training pe data


import os
import pandas as pd
import warnings

from tqdm import tqdm

warnings.filterwarnings('ignore')

folder_list = ['/home/vladvoicu/Downloads/ADFA-LD/Training_Data_Master/',
                '/home/vladvoicu/Downloads/ADFA-LD/Validation_Data_Master/',
                '/home/vladvoicu/Downloads/ADFA-LD/Attack_Data_Master/']

feature_dict = {}
attack_dict = {}

for folder in folder_list:
    if 'Attack' in folder == '/home/vladvoicu/Downloads/ADFA-LD/Attack_Data_Master/':
        sub_folders =  os.listdir(folder)
        for sub_folder in sub_folders:
            sub_folder_path = folder + sub_folder + '/'
            folder_list.append(sub_folder_path)
        continue

    for filename in os.listdir(folder):
        filepath = folder + filename
        with open(filepath) as f:
            lines = f.readline().split(' ')[0:-1]
            if 'Attack' in folder:
                attack_dict[filename] = True
            else:
                attack_dict[filename] = False
            feature_dict[filename] = lines

feature_df = pd.DataFrame()

for file in tqdm(list(feature_dict.keys())):

    frequency_dict = {}
    for call in feature_dict[file]:
        if call in frequency_dict.keys():
            frequency_dict[call] += 1
        else:
            frequency_dict[call] = 1

    for callid in range(0, 419):
        if callid not in frequency_dict.keys():
            frequency_dict[callid] = 0
    frequency_dict['Is_attack'] = attack_dict[file]
    frequency_dict['filename'] = file
    feature_df = feature_df.append(frequency_dict, ignore_index=True)



feature_df = feature_df.fillna(0)
columns = [i for i in range(0, 419)] + ['Is_attack', 'filename']
feature_df = feature_df[columns]
print(feature_df)
feature_df.to_csv('frequency_features.csv', index=False)
