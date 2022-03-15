
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
max_calls = 0

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
            max_calls = max(max_calls, len(lines))


feature_df = pd.DataFrame()
# print(feature_df)

for file in tqdm(list(feature_dict.keys())):
    current_feature_df = pd.DataFrame(columns=range(0, len(feature_dict[file])))
    current_feature_df[current_feature_df.columns.tolist()] = [feature_dict[file]]

    current_feature_df['Is_attack'] = attack_dict[file]
    current_feature_df['filename'] = file

    feature_df = feature_df.append(current_feature_df)
    

    
    # print(feature_dict[file])
feature_df = feature_df.fillna('-1')
print(feature_df)

feature_df.to_csv('features.csv', index=False)