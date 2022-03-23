# The list of files have been split randomly into training (50 %) / validation (25 %) / testing (25%)
# A Random Forest Classifier has been trained and tuned by testing variouse tree depth and number of trees values.

# Explain Random Forest 

# The optimal model had numbers of trees = ... and tree depth = ... 
# Training accuracy = ... %. Validation accuracy = ... % Test accuracy = ... % 




from sklearn.ensemble import RandomForestClassifier

import pandas as pd
import pickle
import random
import warnings

from tqdm import tqdm

warnings.filterwarnings('ignore')

def train_model(feature_df):
    feature_df.loc[feature_df['Is_attack'] == True, 'Is_attack'] = 1
    feature_df.loc[feature_df['Is_attack'] == False, 'Is_attack'] = 0

    filename_list = feature_df['filename'].unique().tolist()

    training_filenames = random.sample(filename_list, int(len(filename_list) / 2))
    remainings_filenames = [file for file in filename_list if file not in training_filenames]
    validation_filenames = random.sample(remainings_filenames, int(len(remainings_filenames) / 2))
    test_filenames = [file for file in remainings_filenames if file not in validation_filenames]

    training_df = feature_df[feature_df['filename'].isin(training_filenames)]
    validation_df = feature_df[feature_df['filename'].isin(validation_filenames)]
    test_df = feature_df[feature_df['filename'].isin(test_filenames)]

    X_train = training_df.drop(['filename','Is_attack'], axis=1).astype(int).values
    X_val = validation_df.drop(['filename','Is_attack'], axis=1).astype(int).values
    X_test = test_df.drop(['filename','Is_attack'], axis=1).astype(int).values

    Y_train = training_df[['Is_attack']].astype(int).values
    Y_val = validation_df[['Is_attack']].astype(int).values
    Y_test = test_df[['Is_attack']].astype(int).values

    print(X_train.shape)

    best_training_score = 0
    best_score = 0

    n_estimators_list = [2, 4, 8, 16, 32]
    max_depth_list = [None, 2, 4, 8, 16]

    for n_estimators in n_estimators_list:
        for max_depth in max_depth_list:
            current_model = RandomForestClassifier(n_estimators=n_estimators, max_depth=max_depth).fit(X_train, Y_train)
            current_score = current_model.score(X_val, Y_val)

            if current_score > best_score:
                best_training_score = current_model.score(X_train, Y_train)
                best_score = current_score
                best_model = current_model

    print("Best training score:", best_training_score)
    print("Best validation score:", best_score)
    print("Best test score:", best_model.score(X_test, Y_test))

    print(best_model)

    return best_model

print("Order features model:")
order_model = train_model(pd.read_csv('features.csv'))
pickle.dump(order_model, open("order_model.pkl", "wb"))
print()
print("Frequency features model:")
frequency_model = train_model(pd.read_csv('frequency_features.csv'))
pickle.dump(frequency_model, open("frequency_model.pkl", "wb"))