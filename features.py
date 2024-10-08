import os

import h5py
import numpy as np
from sklearn import preprocessing
import pandas as pd
from sklearn.model_selection import train_test_split

_FEATURES = ['Destination Port', 'Flow Duration', 'Total Fwd Packets',
             'Total Backward Packets', 'Total Length of Fwd Packets',
             'Total Length of Bwd Packets', 'Fwd Packet Length Max',
             'Fwd Packet Length Min', 'Fwd Packet Length Mean',
             'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
             'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
             'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
             'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
             'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
             'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
             'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
             'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
             'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
             'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
             'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
             'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
             'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
             'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
             'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
             'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
             'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
             'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
             'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
             'Idle Std', 'Idle Max', 'Idle Min']

_FEATURES2 = ['Dst Port', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
       'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
       'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
       'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
       'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
       'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
       'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
       'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
       'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
       'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
       'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean',
       'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
       'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
       'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg',
       'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
       'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
       'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
       'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
       'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
       'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']

_DOS = ['DoS GoldenEye', 'DoS slowloris', 'DoS Slowhttptest', 'DoS Hulk', 'DoS attacks-Hulk', 'DoS attacks-SlowHTTPTest', 'DoS attacks-GoldenEye', 'DoS attacks-Slowloris']
_DDOS = ['DDoS', 'DDOS attack-LOIC-UDP', 'DDOS attack-HOIC']
_INFL = ['Infiltration','Heartbleed', 'Infilteration']
_BRUTE = ['FTP-Patator', 'SSH-Patator', 'FTP-BruteForce', 'SSH-Bruteforce']
_WEB = ['Web Attack � Brute Force', 'Web Attack � XSS', 'Web Attack � Sql Injection', 'Brute Force -Web', 'Brute Force -XSS', 'SQL Injection']
_BOT = ['Bot']
_BENIGN = ['BENIGN', 'Benign']
_LABELS = _DOS + _DDOS + _INFL + _BRUTE + _WEB + _BOT + _BENIGN

_DOS_FF = [0, 1, 2, 3, 4, 5, 14, 15, 21, 26, 44, 45, 34, 35]
_DDOS_FF = [0, 1, 2, 3, 4, 5, 14, 15, 21, 26, 44, 45, 34, 35]
_INFL_FF = [0, 1, 2, 3, 14, 15, 21, 26, 70, 74, 44, 46, 47, 34, 35]
_BRUTE_FF = [0, 1, 2, 3, 46, 47, 44]
_WEB_FF = [46, 47, 43, 45, 44, 0, 2, 3]
_BOT_FF = [0, 1, 2, 3, 14, 15, 21, 26, 70, 74, 44, 46, 47, 34, 35]


def split_features(dataframe, attack_class):
    if attack_class.casefold() == 'dos':
        attack_classes = _DOS
        ff_features = _DOS_FF
    elif attack_class.casefold() == 'ddos':
        attack_classes = _DDOS
        ff_features = _DDOS_FF
    elif attack_class.casefold() == 'infl':
        attack_classes = _INFL
        ff_features = _INFL_FF
    elif attack_class.casefold() == 'brute':
        attack_classes = _BRUTE
        ff_features = _BRUTE_FF
    elif attack_class.casefold() == 'web':
        attack_classes = _WEB
        ff_features = _WEB_FF
    elif attack_class.casefold() == 'bot':
        attack_classes = _BOT
        ff_features = _BOT_FF
    else:
        attack_classes = _DOS
        ff_features = _DOS_FF

    nff_features = [i for i in range(len(_FEATURES)) if i not in ff_features]

    benign = dataframe[dataframe['Label'].isin(_BENIGN)]
    attack = dataframe[dataframe['Label'].isin(attack_classes)]

    benign_ff = benign.iloc[:, ff_features]
    benign_nff = benign.iloc[:, nff_features]

    attack_ff = attack.iloc[:, ff_features]
    attack_nff = attack.iloc[:, nff_features]

    return attack_ff, attack_nff, benign_ff, benign_nff


def reassemble_features(attack_ff, attack_nff, benign_ff, benign_nff, attack_class):
    if attack_class.casefold() == 'dos':
        ff_features = _DOS_FF
    elif attack_class.casefold() == 'ddos':
        ff_features = _DDOS_FF
    elif attack_class.casefold() == 'infl':
        ff_features = _INFL_FF
    elif attack_class.casefold() == 'brute':
        ff_features = _BRUTE_FF
    elif attack_class.casefold() == 'web':
        ff_features = _WEB_FF
    elif attack_class.casefold() == 'bot':
        ff_features = _BOT_FF
    else:
        ff_features = _DOS_FF

    nff_features = [i for i in range(len(_FEATURES)) if i not in ff_features]
    new_index = [(ff_features + nff_features).index(i) for i in range(len(_FEATURES))]

    benign = pd.concat([benign_ff, benign_nff], axis=1).iloc[:, new_index]
    attack = pd.concat([attack_ff, attack_nff], axis=1).iloc[:, new_index]

    dataframe = pd.concat([benign, attack])
    return dataframe


def normalize_std(x):
    return preprocessing.StandardScaler().fit_transform(x)


if __name__ == '__main__':
    #
    # for i in range(len(_FEATURES)):
    #     print(_FEATURES[i], '|', _FEATURES2[i])

    files = os.listdir('data/raw2017')
    packets = pd.DataFrame()
    for file in files:
        temp = pd.read_csv('./data/raw2017/' + file)
        temp.columns = _FEATURES + ['Label']
        temp.drop("Fwd Header Length.1", axis=1, inplace=True)
        temp.columns = _FEATURES2 + ['Label']
        print(file)
        print(temp['Label'].value_counts())
        print()
        packets = pd.concat([packets, temp], ignore_index=True)

    packets.to_csv('./data/raw2017/packets.csv', index=False)

    # save_path = f'./data/normed_w10o9_{name}.h5'
    # hf = h5py.File(save_path, 'w')
    # hf.create_dataset('data', data=dataX)
    # hf.create_dataset('label', data=dataY)
    # hf.close()

    # inputX = h5py.File(file_path, 'r').get('data')[:]
    # inputY = h5py.File(file_path, 'r').get('label')[:]

    print(packets['Label'].value_counts())
    # Determine the split indices
    split_indices = list((np.cumsum([0.0, 0.5, 0.5]) * len(packets)).astype(int))
    parts = []
    results = []
    for index in range(len(split_indices) - 1):
        part = packets.iloc[split_indices[index]:split_indices[index + 1]]

        results.append(part['Label'].value_counts())
        parts.append(part)

    # Split into train+val and test
    train_val_df, test_df = train_test_split(packets, test_size=0.2, stratify=packets['Label'], random_state=42)

    # Split train+val into train and validation
    train_df, val_df = train_test_split(train_val_df, test_size=0.25, stratify=train_val_df['Label'], random_state=42)

    # Display the parts
    print("Train set:")
    print(train_df['Label'].value_counts())
    print("\nValidation set:")
    print(val_df['Label'].value_counts())
    print("\nTest set:")
    print(test_df['Label'].value_counts())

    la = packets['Label'].unique()
    print(la)
    attack_class = 'ddos'
    attack_ff, attack_nff, benign_ff, benign_nff = split_features(packets, attack_class)

    dataframe = reassemble_features(attack_ff, attack_nff, benign_ff, benign_nff, attack_class)
    print()
