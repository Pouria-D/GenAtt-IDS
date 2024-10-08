from functools import partial
import numpy as np
from operator import itemgetter
import pandas as pd
from sklearn import preprocessing
import h5py
import torch

_FEATURES = ['Dst Port', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
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
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']

_BENIGN = ['BENIGN', 'Benign']
_BOT = ['Bot']
_BRUTE = ['FTP-Patator', 'SSH-Patator', 'FTP-BruteForce', 'SSH-Bruteforce']
_DDOS = ['DDoS', 'DDOS attack-LOIC-UDP', 'DDOS attack-HOIC']
_DOS = ['DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest', 'DoS slowloris', 'Heartbleed', 'DoS attacks-GoldenEye', 'DoS attacks-Hulk', 'DoS attacks-Slowloris', 'DoS attacks-SlowHTTPTest']
_PROBE = ['PortScan']
_WEB = ['Web Attack � Brute Force', 'Web Attack � XSS', 'Web Attack � Sql Injection', 'Brute Force -Web', 'Brute Force -XSS', 'SQL Injection']
_INFL = ['Infiltration', 'Infilteration']

_BOT_FF = [0, 1, 2, 3, 4, 5, 14, 15, 36, 37, 58, 59, 60, 61, 62, 63, 64]
_BRUTE_FF = [0, 1, 2, 3, 14, 15, 8, 12, 36, 37, 43, 44, 45, 46, 47, 48, 56, 57, 58, 59]
_DDOS_FF = [0, 1, 2, 3, 4, 5, 8, 12, 14, 15, 16, 20, 21, 25, 26, 34, 35, 40, 44, 45, 46, 47, 61, 62, 63, 64, 67]
_DOS_FF = [0, 1, 2, 3, 8, 12, 14, 15, 21, 26, 34, 35, 44, 46, 47]
_PROBE_FF = [0, 1, 2, 3, 4, 5, 14, 15, 16, 17, 18, 19, 34, 35, 36, 37, 43, 44, 45, 48]
_WEB_FF = [0, 1, 2, 4, 8, 9, 14, 15, 16, 17, 18, 19, 40, 44, 45, 52, 53, 59, 61]
_INFL_FF = [0, 1, 2, 3, 4, 5, 14, 15, 16, 17, 30, 31, 38, 39, 40, 42, 44, 46, 50, 58, 60, 62, 63]

#         0        1     2       3      4     5       6     7
_LABEL = [_BENIGN, _BOT, _BRUTE, _DDOS, _DOS, _PROBE, _WEB, _INFL]
_ATTACK_FF = [list(range(len(_FEATURES) - 1)), _BOT_FF, _BRUTE_FF, _DDOS_FF, _DOS_FF, _PROBE_FF, _WEB_FF, _INFL_FF]

# 2018    0        1      2     3     4      5     
_LABEL = [_BENIGN, _DDOS, _DOS, _BOT, _INFL, _BRUTE]
_ATTACK_FF = [list(range(len(_FEATURES) - 1)), _DDOS_FF, _DOS_FF, _BOT_FF, _INFL_FF, _BRUTE_FF]

def load_train(wgan=False):
    """
    Loads trainingset as a Pandas dataframe.
    """
    name = 'wgan_train' if wgan else 'ids_train'
    with h5py.File(f"data/{name}.h5", 'r') as h5file:
        array = h5file['train'][:]
    return pd.DataFrame(array, columns=_FEATURES)


def load_test():
    """
    Loads testset as a Pandas dataframe.
    """
    
    with h5py.File("data/test.h5", 'r') as h5file:
        array = h5file['test'][:]
    return pd.DataFrame(array, columns=_FEATURES)


def load_val(wgan=False):
    """
    Loads validationset as a Pandas dataframe.
    """
    name = 'wgan_valid' if wgan else 'ids_valid'
    with h5py.File(f"data/{name}.h5", 'r') as h5file:
        array = h5file['valid'][:]
    return pd.DataFrame(array, columns=_FEATURES)


def preprocess(dataframe, normalize=False, attack_class=None):
    """
    Preprocesses data.
    Performs these operations:
    * Normalize numeric attributes unless specified otherwise.
    * Splits data into: attributes, attack_class.
    * Makes attack class binary (in accordance with the selected attack class).
    :param dataframe: data
    :param normalize: flag if the numerical attributes should be normalized (default false)
    :return: attributes, binary attack class
    :rtype: (ndarray, ndarray)
    """

    # split into (attributes, attack_class) and remove class from attributes
    attributes_dataframe = dataframe.drop(columns=['Label'])
    attack_class_dataframe = dataframe['Label']

    # keep normal and specified attack data and drop other if attal_class is set
    if attack_class is not None:
      attributes_dataframe = attributes_dataframe[attack_class_dataframe.isin([0, attack_class])]
      attack_class_dataframe = attack_class_dataframe[attack_class_dataframe.isin([0, attack_class])]

    # make attack class binary (1 = normal, 0 = malicious)
    binary_attack_class = np.zeros_like(attack_class_dataframe, dtype=bool)
    binary_attack_class[attack_class_dataframe == 0] = 1

    attributes = attributes_dataframe.to_numpy().astype(float)

    # normalize
    if normalize:
        # load training set since the numeric columns should be standardized in accordance with the training set,
        # and we do not know if the dataframe represents the training set
        
        with h5py.File(f"data/norm.h5", 'r') as h5file:
            mean = h5file['mean'][:]
            std = h5file['std'][:]
            
            # handle zero std columns
            zero_std_mask = std == 0
            std[zero_std_mask] = 1

            attributes = (attributes - mean) / std
            attributes[:, zero_std_mask] = 0

    return attributes, binary_attack_class


def get_attack(attack_type):
    if attack_type is None:
      return None
    if attack_type.casefold() == 'ddos':
        return 1
    elif attack_type.casefold() == 'dos':
        return 2
    elif attack_type.casefold() == 'bot':
        return 3
    elif attack_type.casefold() == 'infl':
        return 4
    elif attack_type.casefold() == 'brute':
        return 5
    else:
        return None


def get_attack2(attack_type):
    if attack_type.casefold() == 'bot':
        return 1
    elif attack_type.casefold() == 'brute':
        return 2
    elif attack_type.casefold() == 'ddos':
        return 3
    elif attack_type.casefold() == 'dos':
        return 4
    elif attack_type.casefold() == 'probe':
        return 5
    elif attack_type.casefold() == 'web':
        return 6
    elif attack_type.casefold() == 'infl':
        return 7
    else:
        raise Exception("Invalid attack type. (bot/brute/ddos/dos/probe/web/infl)")
        return None


def split_features(dataframe, attack_class):
    ff_features = _ATTACK_FF[attack_class]
    nff_features = [i for i in range(len(_FEATURES) - 1) if i not in ff_features]

    dataframe_ff = dataframe[:, ff_features]
    dataframe_nff = dataframe[:, nff_features]

    return dataframe_ff, dataframe_nff

    
def reassemble_features(attack_ff, attack_nff, attack_class):
    ff_features = _ATTACK_FF[attack_class]
    nff_features = [i for i in range(len(_FEATURES) - 1) if i not in ff_features]
    new_index = [(ff_features + nff_features).index(i) for i in range(len(_FEATURES) - 1)]

    attack = torch.cat((attack_ff, attack_nff), 1)[:, new_index]

    return attack

