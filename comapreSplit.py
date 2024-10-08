import numpy as np

FEATURES = ['Destination Port', 'Flow Duration', 'Total Fwd Packets',
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

_FEATURES = np.array(FEATURES)
# Categorize the features
intrinsic_features = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std'
]

content_features = [
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'CWE Flag Count', 'ECE Flag Count'
]

time_based_features = [
    'Flow Bytes/s', 'Flow Packets/s', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
    'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

host_based_features = [
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
    'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
    'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward'
]

labels = ['Label']

# Function to get functional and non-functional features based on attack type
def get_features_by_attack_type1(attack_type):
    if attack_type == 'DoS':
        functional_features = intrinsic_features + time_based_features + [
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd Header Length', 'Bwd Header Length', 'SYN Flag Count', 'RST Flag Count']
        non_functional_features = list(_FEATURES - set(functional_features) - set(labels))
    elif attack_type == 'Web Attack':
        functional_features = content_features + [
            'PSH Flag Count', 'ACK Flag Count', 'ECE Flag Count']
        non_functional_features = list(_FEATURES - set(functional_features) - set(labels))
    elif attack_type == 'Infiltration':
        functional_features = intrinsic_features + time_based_features + [
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd Header Length', 'Bwd Header Length']
        non_functional_features = list(_FEATURES - set(functional_features) - set(labels))
    elif attack_type == 'Port Scan':
        functional_features = intrinsic_features + [
            'SYN Flag Count', 'Fwd Header Length', 'Bwd Header Length']
        non_functional_features = list(_FEATURES - set(functional_features) - set(labels))
    elif attack_type == 'Brute Force':
        functional_features = intrinsic_features + content_features + [
            'PSH Flag Count', 'ACK Flag Count']
        non_functional_features = list(_FEATURES - set(functional_features) - set(labels))
    elif attack_type == 'Bot':
        functional_features = intrinsic_features + time_based_features + [
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd Header Length', 'Bwd Header Length', 'SYN Flag Count']
        non_functional_features = list(_FEATURES - set(functional_features) - set(labels))
    elif attack_type == 'BENIGN':
        functional_features = intrinsic_features + content_features + time_based_features + host_based_features
        non_functional_features = list(_FEATURES - set(functional_features) - set(labels))
    return functional_features, non_functional_features


# Define a function to get the functional and non-functional features based on attack type
def get_features_by_attack_type2(attack_type):
    if attack_type == 'DoS':
        functional_features = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                               'Flow Bytes/s', 'Flow Packets/s', 'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
                               'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd Header Length', 'Bwd Header Length',
                               'Fwd Packets/s', 'Bwd Packets/s', 'SYN Flag Count', 'RST Flag Count']
        non_functional_features = ['Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
                                   'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
                                   'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std',
                                   'Idle Max', 'Idle Min']
    elif attack_type == 'Web Attack':
        functional_features = ['Destination Port', 'Flow Duration', 'Total Length of Fwd Packets',
                               'Fwd Packet Length Min', 'Fwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Max',
                               'PSH Flag Count', 'ACK Flag Count', 'ECE Flag Count']
        non_functional_features = ['Fwd IAT Std', 'Bwd IAT Std', 'Active Min', 'Idle Std', 'Min Packet Length',
                                   'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
                                   'CWE Flag Count', 'Down/Up Ratio']
    elif attack_type == 'Infiltration':
        functional_features = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                               'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Flow Bytes/s', 'Flow Packets/s',
                               'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd Packets/s', 'Bwd Packets/s']
        non_functional_features = ['Fwd IAT Mean', 'Bwd IAT Mean', 'Active Mean', 'Idle Mean',
                                   'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
                                   'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward']
    elif attack_type == 'Port Scan':
        functional_features = ['Destination Port', 'Total Fwd Packets', 'Total Backward Packets',
                               'Flow Packets/s', 'Fwd Header Length', 'Bwd Header Length', 'SYN Flag Count']
        non_functional_features = ['Fwd IAT Total', 'Bwd IAT Total', 'Active Std', 'Idle Std',
                                   'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
                                   'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward']
    elif attack_type == 'Brute Force':
        functional_features = ['Destination Port', 'Flow Duration', 'Total Length of Fwd Packets',
                               'Fwd Packet Length Min', 'Fwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Max',
                               'PSH Flag Count', 'ACK Flag Count']
        non_functional_features = ['Fwd IAT Std', 'Bwd IAT Std', 'Active Max', 'Idle Max',
                                   'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
                                   'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward']
    elif attack_type == 'Bot':
        functional_features = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                               'Flow Bytes/s', 'Flow Packets/s', 'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
                               'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd Packets/s', 'Bwd Packets/s', 'SYN Flag Count']
        non_functional_features = ['Fwd IAT Mean', 'Bwd IAT Mean', 'Active Mean', 'Idle Mean',
                                   'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
                                   'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward']
    elif attack_type == 'BENIGN':
        functional_features = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Fwd Header Length',
            'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s'
        ]
        non_functional_features = [
            'Fwd IAT Total', 'Bwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Bwd IAT Mean',
            'Bwd IAT Std', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]
    return functional_features, non_functional_features


# Function to compare feature sets
def compare_feature_sets(attack_type):
    func_feat1, non_func_feat1 = get_features_by_attack_type1(attack_type)
    func_feat2, non_func_feat2 = get_features_by_attack_type2(attack_type)

    func_equal = set(func_feat1) == set(func_feat2)
    non_func_equal = set(non_func_feat1) == set(non_func_feat2)

    report = {
        'attack_type': attack_type,
        'featuresNum1': len(func_feat1 + non_func_feat1),
        'featuresNum2': len(func_feat2 + non_func_feat2)
    }
    # report = {
    #     'attack_type': attack_type,
    #     'functional_equal': func_equal,
    #     'non_functional_equal': non_func_equal,
    #     'functional_diff_Num': len(set(func_feat1).difference(func_feat2)) if not func_equal else None,
    #     'functional_diff': set(func_feat1).difference(func_feat2) if not func_equal else None,
    #     'non_functional_diff': set(non_func_feat1).difference(non_func_feat2) if not non_func_equal else None,
    #     'functional_count_1': len(func_feat1),
    #     'functional_count_2': len(func_feat2),
    #     'non_functional_count_1': len(non_func_feat1),
    #     'non_functional_count_2': len(non_func_feat2)
    # }

    return report


# Attack types to compare
attack_types = ['BENIGN','Bot','Brute Force','Port Scan','Infiltration','Web Attack','DoS']

# Generate and print comparison report
# comparison_reports = [compare_feature_sets(attack_type) for attack_type in attack_types]
# print(comparison_reports)

# Function to count total features in a given array
def count_features(features):
    return len(features)

# Counting features in each category
total_features = count_features(FEATURES)

print(f"Total number of features: {total_features}")
print("List of features:")
print(FEATURES)