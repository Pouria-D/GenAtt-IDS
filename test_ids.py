import configargparse
from data import load_test, preprocess, get_attack, load_val
import ids
import pandas as pd
from train_ids import get_model, parse_ids_arguments
from scores import get_binary_class_scores, print_scores
import sys

IDS_CONFIGS = [
    ('baseline', 'configs/baseline.yaml'),
    ('decision_tree', 'configs/decision_tree.yaml'),
    ('k_nearest_neighbors', 'configs/k_nearest_neighbors.yaml'),
    ('logistic_regression', 'configs/logistic_regression.yaml'),
    ('multi_layer_perceptron', 'configs/multi_layer_perceptron.yaml'),
    ('naive_bayes', 'configs/naive_bayes.yaml'),
    ('random_forest', 'configs/random_forest.yaml'),
    ('support_vector_machine', 'configs/support_vector_machine.yaml')
]

def main():
    arguments = sys.argv[1:]
    options = parse_arguments(arguments)
    arguments += ['--config', dict(IDS_CONFIGS)[options.ids]]
    options = parse_arguments(arguments)
    scores = test(options)
    print_scores(scores)


def test(options):
    attack_class = get_attack(options.attack)
    attributes, labels = preprocess(load_val(wgan=True), normalize=options.normalize, attack_class=attack_class)
    n_attributes = attributes.shape[1]
    model = get_model(options, n_attributes)
    model.load(options.save_model)
    predictions = model.predict(attributes)
    return get_binary_class_scores(labels, predictions)


def test_wgan(options, dataframe):
    attributes, labels = preprocess(dataframe, normalize=options.normalize)
    n_attributes = attributes.shape[1]
    model = get_model(options, n_attributes)
    model.load(options.save_model)
    predictions = model.predict(attributes)
    return get_binary_class_scores(labels, predictions)


def parse_arguments(arguments):
    parser = configargparse.ArgParser(config_file_parser_class=configargparse.YAMLConfigFileParser)
    parser.add('--ids', required=False, help='ids model')
    parser.add('--algorithm', required=False, choices=['baseline', 'dt', 'knn', 'lr', 'mlp', 'nb', 'rf', 'svm'], help='algorithm to train')
    parser.add('--save_model', required=False, default=None, type=str, help='path of file to save trained model')
    parser.add('--config', required=False, is_config_file=True, help='config file path')
    parser.add('--attack', required=False, default=None, help='select attack class to only evaluate on this attack class (default evaluate on all)')
    parser.add('--normalize', required=False, action='store_true', default=False, help='normalize data (default false)')
    parse_ids_arguments(parser)
    options = parser.parse_args(arguments)
    return options


def load_data(options):
    data = load_test()
    if options.attack is not None:
        data = data[data.attack_class.isin(['Benign', options.attack])]
    return preprocess(data, normalize=options.normalize)


if __name__ == '__main__':
    main()
