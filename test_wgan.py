import ids
from data import load_test, preprocess, split_features, get_attack, load_val
from model import WGAN
from train_wgan import parse_arguments
import numpy as np
import pandas as pd
from scores import get_binary_class_scores
from tabulate import tabulate
from test_ids import parse_arguments as parse_test_ids_arguments
import os, sys

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
    test_ids(options)

def test_ids(options):
    attack_class = get_attack(options.attack)
    
    arguments = ['--config', dict(IDS_CONFIGS)[options.ids]]
    ids_options = parse_test_ids_arguments(arguments)

    attributes, labels = preprocess(load_val(wgan=True), normalize=ids_options.normalize, attack_class=attack_class)
    normal_attributes = attributes[labels == 1]
    attack_attributes = attributes[labels == 0]
    normal_labels = labels[labels == 1]
    attack_labels = labels[labels == 0]
    attack_ff_attributes, attack_nff_attributes = split_features(attack_attributes, attack_class)

    n_attributes_dis = attack_attributes.shape[1]
    n_attributes_gen = attack_nff_attributes.shape[1]
    
    model = WGAN(options, n_attributes_gen, n_attributes_dis, attack_class)
    #model.load_checkpoint(options.checkpoint)
    load_model_directory = os.path.join(options.save_model, options.name)
    model.load(load_model_directory)
    
    attack_attributes = model.generate(attack_ff_attributes, attack_nff_attributes).detach()
    data = np.concatenate((attack_attributes, normal_attributes), axis=0)
    labels = np.concatenate((attack_labels, normal_labels), axis=0)
    
    #tester = get_tester(options.attack, data, labels)
    #results = list(map(tester, IDS_CONFIGS))
    #results = [tester(IDS_CONFIGS[5])]
    scores = test(ids_options, data, labels)
    results = [[options.ids, *scores]]
    save_results(results, f'results/{options.name}.csv')
    print_results(results)

def get_tester(attack, data, labels):
    def tester(configuration):
        name, config_path = configuration
        arguments = ['--config', config_path]
        if attack is not None:
            arguments.append('--attack')
            arguments.append(attack)
        options = parse_test_ids_arguments(arguments)
        scores = test(options, data, labels)
        named_scores = [name, *scores]
        return named_scores
    return tester

def test(options, data, labels):
    n_attributes = data.shape[1]
    model = get_model(options, n_attributes)
    model.load(options.save_model)
    predictions = model.predict(data)
    return get_binary_class_scores(labels, predictions)

def get_model(options, n_features):
    algorithm = options.algorithm
    if algorithm == 'baseline':
        return ids.Baseline()
    elif algorithm == 'dt':
        return ids.DecisionTree(
            max_depth=options.max_depth,
            split_criterion=options.split_criterion,
            splitter=options.splitter,
            min_samples_leaf=options.min_samples_leaf,
            min_samples_split=options.min_samples_split
        )
    elif algorithm == 'knn':
        return ids.KNearestNeighbours(
            algorithm=options.knn_algorithm,
            n_neighbors=options.n_neighbors,
            weights=options.knn_weights
        )
    elif algorithm == 'lr':
        return ids.LogisticRegression(
            max_iter=options.iterations,
            solver=options.lr_solver
        )
    elif algorithm == 'mlp':
        return ids.MultiLayerPerceptron(
            input_size=n_features,
            log_dir=options.log_dir,
            log_every=options.log_every,
            evaluate_every=options.evaluate_every,
            epochs=options.epochs,
            batch_size=options.batch_size,
            learning_rate=options.learning_rate,
            weight_decay=options.weight_decay,
            dropout_rate=options.dropout_rate,
            hidden_size=options.hidden_size
        )
    elif algorithm == 'nb':
        return ids.NaiveBayes()
    elif algorithm == 'rf':
        return ids.RandomForest(
            n_trees=options.n_trees,
            max_depth=options.max_depth,
            split_criterion=options.split_criterion,
            min_samples_leaf=options.min_samples_leaf,
            min_samples_split=options.min_samples_split
        )
    elif algorithm == 'svm':
        return ids.SupportVectorMachine(max_iter=options.iterations)
    else:
        raise Exception(f'"{algorithm}" is not a valid choice of algorithm.')

def print_results(results):
    rows = list(map(format_result, results))
    headers = ['algorithm', 'accuracy', 'f1', 'precision', 'recall', 'detection_rate']
    print(tabulate(rows, headers=headers))

def save_results(results, options):
    columns = ['algorithm', 'accuracy', 'f1', 'precision', 'recall', 'detection_rate']
    dataframe = pd.DataFrame(results, columns=columns)
    with open(options, 'w') as result_file:
        dataframe.to_csv(result_file, index=False)

def format_result(result):
    scores = map(lambda score: f'{score:0.4f}', result[1:])
    formatted_result = [result[0], *scores]
    return formatted_result

if __name__ == '__main__':
    main()
