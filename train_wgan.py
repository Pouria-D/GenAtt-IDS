import configargparse
from data import load_train, load_val, preprocess, split_features, reassemble_features, get_attack
from model import WGAN
import os, sys
import yaml
from test_ids import parse_arguments as parse_test_ids_arguments
from train_ids import get_model
from scores import get_binary_class_scores, print_scores

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
    attack_class = get_attack(options.attack)

    arguments = ['--config', dict(IDS_CONFIGS)[options.ids]]
    ids_options = parse_test_ids_arguments(arguments)

    attributes, labels = preprocess(load_train(wgan=True), normalize=ids_options.normalize, attack_class=attack_class)
    normal_attributes = attributes[labels == 1]
    attack_attributes = attributes[labels == 0]
    normal_labels = labels[labels == 1]
    attack_labels = labels[labels == 0]
    attack_ff_attributes, attack_nff_attributes = split_features(attack_attributes, attack_class)
    trainingset = (normal_attributes, normal_labels, attack_ff_attributes, attack_nff_attributes, attack_labels)

    attributes, labels = preprocess(load_val(wgan=True), normalize=ids_options.normalize, attack_class=attack_class)
    normal_attributes = attributes[labels == 1]
    attack_attributes = attributes[labels == 0]
    normal_labels = labels[labels == 1]
    attack_labels = labels[labels == 0]
    attack_ff_attributes, attack_nff_attributes = split_features(attack_attributes, attack_class)
    validationset = (normal_attributes, normal_labels, attack_ff_attributes, attack_nff_attributes, attack_labels)

    n_attributes_dis = attack_attributes.shape[1]
    n_attributes_gen = attack_nff_attributes.shape[1]
    
    ids_model = get_model(ids_options, n_attributes_dis)
    ids_model.load(ids_options.save_model)

    # predictions = ids_model.predict(attack_attributes)
    # print_scores(get_binary_class_scores(attack_labels, predictions))

    model = WGAN(options, n_attributes_gen, n_attributes_dis, attack_class)
    model.train(trainingset, validationset, ids_model)

    # save model
    if options.save_model is not None:
        save_model_directory = os.path.join(options.save_model, options.name)
        os.makedirs(save_model_directory, exist_ok=True)
        model.save(save_model_directory)

def parse_arguments(arguments):
    parser = configargparse.ArgParser(config_file_parser_class=configargparse.YAMLConfigFileParser)
    parser.add('--ids', required=True, help='ids model')
    parser.add('--config', required=False, is_config_file=True, help='config file path')
    parser.add('--save_config', required=False, default=None, type=str, help='path of config file where arguments can be saved')
    parser.add('--save_model', required=False, default=None, type=str, help='path of file to save trained model')
    parser.add('--normalize', required=False, action='store_true', default=False, help='normalize data (default false)')
    parser.add('--attack', required=True, default='Probe', help='selected attack')
    parser.add('--name', required=True, type=str, help='Unique name of the experiment.')
    parser.add('--checkpoint', required=False, type=str, default=None, help='path to load checkpoint from')
    parser.add('--checkpoint_directory', required=False, type=str, default='checkpoints/', help='path to checkpoints directory (default: checkpoints/)')
    parser.add('--checkpoint_interval_s', required=False, type=int, default=1800, help='seconds between saving checkpoints (default: 1800)')
    parser.add('--evaluate', required=False, type=int, default=200, help='number of epochs between evaluating on validation set (default: 200)')
    parse_wgan_arguments(parser)
    options = parser.parse_args(arguments)

    # remove keys that should not be saved to config file
    save_config = options.save_config
    del options.config
    del options.save_config

    # save config file
    if save_config is not None:
        with open(save_config, 'w') as config_file:
            yaml.dump(vars(options), config_file)

    return options

def parse_wgan_arguments(parser):
    wgan_group = parser.add_argument_group('wgan')
    wgan_group.add('--epochs', required=False, default=100, type=int, help='epochs of training (default 100), set to -1 to continue until manually stopped')
    wgan_group.add('--batch_size', required=False, default=64, type=int, help='batch size (default 64)')
    wgan_group.add('--learning_rate', required=False, default=0.0001, type=float, help='learning rate (default 0.0001)')
    wgan_group.add('--weight_clipping', required=False, default=0.01, type=float, help='weight clipping threshold (default 0.01)')
    wgan_group.add('--noise_dim', required=False, default=9, type=int, help='dimension of the noise vector (default 9)')
    wgan_group.add('--critic_iter', required=False, default=5, type=int, help='Number of critic iteration per epoch (default 5)')

if __name__ == '__main__':
    main()
