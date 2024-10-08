"""Contains definitions for classes related to Wasserstein GAN model."""

import itertools
import os
import numpy as np
from scores import get_binary_class_scores, print_scores
import time
import torch
import torch.nn as nn
import torch.optim as optim
from torch.autograd import Variable
from torch.utils.tensorboard import SummaryWriter

from data import reassemble_features
from train_ids import get_model

class myAttentionModule(nn.MultiheadAttention):
  def __init__(self, embed_dim, num_heads):
    super().__init__(embed_dim, num_heads, batch_first=True)

  def forward(self, x):
    x = torch.unsqueeze(x, 1)
    y, _ = super().forward(x, x, x)
    return torch.squeeze(y)


class Generator(nn.Module):
  """Generator in Wasserstein GAN."""

  def __init__(self, input_size, output_size):
    """Create a generator."""
    super(Generator, self).__init__()

    def block(input_dim, output_dim):
      layers = [nn.Linear(input_dim, output_dim)]
      layers.append(nn.ReLU(inplace=False))
      layers.append(nn.BatchNorm1d(output_dim))
      layers.append(nn.Dropout(0.2))
      return layers

    self.model = nn.Sequential(
      *block(input_size, 10),
      *block(10, 32),
      myAttentionModule(32, 2),
      *block(32, 64),
      nn.Linear(64, output_size),
    )

  def forward(self, x):
    """Do a forward pass."""
    adversarial_traffic = self.model(x)
    #, need_weights=False
    return adversarial_traffic


class Discriminator(nn.Module):
  """Discriminator in Wasserstein GAN."""

  def __init__(self, input_size):
    """Create a discriminator."""
    super(Discriminator, self).__init__()

    def block(input_dim, output_dim):
      layers = [nn.Linear(input_dim, output_dim)]
      layers.append(nn.ReLU(inplace=False))
      layers.append(nn.BatchNorm1d(output_dim))
      layers.append(nn.Dropout(0.2))

      return layers

    self.model = nn.Sequential(
      *block(input_size, 64),
      *block(64, 32),
      *block(32, 10),
      nn.Linear(10, 1)
    )

  def forward(self, x):
    """Do a forward pass."""
    traffic = self.model(x)
    return traffic


class WGAN(object):
  """Wasserstein GAN."""

  def __init__(self, options, n_attributes_gen, n_attributes_dis, attack_class):
    """Create a Wasserstein GAN."""
    self.attack_class = attack_class
    self.n_attributes_gen = n_attributes_gen
    self.n_attributes_dis = n_attributes_dis
    self.noise_dim = options.noise_dim
    self.generator = Generator(self.n_attributes_gen + self.noise_dim, self.n_attributes_gen)
    self.discriminator = Discriminator(self.n_attributes_dis)

    self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    self.generator.to(self.device)
    self.discriminator.to(self.device)

    self.epochs = options.epochs
    self.batch_size = options.batch_size
    self.learning_rate = options.learning_rate
    self.weight_clipping = options.weight_clipping
    self.critic_iter = options.critic_iter
    self.evaluate = options.evaluate

    self.optim_G = optim.RMSprop(self.generator.parameters(), lr=self.learning_rate)
    self.optim_D = optim.RMSprop(self.discriminator.parameters(), lr=self.learning_rate)

    self.writer_train = SummaryWriter(log_dir=f'runs/{options.name}/train')
    self.writer_val = SummaryWriter(log_dir=f'runs/{options.name}/val')

    self.start_epoch = 0

    self.checkpoint_directory = os.path.join(options.checkpoint_directory, options.name)
    self.checkpoint_interval_s = options.checkpoint_interval_s
    os.makedirs(self.checkpoint_directory, exist_ok=True)
    self.previous_checkpoint_time = time.time()
    if options.checkpoint is not None:
        self.load_checkpoint(options.checkpoint)

  def train(self, trainingset, validationset, ids_model):
    """Train Wasserstein GAN."""
    self.generator.train()
    self.discriminator.train()
    normal_attributes, normal_labels, attack_ff_attributes, attack_nff_attributes, attack_labels = self._extract_dataset(trainingset)
    normal_attributes_val, normal_labels_val, attack_ff_attributes_val, attack_nff_attributes_val, attack_labels_val = self._extract_dataset(validationset)
    epoch_iterator = self._get_epoch_iterator()
    for epoch in epoch_iterator:
      self._require_grad(self.discriminator, True)
      self._require_grad(self.generator, False)
      # Discriminator training
      for c in range(self.critic_iter):
        normal_batch = self._sample_normal_traffic(normal_attributes)
        attack_ff_batch, attack_nff_batch = self._sample_malicious_traffic(attack_ff_attributes, attack_nff_attributes)
        adversarial_batch = self.generator(attack_nff_batch)
        attack_batch = self._reassemble_features(attack_ff_batch, adversarial_batch)
        
        #Active
        frac = 0.05
        data = torch.cat((attack_batch, normal_batch), axis=0)
        uncertainties = -torch.abs(self.discriminator(data).squeeze())
        indices = uncertainties.argsort()[-int(len(data) * frac):]
        data = data[indices]
        ###

        data = data.cpu().detach().numpy()
        predictions = ids_model.predict(data)
        
        normal_batch = data[predictions == 1]
        attack_batch = data[predictions == 0]
        
        normal_batch = torch.Tensor(normal_batch).to(self.device)
        attack_batch = torch.Tensor(attack_batch).to(self.device)
        data = torch.cat((attack_batch, normal_batch), axis=0)
        W = torch.cat((torch.div(torch.ones(1, len(attack_batch)), -len(attack_batch)), torch.div(torch.ones(1, len(normal_batch)), len(normal_batch))), axis=1).to(self.device)

        # discriminated_normal = torch.mean(self.discriminator(normal_batch)).view(1)
        # discriminated_adversarial = torch.mean(self.discriminator(attack_batch)).view(1)
        # discriminator_loss = - (discriminated_normal - discriminated_adversarial)
        discriminator_loss = - torch.matmul(W, self.discriminator(data)).view(1)
        self.optim_D.zero_grad()
        discriminator_loss.backward()
        self.optim_D.step()
        for p in self.discriminator.parameters():
          p.data.clamp_(-self.weight_clipping, self.weight_clipping)
      # Generator training
      self._require_grad(self.discriminator, False)
      self._require_grad(self.generator, True)
      attack_ff_batch, attack_nff_batch = self._sample_malicious_traffic(attack_ff_attributes, attack_nff_attributes)
      adversarial_batch = self.generator(attack_nff_batch)
      attack_batch = self._reassemble_features(attack_ff_batch, adversarial_batch)
      generator_objective = torch.mean(self.discriminator(attack_batch)).view(1)
      generator_loss = - generator_objective
      self.optim_G.zero_grad()
      generator_loss.backward()
      self.optim_G.step()

      if epoch % self.evaluate == 0:
        self.generator.eval()
        self.discriminator.eval()
        stats_train = self._log_stats_to_tensorboard(self.writer_train, epoch, normal_attributes, normal_labels, attack_ff_attributes, attack_nff_attributes, attack_labels)
        stats_val = self._log_stats_to_tensorboard(self.writer_val, epoch, normal_attributes_val, normal_labels_val, attack_ff_attributes_val, attack_nff_attributes_val, attack_labels_val)
        self._add_scalars(self.writer_train, epoch, *stats_train)
        self._add_scalars(self.writer_val, epoch, *stats_val)
        self.generator.train()
        self.discriminator.train()

      current_time = time.time()
      if self.checkpoint_interval_s <= current_time - self.previous_checkpoint_time:
        self.save_checkpoint(epoch + 1)
        self.previous_checkpoint_time = time.time()
  
  def _reassemble_features(self, attack_ff_batch, attack_nff_batch):
    attack_batch = reassemble_features(attack_ff_batch, attack_nff_batch, self.attack_class)
    return attack_batch

  def _add_scalars(self, writer, epoch, d_adv_mean, d_normal_mean, d_objective, g_objective):
    writer.add_scalar('discriminator/adversarial_mean', d_adv_mean, epoch)
    writer.add_scalar('discriminator/normal_mean', d_normal_mean, epoch)
    writer.add_scalar('discriminator/objective', d_objective, epoch)
    writer.add_scalar('generator/objective', g_objective, epoch)

  def _extract_dataset(self, dataset):
    normal_attributes, normal_labels, attack_ff_attributes, attack_nff_attributes, attack_labels = dataset
    # normal_labels = 1 - normal_labels
    # malicious_labels = 1 - malicious_labels
    normal_attributes_tensor = torch.tensor(normal_attributes, dtype=torch.float, requires_grad=True).to(self.device)
    attack_ff_attributes_tensor = torch.tensor(attack_ff_attributes, dtype=torch.float, requires_grad=True).to(self.device)
    attack_nff_attributes_tensor = torch.tensor(attack_nff_attributes, dtype=torch.float, requires_grad=True).to(self.device)
    return normal_attributes_tensor, normal_labels, attack_ff_attributes_tensor, attack_nff_attributes_tensor, attack_labels

  def _get_epoch_iterator(self):
      if self.epochs < 0:
          return itertools.count(self.start_epoch)
      else:
          return range(self.start_epoch, self.epochs)

  def _sample_normal_traffic(self, traffic):
    indices = np.random.randint(0, len(traffic), self.batch_size)
    return traffic[indices]

  def _sample_malicious_traffic(self, traffic_ff, traffic_nff):
    indices = np.random.randint(0, len(traffic_ff), self.batch_size)
    batch_ff = traffic_ff[indices]
    batch_nff = traffic_nff[indices]
    noise = torch.rand(self.batch_size, self.noise_dim).to(self.device)
    batch_with_noise = torch.cat((batch_nff, noise), 1)
    return batch_ff, batch_with_noise

  def _require_grad(self, module, require):
    for parameter in module.parameters():
      parameter.requires_grad = require

  def _log_stats_to_tensorboard(self, writer, epoch, normal_attributes, normal_labels, attack_ff_attributes, attack_nff_attributes, attack_labels):
      noise = torch.rand(len(attack_nff_attributes), self.noise_dim).to(self.device)
      malicious_noise = torch.cat((attack_nff_attributes, noise), 1)
      adversarial_traffic = self.generator(malicious_noise)
      attack_attributes = self._reassemble_features(attack_ff_attributes, adversarial_traffic)

      discriminated_adversarial_mean = torch.mean(self.discriminator(attack_attributes))
      discriminated_normal_mean = torch.mean(self.discriminator(normal_attributes))
      discriminator_objective = discriminated_normal_mean - discriminated_adversarial_mean
      generator_objective = discriminated_adversarial_mean

      predictions_adversarial = self.predict(attack_attributes)
      accuracy, f1, precision, recall, _ = get_binary_class_scores(attack_labels, predictions_adversarial)
      writer.add_scalar('scores_adversarial/accuracy', accuracy, epoch)
      writer.add_scalar('scores_adversarial/f1', f1, epoch)
      writer.add_scalar('scores_adversarial/precision', precision, epoch)
      writer.add_scalar('scores_adversarial/recall', recall, epoch)

      predictions_normal = self.predict(normal_attributes)
      accuracy, f1, precision, recall, _ = get_binary_class_scores(normal_labels, predictions_normal)
      writer.add_scalar('scores_normal/accuracy', accuracy, epoch)
      writer.add_scalar('scores_normal/f1', f1, epoch)
      writer.add_scalar('scores_normal/precision', precision, epoch)
      writer.add_scalar('scores_normal/recall', recall, epoch)

      return discriminated_adversarial_mean, discriminated_normal_mean, discriminator_objective, generator_objective

  def predict(self, traffic):
    """Use discriminator to predict whether real or fake."""
    outputs = self.discriminator(traffic).squeeze()
    predictions = torch.empty((len(outputs),), dtype=torch.uint8)
    predictions[outputs < 0] = 0   # adversarial traffic
    predictions[outputs >= 0] = 1  # normal traffic
    return predictions.cpu().numpy()

  def predict_normal_and_adversarial(self, normal_traffic, malicious_traffic):
    """Use generator to make adversarial traffic and return predictions from discriminator on the combination of normal and adversarial traffic."""
    self.generator.eval()
    self.discriminator.eval()
    n_observations_mal = len(malicious_traffic)
    batch_Malicious = torch.from_numpy(malicious_traffic).float()
    noise = Variable(torch.rand(n_observations_mal, self.noise_dim))
    batch_Malicious_noise = torch.cat((batch_Malicious, noise), 1)
    batch_Malicious_noise = Variable(batch_Malicious_noise.to(self.device))

    adversarial = self.generator(batch_Malicious_noise)
    input_disc = Variable(torch.Tensor(np.concatenate((normal_traffic, adversarial.cpu().detach().numpy()), axis=0)))
    input_disc = Variable(input_disc.to(self.device))
    outputs = self.discriminator(input_disc)

    predictions = torch.empty_like(outputs)
    predictions[outputs < 0] =  0
    predictions[outputs >= 0] = 1
    return predictions.cpu().numpy()

  def generate(self, attack_ff_attributes, attack_nff_attributes):
    """Generate adversarial traffic."""
    self.generator.eval()
    self.discriminator.eval()

    n_observations_mal = len(attack_nff_attributes)

    attack_ff_attributes = torch.Tensor(attack_ff_attributes).to(self.device)
    attack_nff_attributes = torch.Tensor(attack_nff_attributes).to(self.device)

    noise = torch.rand(n_observations_mal, self.noise_dim).to(self.device)
    batch_Malicious_noise = torch.cat((attack_nff_attributes, noise), 1)
    batch_Malicious_noise = Variable(batch_Malicious_noise.to(self.device))

    adversarial = self.generator(batch_Malicious_noise)
    attack_attributes = self._reassemble_features(attack_ff_attributes, adversarial)
    return attack_attributes.cpu()

  def save(self, path):
    """Save model."""
    os.makedirs(path, exist_ok=True)
    torch.save(self.generator.state_dict(), path + '/generator.pt')
    torch.save(self.discriminator.state_dict(), path + '/discriminator.pt')

  def load(self, path):
    """Load model from a file."""
    self.generator.load_state_dict(torch.load(path + '/generator.pt'))
    self.discriminator.load_state_dict(torch.load(path + '/discriminator.pt'))

  def load_checkpoint(self, checkpoint_path):
    """Load a checkpoint from a file."""
    checkpoint = torch.load(checkpoint_path)
    self.generator.load_state_dict(checkpoint['generator'])
    self.discriminator.load_state_dict(checkpoint['discriminator'])
    self.optim_G.load_state_dict(checkpoint['generator_optimizer'])
    self.optim_D.load_state_dict(checkpoint['discriminator_optimizer'])
    self.start_epoch = checkpoint['epoch']

  def save_checkpoint(self, epoch):
    """Save a checkpoint."""
    checkpoint = {
      'generator': self.generator.state_dict(),
      'discriminator': self.discriminator.state_dict(),
      'generator_optimizer': self.optim_G.state_dict(),
      'discriminator_optimizer': self.optim_D.state_dict(),
      'epoch': epoch,
    }
    checkpoint_path = os.path.join(self.checkpoint_directory, f'epoch_{epoch}.pt')
    torch.save(checkpoint, checkpoint_path)

