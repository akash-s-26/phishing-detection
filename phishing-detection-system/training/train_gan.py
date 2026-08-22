"""
training/train_gan.py
PhishGuard AI — GAN Data Augmentation Training Script
Trains Generator and Discriminator neural networks on real phishing training sequence representations.
"""

import os
import json
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

LATENT_DIM = 64
EPOCHS = 15
BATCH_SIZE = 256
LEARNING_RATE = 0.0002

class GANGenerator(nn.Module):
    def __init__(self, latent_dim=LATENT_DIM, seq_len=150):
        super(GANGenerator, self).__init__()
        self.seq_len = seq_len
        self.net = nn.Sequential(
            nn.Linear(latent_dim, 128),
            nn.BatchNorm1d(128),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(128, 256),
            nn.BatchNorm1d(256),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(256, seq_len),
            nn.Tanh()
        )

    def forward(self, z):
        return self.net(z)


class GANDiscriminator(nn.Module):
    def __init__(self, seq_len=150):
        super(GANDiscriminator, self).__init__()
        self.net = nn.Sequential(
            nn.Linear(seq_len, 256),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(128, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.net(x)


def train_gan():
    base_dir = os.path.dirname(__file__)
    data_path = os.path.join(base_dir, 'processed_data', 'dataset_splits.npz')
    models_dir = os.path.join(base_dir, '..', 'models')
    os.makedirs(models_dir, exist_ok=True)

    print("=" * 70)
    print("PHISHGUARD AI: GAN MODEL TRAINING (PHISHING SYNTHETIC AUGMENTATION)")
    print("=" * 70)

    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Data splits not found at {data_path}. Run preprocess.py first.")

    data = np.load(data_path)
    X_seq_train = data['X_seq_train']
    y_train = data['y_train']

    # Filter real phishing training samples only (label == 1)
    phish_indices = np.where(y_train == 1)[0]
    X_phish = X_seq_train[phish_indices].astype(np.float32) / 100.0  # Normalize sequence values for Tanh activation
    seq_len = X_phish.shape[1]

    print(f"Loaded {len(X_phish)} real phishing training samples for GAN training.")

    dataset = TensorDataset(torch.tensor(X_phish, dtype=torch.float32))
    dataloader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True, drop_last=True)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using compute device: {device}")

    generator = GANGenerator(latent_dim=LATENT_DIM, seq_len=seq_len).to(device)
    discriminator = GANDiscriminator(seq_len=seq_len).to(device)

    criterion = nn.BCELoss()
    opt_g = optim.Adam(generator.parameters(), lr=LEARNING_RATE, betas=(0.5, 0.999))
    opt_d = optim.Adam(discriminator.parameters(), lr=LEARNING_RATE, betas=(0.5, 0.999))

    print(f"Training GAN for {EPOCHS} epochs (Batch Size={BATCH_SIZE})...")

    for epoch in range(1, EPOCHS + 1):
        d_losses, g_losses = [], []
        for (real_samples,) in dataloader:
            real_samples = real_samples.to(device)
            b_size = real_samples.size(0)

            valid_labels = torch.ones((b_size, 1), device=device)
            fake_labels = torch.zeros((b_size, 1), device=device)

            # ---------------------
            # Train Discriminator
            # ---------------------
            opt_d.zero_grad()
            z = torch.randn((b_size, LATENT_DIM), device=device)
            gen_samples = generator(z)

            real_loss = criterion(discriminator(real_samples), valid_labels)
            fake_loss = criterion(discriminator(gen_samples.detach()), fake_labels)
            d_loss = (real_loss + fake_loss) / 2.0

            d_loss.backward()
            opt_d.step()

            # ---------------------
            # Train Generator
            # ---------------------
            opt_g.zero_grad()
            g_loss = criterion(discriminator(gen_samples), valid_labels)
            g_loss.backward()
            opt_g.step()

            d_losses.append(d_loss.item())
            g_losses.append(g_loss.item())

        print(f"Epoch [{epoch:02d}/{EPOCHS:02d}] - Discriminator Loss: {np.mean(d_losses):.4f} | Generator Loss: {np.mean(g_losses):.4f}")

    # Save GAN Generator and Discriminator checkpoints
    gen_path = os.path.join(models_dir, 'gan_generator.pth')
    disc_path = os.path.join(models_dir, 'gan_discriminator.pth')

    torch.save(generator.state_dict(), gen_path)
    torch.save(discriminator.state_dict(), disc_path)

    print(f"\nSuccessfully saved GAN Generator -> {gen_path}")
    print(f"Successfully saved GAN Discriminator -> {disc_path}\n" + "=" * 70)


if __name__ == '__main__':
    train_gan()
