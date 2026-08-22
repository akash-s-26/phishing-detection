"""
training/train_cnn.py
PhishGuard AI — 1D CNN Character Sequence Neural Network Training Pipeline
Implements 1D Convolutional Neural Network for complementary character n-gram pattern extraction.
"""

import os
import json
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

BATCH_SIZE = 1024
EPOCHS = 3
LEARNING_RATE = 0.003

class CNNPhishing1D(nn.Module):
    def __init__(self, vocab_size=96, embed_dim=32, num_features=15):
        super(CNNPhishing1D, self).__init__()
        self.embedding = nn.Embedding(num_embeddings=vocab_size + 5, embedding_dim=embed_dim, padding_idx=0)
        self.conv1 = nn.Conv1d(in_channels=embed_dim, out_channels=64, kernel_size=5, padding=2)
        self.relu1 = nn.ReLU()
        self.pool1 = nn.MaxPool1d(kernel_size=2)

        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3, padding=1)
        self.relu2 = nn.ReLU()
        self.global_pool = nn.AdaptiveMaxPool1d(1)

        self.fc1 = nn.Linear(128 + num_features, 64)
        self.relu3 = nn.ReLU()
        self.dropout = nn.Dropout(0.3)
        self.fc2 = nn.Linear(64, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x_seq, x_num):
        embeds = self.embedding(x_seq).transpose(1, 2)  # [batch, embed_dim, seq_len]
        c1 = self.pool1(self.relu1(self.conv1(embeds)))
        c2 = self.global_pool(self.relu2(self.conv2(c1))).squeeze(2)  # [batch, 128]

        combined = torch.cat([c2, x_num], dim=1)
        out = self.dropout(self.relu3(self.fc1(combined)))
        prob = self.sigmoid(self.fc2(out))
        return prob


def train_cnn_model():
    base_dir = os.path.dirname(__file__)
    models_dir = os.path.join(base_dir, '..', 'models')
    os.makedirs(models_dir, exist_ok=True)

    data_path = os.path.join(base_dir, 'processed_data', 'dataset_splits_augmented.npz')
    if not os.path.exists(data_path):
        data_path = os.path.join(base_dir, 'processed_data', 'dataset_splits.npz')

    print("=" * 70)
    print("PHISHGUARD AI: 1D CNN MODEL TRAINING")
    print("=" * 70)

    data = np.load(data_path)
    X_seq_train, X_num_train, y_train = data['X_seq_train'], data['X_num_train'], data['y_train']
    X_seq_val, X_num_val, y_val = data['X_seq_val'], data['X_num_val'], data['y_val']

    tokenizer_path = os.path.join(models_dir, 'tokenizer.json')
    vocab_size = 96
    if os.path.exists(tokenizer_path):
        with open(tokenizer_path, 'r') as f:
            tok = json.load(f)
            vocab_size = tok.get('vocab_size', 96)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Device: {device} | Train samples: {len(y_train)} | Val samples: {len(y_val)}")

    train_ds = TensorDataset(torch.tensor(X_seq_train, dtype=torch.long), torch.tensor(X_num_train, dtype=torch.float32), torch.tensor(y_train, dtype=torch.float32))
    val_ds = TensorDataset(torch.tensor(X_seq_val, dtype=torch.long), torch.tensor(X_num_val, dtype=torch.float32), torch.tensor(y_val, dtype=torch.float32))

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False)

    model = CNNPhishing1D(vocab_size=vocab_size, num_features=X_num_train.shape[1]).to(device)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=1e-5)

    best_val_loss = float('inf')
    best_weights = None

    for epoch in range(1, EPOCHS + 1):
        model.train()
        train_loss, train_correct = 0.0, 0
        for seqs, nums, targets in train_loader:
            seqs, nums, targets = seqs.to(device), nums.to(device), targets.to(device).unsqueeze(1)
            optimizer.zero_grad()
            outputs = model(seqs, nums)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()

            train_loss += loss.item() * seqs.size(0)
            preds = (outputs >= 0.5).float()
            train_correct += (preds == targets).sum().item()

        train_acc = train_correct / len(y_train)
        train_loss = train_loss / len(y_train)

        # Validation
        model.eval()
        val_loss, val_correct = 0.0, 0
        with torch.no_grad():
            for seqs, nums, targets in val_loader:
                seqs, nums, targets = seqs.to(device), nums.to(device), targets.to(device).unsqueeze(1)
                outputs = model(seqs, nums)
                loss = criterion(outputs, targets)
                val_loss += loss.item() * seqs.size(0)
                preds = (outputs >= 0.5).float()
                val_correct += (preds == targets).sum().item()

        val_acc = val_correct / len(y_val)
        val_loss = val_loss / len(y_val)

        print(f"Epoch [{epoch:02d}/{EPOCHS:02d}] Train Loss: {train_loss:.4f} | Acc: {train_acc:.4f} || Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_weights = model.state_dict()

    out_path = os.path.join(models_dir, 'cnn_model.pth')
    if best_weights is not None:
        torch.save(best_weights, out_path)
        print(f"Saved 1D CNN checkpoint -> {out_path}\n" + "=" * 70)


if __name__ == '__main__':
    train_cnn_model()
