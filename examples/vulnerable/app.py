"""Deliberately vulnerable sample — pickle-sentry should flag every sink here."""
import pickle

import pandas as pd
from datasets import load_dataset

# CVE-2026-57845: pandas builder -> pandas.read_pickle() on attacker files
ds = load_dataset("pandas", data_files="shared/train.pkl")

# Direct sinks
with open("model.pkl", "rb") as fh:
    model = pickle.load(fh)
df = pd.read_pickle("shared/train.pkl")

import torch
net = torch.load("checkpoint.pt")                      # no weights_only
net2 = torch.load("checkpoint.pt", weights_only=False)  # explicitly unsafe
