"""Safe sample — pickle-sentry should report no high/critical findings here."""
import pandas as pd
import torch
from datasets import Dataset, load_dataset

ds = load_dataset("parquet", data_files="data/train.parquet")
df = pd.read_parquet("data/train.parquet")
df2 = pd.read_csv("data/train.csv")
own = Dataset.from_pandas(df)
net = torch.load("checkpoint.pt", weights_only=True)
