"""
model.py -- the EXACT architecture used in train_final_gnn_v2.py.

Loading best_model.pt into any other architecture (e.g. an older 2-layer
GCNConv model) either crashes on a state_dict mismatch, or -- worse --
silently loads garbage and gives meaningless predictions. This class
must stay byte-for-byte identical to the one used for training.
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn import Linear, Sequential, ReLU, BatchNorm1d, Dropout
from torch_geometric.nn import GATv2Conv, global_mean_pool, global_max_pool
from torch_geometric.data import Data


class VulnerabilityGNN(nn.Module):
    def __init__(self, in_channels=768, num_classes=2):
        super().__init__()
        self.gat1 = GATv2Conv(in_channels, 128, heads=4, concat=True)   # -> 512
        self.bn1 = BatchNorm1d(512)
        self.gat2 = GATv2Conv(512, 64, heads=4, concat=True)            # -> 256
        self.bn2 = BatchNorm1d(256)
        self.gat3 = GATv2Conv(256, 64, heads=2, concat=False)           # -> 64

        self.classifier = Sequential(
            Linear(128, 64),
            ReLU(),
            Dropout(0.5),
            Linear(64, 32),
            ReLU(),
            Dropout(0.3),
            Linear(32, num_classes),
        )

    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch

        x, (edge_index_a1, alpha1) = self.gat1(x, edge_index, return_attention_weights=True)
        x = F.elu(self.bn1(x))
        x = F.dropout(x, p=0.3, training=self.training)

        x, (edge_index_a2, alpha2) = self.gat2(x, edge_index, return_attention_weights=True)
        x = F.elu(self.bn2(x))
        x = F.dropout(x, p=0.3, training=self.training)

        x = self.gat3(x, edge_index)

        pooled = torch.cat([global_mean_pool(x, batch), global_max_pool(x, batch)], dim=1)
        out = self.classifier(pooled)
        return out, (edge_index_a1, alpha1)


def load_model(checkpoint_path, device="cpu"):
    model = VulnerabilityGNN().to(device)
    state = torch.load(checkpoint_path, map_location=device)
    model.load_state_dict(state)
    model.eval()
    return model


@torch.no_grad()
def predict_function(model, data: Data, device="cpu"):
    """Runs one function-graph through the model.

    Returns: (label, confidence, node_importance)
      label: 0 (safe) or 1 (vulnerable)
      confidence: 0-100
      node_importance: list[float], one score per node in `data.x`,
        derived from layer-1 GAT attention. This is REAL model
        introspection, not an LLM guess.
    """
    data = data.to(device)
    data.batch = torch.zeros(data.x.size(0), dtype=torch.long, device=device)

    logits, (edge_index_a1, alpha1) = model(data)
    probs = F.softmax(logits, dim=1)[0]
    label = int(probs.argmax().item())
    confidence = float(probs[label].item() * 100)

    alpha_mean = alpha1.mean(dim=1)              # [num_edges] avg across attention heads
    num_nodes = data.x.size(0)
    importance = torch.zeros(num_nodes, device=device)

    # IMPORTANT: GATv2 attention is softmax-normalized PER DESTINATION node
    # -- for any node v, the incoming weights over its neighbors always sum
    # to ~1.0. Aggregating "sum of incoming attention" therefore gives a
    # flat, meaningless ~1.0 for almost every node (a real bug in earlier
    # versions -- every line showed "1.000 attention"). Instead we
    # aggregate by SOURCE: for each node v, how much total attention did
    # OTHER nodes place on v when v was in their neighborhood? This is not
    # constrained to sum to 1 and varies meaningfully across nodes, giving
    # a real importance ranking.
    src_nodes = edge_index_a1[0]
    importance.scatter_add_(0, src_nodes, alpha_mean)

    return label, confidence, importance.cpu().tolist()
