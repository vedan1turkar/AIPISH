"""DistilRoBERTa sequence classifier (R1): fine-tuning and batched inference.

torch/transformers are imported lazily so the API starts without them.
"""
from __future__ import annotations

import math
import random
import time
from pathlib import Path

from app.ml.dataset.labels import LABELS

BASE_MODEL = "distilroberta-base"


def pick_device(prefer: str = "auto") -> str:
    import torch
    if prefer != "auto":
        return prefer
    if torch.backends.mps.is_available():
        return "mps"
    return "cuda" if torch.cuda.is_available() else "cpu"


def set_seed(seed: int) -> None:
    import numpy as np
    import torch
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def predict_proba(model, tokenizer, texts: list[str], max_len: int, device: str,
                  batch_size: int = 32) -> list[list[float]]:
    import torch
    model.eval()
    out: list[list[float]] = []
    with torch.no_grad():
        for i in range(0, len(texts), batch_size):
            enc = tokenizer(texts[i:i + batch_size], truncation=True, max_length=max_len,
                            padding=True, return_tensors="pt").to(device)
            probs = torch.softmax(model(**enc).logits.float(), dim=-1).cpu().tolist()
            out.extend(probs)
    return out


def fine_tune(train_texts: list[str], train_labels: list[int], val_texts: list[str],
              val_labels: list[int], out_dir: Path, *, seed: int, max_len: int, epochs: int,
              batch_size: int, lr: float, weight_decay: float, warmup_ratio: float,
              class_weights: list[float], device: str, select_metric, log=print) -> dict:
    """Fine-tune on train only; keep the epoch with the best validation metric.

    `select_metric(val_probs) -> float` is computed on validation predictions
    (model selection only; validation is never used for gradient updates).
    """
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    from transformers import get_linear_schedule_with_warmup

    set_seed(seed)
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL, num_labels=len(LABELS),
        id2label=dict(enumerate(LABELS)), label2id={lbl: i for i, lbl in enumerate(LABELS)},
    ).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    steps_per_epoch = math.ceil(len(train_texts) / batch_size)
    sched = get_linear_schedule_with_warmup(opt, int(warmup_ratio * steps_per_epoch * epochs),
                                            steps_per_epoch * epochs)
    loss_fn = torch.nn.CrossEntropyLoss(weight=torch.tensor(class_weights, dtype=torch.float32,
                                                            device=device))
    rng = random.Random(seed)
    order = list(range(len(train_texts)))
    history, best = [], (-1.0, -1)
    for epoch in range(epochs):
        model.train()
        rng.shuffle(order)
        t0, total = time.time(), 0.0
        for step in range(steps_per_epoch):
            idx = order[step * batch_size:(step + 1) * batch_size]
            enc = tok([train_texts[i] for i in idx], truncation=True, max_length=max_len,
                      padding=True, return_tensors="pt").to(device)
            y = torch.tensor([train_labels[i] for i in idx], device=device)
            loss = loss_fn(model(**enc).logits, y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            total += loss.item()
            if step % 100 == 0:
                log(f"epoch {epoch + 1} step {step}/{steps_per_epoch} loss {loss.item():.4f}")
        val_probs = predict_proba(model, tok, val_texts, max_len, device)
        score = select_metric(val_probs)
        history.append({"epoch": epoch + 1, "train_loss": round(total / steps_per_epoch, 5),
                        "val_macro_f1": round(score, 5), "seconds": round(time.time() - t0, 1)})
        log(f"epoch {epoch + 1} done: {history[-1]}")
        if score > best[0]:
            best = (score, epoch + 1)
            model.save_pretrained(out_dir)
            tok.save_pretrained(out_dir)
    return {"history": history, "best_epoch": best[1], "best_val_macro_f1": round(best[0], 5)}


def load(model_dir: Path, device: str = "cpu"):
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir).to(device)
    model.eval()
    return model, tok
