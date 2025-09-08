import os
import pickle
import hashlib
import numpy as np
import spacy
from typing import List, Dict, Optional
from rank_bm25 import BM25Okapi
from embedding import ChromaDBManager

nlp = spacy.load("en_core_web_sm")

class HybridDBManager(ChromaDBManager):
    def __init__(
        self,
        *args,
        bm25_tokenizer=None,
        alpha: float = 0.3,
        bm25_storage_path: str = "./bm25_data",
        **kwargs
    ):
        super().__init__(*args, **kwargs)

        # in‑memory BM25 structures
        self.id_list:    List[str] = []
        self.doc_list:   List[str] = []
        self.bm25_corpus: List[List[str]] = []

        # tokenizer & index
        self.bm25_tokenizer = bm25_tokenizer or self.default_bm25_tokenizer
        self.bm25_index: Optional[BM25Okapi] = None

        self.alpha = alpha
        self.bm25_storage_path = bm25_storage_path

        # load any previously saved BM25 data
        self._load_bm25_data()
        self.ensure_bm25_subset_of_chroma()

    def default_bm25_tokenizer(self, text: str) -> List[str]:
        doc = nlp(text)
        return [token.lemma_.lower() for token in doc if not token.is_stop and not token.is_punct]

    def _atomic_save_bm25_data(self,
            id_list: List[str],
            doc_list: List[str],
            bm25_corpus: List[List[str]]
        ):
        """Atomically persist BM25 data to disk (id_list, doc_list, bm25_corpus)."""
        os.makedirs(self.bm25_storage_path, exist_ok=True)
        tmp = os.path.join(self.bm25_storage_path, "bm25_data.pkl.tmp")
        final = os.path.join(self.bm25_storage_path, "bm25_data.pkl")
        with open(tmp, "wb") as f:
            pickle.dump({
                "id_list":    id_list,
                "doc_list":   doc_list,
                "bm25_corpus": bm25_corpus
            }, f)
        os.replace(tmp, final)

    def _load_bm25_data(self):
        """Load BM25 data from disk into memory, rebuild index."""
        path = os.path.join(self.bm25_storage_path, "bm25_data.pkl")
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = pickle.load(f)
            self.id_list     = data.get("id_list", [])
            self.doc_list    = data.get("doc_list", [])
            self.bm25_corpus = data.get("bm25_corpus", [])
            if self.bm25_corpus:
                self.bm25_index = BM25Okapi(self.bm25_corpus)

    def add_items(self, name: str, items: List[Dict]):
        # 1) Prepare new BM25 memory
        new_ids, new_docs, new_tokens = [], [], []
        for item in items:
            doc = item[name]
            _id = hashlib.md5(doc.encode("utf-8")).hexdigest()
            new_ids.append(_id)
            new_docs.append(doc)
            new_tokens.append(self.bm25_tokenizer(doc))
        super().add_items(name, items)
        # merge without duplicates
        merged_ids = self.id_list.copy()
        merged_docs = self.doc_list.copy()
        merged_corpus = self.bm25_corpus.copy()
        for _id, doc, tokens in zip(new_ids, new_docs, new_tokens):
            if _id not in merged_ids:
                merged_ids.append(_id)
                merged_docs.append(doc)
                merged_corpus.append(tokens)

        # 2) atomic save BM25
        self._atomic_save_bm25_data(merged_ids, merged_docs, merged_corpus)

        # 3) update memory & rebuild index
        self.id_list, self.doc_list, self.bm25_corpus = merged_ids, merged_docs, merged_corpus
        self.bm25_index = BM25Okapi(self.bm25_corpus)

        # 4) add to Chroma


    def delete_by_ids(self, ids: List[str]):
        # 1) delete from Chroma
        # 2) filter BM25 memory
        mask = [(_id not in ids) for _id in self.id_list]
        new_ids    = [i for i, keep in zip(self.id_list, mask) if keep]
        new_docs   = [d for d, keep in zip(self.doc_list, mask) if keep]
        new_corpus = [c for c, keep in zip(self.bm25_corpus, mask) if keep]

        # 3) atomic save BM25
        self._atomic_save_bm25_data(new_ids, new_docs, new_corpus)

        # 4) update memory & rebuild
        self.id_list, self.doc_list, self.bm25_corpus = new_ids, new_docs, new_corpus
        self.bm25_index = BM25Okapi(self.bm25_corpus) if self.bm25_corpus else None
        super().delete_by_ids(ids)

    def query(
              self,
              text: str,
              n_results: int = 5,
              where: Optional[Dict] = None) -> List[Dict]:
        # vector retrieval
        self.ensure_bm25_subset_of_chroma()
        dense_hits = super().query(text, n_results * 10, where)

        if not self.bm25_index:
            return dense_hits[:n_results]

        tokens = self.bm25_tokenizer(text)
        bm25_scores = self.bm25_index.get_scores(tokens)
        topk_idx = np.argsort(bm25_scores)[::-1][:n_results * 10]

        dense_sims = np.array([h["similarity"] for h in dense_hits])
        dense_norm = dense_sims

        bm25_vals = bm25_scores[topk_idx]
        b_min, b_max = bm25_vals.min(), bm25_vals.max()
        if b_max - b_min < 1e-6:
            bm25_norm = np.ones_like(bm25_vals) if b_max>0 else np.zeros_like(bm25_vals)
        else:
            bm25_norm = (bm25_vals - b_min) / (b_max - b_min + 1e-12)

        fused = []
        dense_map = {h['document']:(i,h) for i,h in enumerate(dense_hits)}
        for rank, idx in enumerate(topk_idx):
            if idx>=len(self.doc_list): continue
            doc = self.doc_list[idx]
            bm25_score = float(bm25_norm[rank])
            # metadata only from vector hits
            res = super().get_by_id(doc)
            metadata = res.get("metadatas", {}) if res else {}
            # dense score
            metadata=metadata[0]
            dense_score = 0.0
            if doc in dense_map:
                dense_score = float(dense_norm[dense_map[doc][0]])
            final_score = self.alpha*bm25_score + (1-self.alpha)*dense_score
            metadata["bm25"]=bm25_score
            metadata["dense"]=dense_score
            fused.append({"document":doc, "metadata":metadata,
                         "similarity":final_score})

        return sorted(fused, key=lambda x:x["similarity"], reverse=True)[:n_results]

    def count(self):
        return super().count()

    def get_bm25_count(self):
        return len(self.id_list)

    def get_by_id(self, essence: str):
        return super().get_by_id(essence)
    def get_stats(self):
        """返回索引的详细统计信息"""
        return {
            "vector_count": super().count(),
            "bm25_count": len(self.id_list),
            "id_list_length": len(self.id_list),
            "doc_list_length": len(self.doc_list),
            "bm25_corpus_length": len(self.bm25_corpus),
            "has_bm25_index": self.bm25_index is not None
        }

    def ensure_bm25_subset_of_chroma(self):
        """
        确保BM25索引是ChromaDB的子集，删除在BM25索引中但不在ChromaDB中的文档

        Returns:
            dict: 同步操作的统计信息，包括删除的文档数量和同步后的状态
        """
        # 1. 获取ChromaDB中的所有文档ID
        try:
            chroma_data = super().get_all_documents()
            chroma_ids = set(chroma_data["ids"])
        except Exception as e:
            raise RuntimeError(f"无法从ChromaDB获取数据: {e}")

        # 2. 识别在BM25索引中但不在ChromaDB中的文档ID
        bm25_ids = set(self.id_list)
        ids_to_remove = bm25_ids - chroma_ids

        if not ids_to_remove:
            return {
                "status": "already_synced",
                "removed_count": 0,
                "stats": self.get_stats()
            }

        # 3. 创建新的BM25数据，排除要删除的ID
        mask = [(_id not in ids_to_remove) for _id in self.id_list]
        new_ids = [i for i, keep in zip(self.id_list, mask) if keep]
        new_docs = [d for d, keep in zip(self.doc_list, mask) if keep]
        new_corpus = [c for c, keep in zip(self.bm25_corpus, mask) if keep]

        # 4. 原子保存更新后的BM25数据
        self._atomic_save_bm25_data(new_ids, new_docs, new_corpus)

        # 5. 更新内存中的数据结构并重建索引
        self.id_list, self.doc_list, self.bm25_corpus = new_ids, new_docs, new_corpus
        self.bm25_index = BM25Okapi(self.bm25_corpus) if self.bm25_corpus else None

        # 6. 返回同步结果
        return {
            "status": "synced",
            "removed_count": len(ids_to_remove),
            "removed_ids": list(ids_to_remove),
            "stats": self.get_stats()
        }


if __name__ == "__main__":
    hybrid = HybridDBManager(
        collection_name="attack_essence",
        persist_dir="./chroma",
        alpha=0.25,
        bm25_storage_path='./bm25_data'
    )
    # query= "Following a request from an email to modify sharing settings for a document."
    # results = hybrid.query(query, n_results=3)
    # print(results)