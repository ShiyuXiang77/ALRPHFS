import hashlib
from typing import List, Dict, Optional
import chromadb
from chromadb.config import Settings
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import json
from openai import OpenAI
import torch
from sentence_transformers import util
def get_embedding(text, model="text-embedding-3-large"):
    """
    获取文本的embedding向量。
    :param text: 要转换的文本 (str)
    :param model: 使用的模型 (str)，默认是 text-embedding-3-large
    :return: embedding向量 (Tensor)
    """
    client = OpenAI(api_key='sk-1AenZJt8Az8saFqCRg8dtL1LjX8Hl1CLhLh7p5zM4HGctubk',
                    base_url='https://api.openai-proxy.org/v1')
    try:
        response = client.embeddings.create(
            input=text,
            model=model

        )
        embedding = response.data[0].embedding  # 注意这里用 .data[0].embedding
        return embedding         # 直接转成Tensor，方便后续相似度计算
    except Exception as e:
        print(f"OpenAI API 请求出错了: {e}")
        return None
class ChromaDBManager:
    def __init__(self, collection_name: str="my_json_collection", persist_dir: str = "./chroma_test"):
        self.client = chromadb.Client(Settings(persist_directory=persist_dir, anonymized_telemetry=False))

        # Create or load collection
        try:
            self.collection = self.client.get_collection(name=collection_name)
        except:
            self.collection = self.client.create_collection(name=collection_name,metadata={"hnsw":"cosine"})

    def _generate_id(self, item) -> str:
        """Generate a deterministic ID using content + type"""
        if isinstance(item, dict):
            base = item["attack_essence"]
        elif isinstance(item, str):
            base = item
        else:
            raise ValueError("Unsupported type for item: must be dict or str")

        return hashlib.md5(base.encode("utf-8")).hexdigest()

    def _prepare_metadata(self, item: Dict) -> Dict:
        """Format metadata fields to ensure all values are str, int, float, or bool"""
        metadata = {}
        for key, value in item.items():
            if isinstance(value, (str, int, float, bool)):
                metadata[key] = value
            elif isinstance(value, list):
                try:
                    # 把 list 序列化为 JSON array 字符串
                    metadata[key] = json.dumps(value, ensure_ascii=False)
                except Exception:
                    metadata[key] = str(value)

            elif isinstance(value, dict):
                try:
                    metadata[key] = json.dumps(value, ensure_ascii=False)
                except Exception:
                    metadata[key] = str(value)
            else:
                metadata[key] = str(value)  # fallback for other types like None, set, etc.
        return metadata

    def add_items(self, name: str, items: List[Dict]):
        #name等于"attack_essence"或者"harmful_result"
        ids, docs, embeddings, metadatas = [], [], [], []
        for item in items:
            _id = self._generate_id(item)
            doc = item[name]
            # 使用 get_embedding 替代 model.encode
            emb = get_embedding(doc)  # 获取文档的 embedding
            if emb is None:
                continue  # 如果 embedding 获取失败，跳过该项
            meta = self._prepare_metadata(item)
            ids.append(_id)
            docs.append(doc)
            embeddings.append(emb)
            metadatas.append(meta)

        self.collection.add(ids=ids, documents=docs, embeddings=embeddings, metadatas=metadatas)
        # self.client.persist()

    def query(self, text: str, n_results: int = 5, where: Optional[Dict] = None,need_embedding=None) -> List[Dict]:
        # 使用 get_embedding 获取查询文本的 embedding
        query_embedding = get_embedding(text)  # 获取查询文本的 embedding
        if query_embedding is None:
            return []  # 如果 embedding 获取失败，返回空列表

        if where is not None:
            results = self.collection.query(
                query_embeddings=[query_embedding],  # 需要传入列表
                n_results=n_results,
                where=where,
                include=["documents", "metadatas", "embeddings","distances"]
            )
        else:
            results = self.collection.query(
                query_embeddings=[query_embedding],  # 需要传入列表
                n_results=n_results,
                include=["documents", "metadatas", "embeddings",'distances']
            )
        doc_embs = results["embeddings"][0]
        query_tensor = torch.tensor(query_embedding, dtype=torch.float32)
        doc_tensors = torch.tensor(doc_embs, dtype=torch.float32)
        cos_scores = util.cos_sim(query_tensor, doc_tensors)
        # cos_scores.shape == (1, n_results)
        sims = cos_scores[0].tolist()
        # sims = cosine_similarity([query_embedding], doc_embs)[0]  # 计算余弦相似度
        # 合并结果
        if need_embedding:
            return[
            {
                "document": doc,
                "metadata": meta,
                "similarity": float(sim),
                "embedding":doc_emb
            }
            for doc, meta, sim ,doc_emb in zip(results["documents"][0], results["metadatas"][0], sims,results["embeddings"][0])
        ]

        return [
            {
                "document": doc,
                "metadata": meta,
                "similarity": float(sim)
            }
            for doc, meta, sim in zip(results["documents"][0], results["metadatas"][0], sims)
        ]

    def delete_by_ids(self, ids: List[str]):
        self.collection.delete(ids=ids)
        # self.client.persist()
    #
    # def update_item(self, name: str, item: Dict):
    #     self.add_items(name, [item])

    def count(self):
        return self.collection.count()
    def get_by_id(self, essence):
        id=self._generate_id(essence)
        result=self.collection.get(ids=id)
        return result

    def get_all_documents(self):
        """
        获取集合中的所有文档

        Returns:
            dict: 包含ids、documents、embeddings和metadatas的字典
        """
        try:
            # 获取集合中所有文档数量
            doc_count = self.collection.count()
            if doc_count == 0:
                return {
                    "ids": [],
                    "documents": [],
                }

            # 获取所有文档
            result = self.collection.get(
                include=["documents"]
            )
            return result
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"获取所有文档时出错: {e}\n{error_details}")
            return {
                "ids": [],
                "documents": [],
            }


# import os
# #计算相似度
# folder_path = "./data1"
# attacks = []
# # 遍历文件夹中的所有 JSON 文件
# for filename in os.listdir(folder_path):
#     if filename.endswith(".json"):
#         file_path = os.path.join(folder_path, filename)
#         try:
#             with open(file_path, "r", encoding="utf-8") as f:
#                 data = json.load(f)
#                 for item in data:
#                 #遍历每一个元素，如果有 harmful_result 字段，则添加到 attacks 列表中
#                     if "harmful_result" in item:
#                         attacks.append(item)
#         except Exception as e:
#             print(f"Error reading {filename}: {e}")
#
# # 初始化数据库并添加数据
# db1 = ChromaDBManager(collection_name="attack_essence")
# db1.add_items(name="attack_essence", items=attacks[0:3])
# db2 = ChromaDBManager(collection_name="harmful_result")
# db2.add_items(name="harmful_result", items=attacks)
# # db1.collection.persist()
# # db2.collection.persist()
#
# print("attack_essence 数据量:", db1.count())
# print("harmful_result 数据量:", db2.count())
