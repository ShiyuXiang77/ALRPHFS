<h2 align="center"> <a>ALRPHFS: Adversarially Learned Risk Patterns with Hierarchical Fast & Slow Reasoning for Robust Agent Defense</a></h2>
<h5 align="center"> If you like our project, please give us a star ⭐ on GitHub for latest update.  </h2>

<h5 align="center">

[Shiyu Xiang], [Tong Zhang],[Ronghao Chen]

[![arxiv](https://img.shields.io/badge/Arxiv-2502.11448-red)](https://arxiv.org/abs/2505.19260)

**<font color='red'>Warning: This repo contains examples of harmful agent action</font>**

## 💡 Abstract
LLM Agents are becoming central to intelligent systems. However, their deployment raises serious safety concerns. Existing defenses largely rely on "Safety Checks", which struggle to capture the complex semantic risks posed by harmful user inputs or unsafe agent behaviors—creating a significant semantic gap between safety checks and real-world risks.

To bridge this gap, we propose a novel defense framework, ALRPHFS (**A**dversarially **L**earned **R**isk **P**atterns with **H**ierarchical **F**ast & **S**low Reasoning). ALRPHFS consists of two core components: (1) an offline adversarial self-learning loop to iteratively refine a generalizable and balanced library of risk patterns, substantially enhancing robustness without retraining the base LLM, and (2) an online hierarchical fast & slow reasoning engine that balances detection effectiveness with computational efficiency. Experimental results demonstrate that our approach achieves superior overall performance compared to existing baselines, achieving a best-in-class average accuracy of 80% and exhibiting strong generalizability across tasks.
<img src="method.png" width="1000"/>

## 👻 Quick Start

### 1. Configuration

Go to the `method` folder and open `config.py`.  
Fill in the required information (e.g., `API_KEY`, dataset paths, etc.).  
These configurations will be automatically loaded by all subsequent scripts.  

---

### 2. Offline Workflow

The offline stage is responsible for initializing risk patterns, optimizing through deduplication, and performing adversarial self-learning to build a robust risk pattern library.

#### 2.1 Risk Patterns Initialization

Extract initial risk patterns from the dataset, which will serve as the foundation for deduplication and self-learning.  

```bash
python risk_patterns.py
```

#### 2.2 Deduplication Optimization

Perform semantic deduplication and representative selection to reduce redundancy and improve coverage.

```bash
python deduplicate.py
```

#### 2.3 Adversarial Self-Learning Loop

Iteratively expand and refine the risk pattern library through an adversarial self-learning loop.

* For **harmful** data:

```bash
python offline_train_harmful.py
```

* For **benign** data:

```bash
python offline_train_benign.py
```

---

### 3. Dataset Preparation

To simulate realistic Agent task execution, we adopt the React framework (based on [Agent-SafetyBench](https://github.com/thu-coai/Agent-SafetyBench)).
The datasets used include:

* [Mind2Web](https://github.com/OSU-NLP-Group/Mind2Web)
* [EICU-AC](https://github.com/guardagent/dataset)
* [TrustAgent](https://github.com/Ymm-cll/TrustAgent)

> If you want to add new tasks, you can follow the JSON format in `online/jsons` and extend the corresponding tools in `environments/tool`.

---

### 4. Online Defense

Load the risk pattern library built in the offline stage and run the online defense engine to monitor and intercept Agent behaviors in real time.

```bash
python defence_online.py
```


## 👍 Contact
- Shiyu Xiang: xiangshiyu@stu.scu.edu.cn
- Tong Zhang: tz21@zju.edu.cn
- Ronghao Chen: chenronghao@alumni.pku.edu.cn

## 📖 BibTeX:
```python
@misc{xiang2025alrphfsadversariallylearnedrisk,
      title={ALRPHFS: Adversarially Learned Risk Patterns with Hierarchical Fast \& Slow Reasoning for Robust Agent Defense}, 
      author={Shiyu Xiang and Tong Zhang and Ronghao Chen},
      year={2025},
      eprint={2505.19260},
      archivePrefix={arXiv},
      primaryClass={cs.CR},
      url={https://arxiv.org/abs/2505.19260}, 
}
```
