# Master Thesis Project: Robustness Analysis and Adversarial Attacks on Network Intrusion Detection Systems (NIDS)

This repository contains the implementation of a part of my **Master's thesis**, focusing on analyzing the robustness of **Network Intrusion Detection Systems (NIDS)** and developing practical black-box adversarial attacks. The project uses a **self-attention mechanism** integrated into a **Generative Adversarial Network (GAN)** to generate adversarial examples (AEs) that successfully evade IDSs. This work has currently led to a research paper, and the complete Master's thesis is still ongoing, which will also explore methods to enhance the defense capabilities of IDSs against such attacks.

## Project Overview

### Objective
The primary goal of this project is to develop an adversarial attack model that can generate adversarial examples capable of evading network intrusion detection systems in a **black-box** setting, where the attacker has no prior knowledge of the internal architecture or parameters of the IDS.

A key contribution of this project is the **practicality** of the method, achieved through the use of **active learning** to implement an efficient query-based black-box attack. This approach minimizes communication complexity and prevents the attacker's node from being blocked, making the method feasible for real-world scenarios.

### Key Concepts
- **Adversarial Examples (AEs)**: Specially crafted inputs designed to deceive machine learning models. In this context, AEs are generated to evade detection by NIDS.
- **Self-Attention Mechanism**: Utilized within the GAN architecture to improve the generative capabilities of the model, focusing on learning the most important features to evade detection.
- **Generative Adversarial Networks (GAN)**: A GAN is used to generate adversarial examples. The **generator** attempts to create network traffic data that evades detection, while the **discriminator** acts as an adversarial IDS, trying to detect generated AEs.
- **Active Learning**: Employed to efficiently query the black-box IDS, minimizing the number of queries needed and reducing the risk of detection.

### Scope
- This project focuses on **black-box attacks**, meaning that no information about the IDS's internal workings is available to the adversary.
- The complete Master's thesis project will eventually also include methods to increase IDS defenses against adversarial attacks, but these defense mechanisms are not part of this repository yet.

## Implementation Details

### GAN with Self-Attention
- **Generator**: The generator aims to create realistic network traffic data that can bypass the IDS.
- **Discriminator**: The discriminator simulates the IDS, attempting to classify generated traffic as either benign or malicious.
- **Self-Attention**: Self-attention is integrated into the GAN to allow the model to focus on critical features that contribute most to the successful generation of adversarial examples.
- **Active Learning for Query Efficiency**: Active learning is used to select the most informative queries, reducing the total number of queries and enhancing the practicality of the attack.

### Dataset
- **CICIDS2017**: The CICIDS2017 dataset was used to train and test the GAN. This dataset includes a variety of modern network attack scenarios that are well-suited for evaluating the robustness of IDSs.

### Attack Scenario
- **Black-Box Setting**: The project simulates a scenario where the adversary has no direct access to the model's internal structure or its training data, making it more challenging and realistic compared to white-box attacks.
- **Evaluation Metrics**: Metrics such as **evasion rate**, **F1-score**, and **precision/recall** are used to evaluate the effectiveness of the generated adversarial examples against different IDS models.

## Results
- **Evasion Rate**: The GAN model achieved a high evasion rate against the tested IDS, demonstrating the vulnerability of traditional detection systems to adversarial attacks.
- **Effectiveness of Self-Attention**: The integration of self-attention allowed the generator to focus on key features, improving the quality and success rate of adversarial examples.
- **Practicality with Active Learning**: The use of active learning significantly improved the practicality of the attack by minimizing the number of queries required, reducing communication complexity, and preventing the attacker node from being easily blocked. This makes the method viable for real-world scenarios where efficiency and stealth are crucial.

## Future Work
- **Defense Mechanisms**: The ongoing work for the complete Master's thesis will focus on enhancing IDS defenses against adversarial attacks. Techniques such as **adversarial training** and **ensemble learning** will be explored.

## Contact
For more details or questions regarding this project, feel free to contact me at [pouria.dadkhah@gmail.com](mailto:pouria.dadkhah@gmail.com).

