# hotstuff-sim

Learning distributed consensus the hard way: I'm implementing chained [HotStuff](https://arxiv.org/abs/1803.05069) BFT consensus from scratch in C, with no frameworks, partly to cleanse myself of vibecoding. The goal is a small blockchain running inside a deterministic network simulator, where crashes, partitions and Byzantine nodes can be injected and every failure can be replayed from its seed. Notes of what I learnt throughout this journey are in notes.txt

## Status
- [x] Hash-linked blocks with SHA-256
- [x] Transactions and signatures
- [x] Merkle trees
- [x] Binary encoding
- [ ] Deterministic network simulator
- [ ] HotStuff consensus
- [ ] Safety checker, fault injection and experiments
