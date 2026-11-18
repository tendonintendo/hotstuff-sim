# hotstuff-sim

Learning distributed consensus the hard way: I'm implementing chained [HotStuff](https://arxiv.org/abs/1803.05069) BFT consensus from scratch in C, with no frameworks  with no frameworks, partly to cleanse myself of vibecoding. The goal is a small blockchain running inside a deterministic network simulator, where crashes, partitions and Byzantine nodes can be injected and every failure can be replayed from its seed.

## Status
- [x] Hash-linked blocks with SHA-256
- [ ] Transactions and signatures
- [ ] Merkle trees
- [ ] Deterministic network simulator
- [ ] HotStuff consensus
- [ ] Safety checker, fault injection and experiments
