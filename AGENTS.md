# Project Rules & Implementation Guidelines

## Research Reproduction Rules (Mandatory)
1. `PAPER_SPEC.md` is the implementation contract.
2. The research paper is the source of truth.
3. Never silently invent a hyperparameter or algorithmic detail.
4. Mark unresolved choices as `[UNSPECIFIED]`, `[PARTIALLY_SPECIFIED]`, or `[ASSUMPTION]`.
5. Keep important paper section/equation references near the corresponding code.
6. Before changing behavior, explain which paper requirement the change satisfies.
7. Keep functions small and testable.
8. Add tests for tensor shapes/buffer sizes, invariants, losses/scores, and edge cases.
9. Run the smallest relevant test after every meaningful change.
10. Do not optimize performance until correctness tests pass.
11. Do not claim a paper result is reproduced unless the exact experiment was actually run.
12. Maintain `REPRODUCTION_NOTES.md` with deviations from the paper.
13. Maintain `VERIFICATION.md` with checks performed and their status.
