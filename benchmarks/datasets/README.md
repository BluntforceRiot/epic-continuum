# Dataset Adapters

This directory is reserved for dataset manifests and download instructions. Do not commit third-party datasets unless their licenses explicitly permit redistribution.

Planned no-LLM retrieval adapters:

- LongMemEval;
- LoCoMo.

Adapter acceptance rules:

- run without an LLM by default;
- require an explicit local dataset path or an explicit download command;
- record dataset name, version, split, source, license, size, and checksum;
- separate raw baseline, tuned development, and held-out results;
- report retrieval metrics only as retrieval metrics, not answer quality;
- record API cost as zero in no-LLM mode.

Do not compare Epic Continuum to another system unless the dataset, split, metric, top-k definition, and reranking conditions match.

Before adding a dataset runner, document:

- source URL;
- license;
- expected download size;
- split name and version;
- checksum;
- preprocessing command;
- whether network access is required;
- whether an API key or paid model is required.

The first accepted mode for public datasets should be no-LLM retrieval so it can run without an API key.
