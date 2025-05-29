# eBPFlex Artifacts

This repository contains artifacts and benchmarks for the eBPFlex project.

## Repository Structure

- `FFmpeg/` - FFmpeg related artifacts
- `httpd/` - Apache HTTP Server artifacts
- `memcached/` - Memcached artifacts
- `nginx/` - Nginx artifacts
- `rsync/` - Rsync artifacts
- `ebpflex_data_invariant_gen/` - Data invariant generation tools
- `program-dependence-graph/` - Program dependence graph analysis (git submodule)
- `scripts/` - Utility scripts

## Submodules

This repository uses git submodules. After cloning, initialize and update the submodules:

```bash
git submodule init
git submodule update
```

Or clone with submodules in one command:

```bash
git clone --recurse-submodules <repository-url>
```

### program-dependence-graph

The `program-dependence-graph` directory is a git submodule pointing to:
- Repository: https://github.com/ARISTODE/program-dependence-graph.git
- Branch: `ebpf_eval`

To update this submodule to the latest commit on its branch:

```bash
cd program-dependence-graph
git pull origin ebpf_eval
cd ..
git add program-dependence-graph
git commit -m "Update program-dependence-graph submodule"
```

## License

See the LICENSE file for details.