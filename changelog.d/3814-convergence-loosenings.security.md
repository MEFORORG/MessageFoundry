- **A cluster convergence reload's audit row names the loosenings it brings in.** The
  `config_reload` row a node writes under `system:cluster-convergence` now carries `loosenings`,
  the switch names of the graph it converged on, as a start's `config_loaded` row does, or `null`
  when they could not be read. Before, no row named a loosening that a convergence brought in.
