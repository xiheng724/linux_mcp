# bench (optional)

`bench/` 是可选压测模块，不参与主链路运行。

## 用途

- 批量压测仲裁与执行路径
- 产出吞吐、延迟、fairness 指标

## 前置条件

- `kernel_mcp` 已加载
- `mcpd` 正在运行
- `client/bin` 已编译

## 运行

```bash
python3 bench/bench_runner.py --agents 10 --requests 50 --tool cpu_burn --burn-ms 50 --out results/phase5_run.json
```

## 绘图

```bash
python3 bench/plot_results.py --in results/phase5_run.json --outdir plots
```
