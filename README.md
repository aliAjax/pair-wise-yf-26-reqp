# 数字档案长期保存服务

仅使用 Python 3.11+ 标准库实现的独立档案保存项目，支持清单校验、真实 SHA-256 内容校验、多个离线副本、损坏检测与自动修复、格式迁移、保留期限和访问控制。

## 运行

```bash
python3 app.py --init --seed
python3 app.py
```

服务地址为 <http://127.0.0.1:8102>，默认数据库 `preservation.db`。测试：

```bash
python3 -m unittest -v
```

演示用户：`owner`、`archivist`、`auditor`、`outsider`。API 使用 `X-User-Id`。文件通过 Base64 提交，单文件上限 10 MiB；这是为了保持示例自包含，生产部署应换成对象存储和流式上传。

## 主要接口

- `POST /api/archives`：创建受限档案。
- `POST /api/archives/{id}/members`：所有者授予 read/write 权限。
- `POST /api/archives/{id}/versions`：提交文件清单，服务端重新计算哈希和大小。
- `GET /api/versions/{id}`：查看版本、文件清单和副本状态。
- `POST /api/versions/{id}/copies`：创建独立副本内容。
- `POST /api/copies/{id}/verify`：校验副本；发现损坏时从健康副本修复。
- `POST /api/copies/{id}/start-verification`：标记介质正在校验，校验结束前退役会被拦下。
- `POST /api/copies/{id}/media`：为副本登记物理介质编号（`media_serial`）和存放点（`storage_site`）。
- `GET /api/copies/{id}`：查看副本介质信息、校验状态和未修复损坏清单。
- `POST /api/decommissions`：提交介质退役批次（`copy_ids`），按版本逐份核对文件；通过则副本停用，否则整体拦下并逐份列出阻塞原因与缺口。
- `GET /api/decommissions/{id}`、`GET /api/decommissions`：查看退役批次详情（含阻塞原因/缺口）和可访问的批次列表。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本并保留派生关系。
- `GET /api/archives/{id}/status`：保留期限、版本状态和审计记录。

### 介质退役规则

- 每个副本必须先登记介质编号和存放点，同一版本介质编号不可重复。
- 提交退役时系统对每个文件逐一核对：必须存在**另一个健康、已登记且存放点不同**的副本（同批次其他待退役副本不算冗余）。
- 介质正在校验、副本损坏/缺文件、未登记介质、缺少异地健康副本时该份被拦下，返回结构化原因（`verifying_in_progress`、`media_unregistered`、`copy_corrupt`、`no_diverse_healthy_copy`）和文件级缺口/损坏清单。
- 损坏发现时写入 `copy_damages` 损坏清单（期望/实际 SHA-256）；自动修复成功则标记修复时间，无法修复则保留未结清单。
- 校验通过并批准退役后，副本仅做停用标记（`deactivated_at/by`）：原位置、介质编号、存放点、文件内容与全部审计记录仍然保留；停用副本不再充当健康供体，也不能重复退役。

档案路径拒绝绝对路径和 `..`；同一版本副本位置唯一；没有健康副本时版本标记为 `degraded`；所有变更写入审计日志。
