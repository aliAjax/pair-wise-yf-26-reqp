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
- `POST /api/versions/{id}/copies`：创建独立副本内容，可同时登记 `media_id` 与 `storage_site`。
- `POST /api/copies/{id}/register`：给副本补登介质编号/更正存放点（退役封存后不可改）。
- `POST /api/copies/{id}/verification/start`、`POST /api/copies/{id}/verification/complete`：两阶段校验，期间副本处于 `verifying`。
- `POST /api/copies/{id}/verify`：原子校验（开始并立即完成）。
- `GET /api/copies/{id}/damage-reports`：损坏清单（发现损坏即永久留存，修复后也保留）。
- `POST /api/copies/{id}/retire`：提交介质退役，逐文件核对异点健康副本。
- `GET /api/copies/{id}/retirements`、`GET /api/retirements`：查看退役记录与阻塞原因。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本并保留派生关系。
- `GET /api/archives/{id}/status`：保留期限、版本状态和审计记录。

## 介质退役规则

离线介质下线前，每个副本都要先登记介质编号（`media_id`，全局唯一）和存放点（`storage_site`，即副本位置）。提交退役时服务端按版本逐份核对文件，任一条件不满足都返回 `409 retirement_blocked` 并持久化一条 `blocked` 记录，`details.reasons/gaps` 给出阻塞原因和逐文件缺口：

- `copy_verifying`：介质正在校验中（`verifying`），完成前不得批准退役。
- `media_not_registered`：副本尚未登记介质编号（或缺少存放点）。
- `damage_report_missing`：副本已损坏但没有损坏清单——须先完成校验，由系统登记损坏文件。
- `copy_not_healthy`：副本处于 `corrupt/degraded` 或自身文件与版本哈希不符，须先修复并通过校验。
- `no_other_healthy_copy`：该文件在**另一个存放点**没有健康且哈希一致的副本；缺口按文件列出，并附现有副本状态便于补盘。

全部文件都能找到异点健康副本时才批准：副本置为 `retired` 在档案中停用，原存放点、介质编号、损坏清单和审计记录全部保留；退役后的副本不再参与修复供体与冗余核对。页面 <http://127.0.0.1:8102/> 可完成登记、两阶段校验、提交退役和查看阻塞原因。

档案路径拒绝绝对路径和 `..`；同一版本副本存放点唯一；介质编号全局唯一；没有健康副本时版本标记为 `degraded`；所有变更写入审计日志。
