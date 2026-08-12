# 发布维护流程

[English](releasing.en.md) | [返回 README](../README.md)

本页只面向具有离线签名密钥和 GitHub 发布权限的维护者，且必须在完整 Git 源码检出中执行；签名发行归档只保留这份流程供审计，不包含发布工具源码。普通用户应阅读[安装与升级](installation.md)和[安全与信任模型](security.md)。

## 发布前约束

- 根 `VERSION` 必须严格为一行 `VERSION="X.Y.Z"`，并在 CHANGELOG 中有唯一同版本标题。
- 发布提交必须位于受保护的 `main`，工作区干净，所选 CI 层级和 `ci-gate` 必须成功。
- 正式 tag 或 `--release` 构建必须能访问固定主指纹对应的离线 GPG 私钥；私钥不得进入 GitHub Actions。
- 正式包固定包含 amd64、arm64、386、ppc64le 和 s390x，不能缩小架构集合。

## 构建签名资产

先在未提交的发布工作树完成[开发与本地验证](development.md)中的“验证源码变更”门禁，再提交并推送发布
提交，等待该精确提交的受保护 `ci-gate` 通过。在干净的该提交上完成同页“验证干净的发布提交”门禁，
随后只在本地创建 annotated tag，准备变量并构建正式资产；此时不要推送 tag：

```bash
set -euo pipefail
tag="vX.Y.Z"
release_sha="$(git rev-parse HEAD)"
git tag -a "$tag" -m "security-update-notify $tag" "$release_sha"
release_dist="$(mktemp -d "/tmp/security-update-notify-${tag}.XXXXXX")"
go run ./cmd/sun-release package --release --sign required \
  --dist "$release_dist" \
  --gpg-key 'C678256ACBFC6491BF5076655F3AE24999921FFC!'
(cd "$release_dist" && sha256sum -c security-update-notify-*.tar.gz.sha256)
```

末尾的 `!` 强制 GPG 使用已发布信任锚中的主密钥，避免自动选择尚未纳入仓库公钥的签名子钥。

正式版本必须生成且只发布归档、checksum、归档 detached signature 和 `sun.sh.asc` 四项显式 Release 资产。打包器会在签名后立即复验；正式 tag 或 `--release` 不允许 `--sign off`。

打包器在生成归档后、签名前复验发布源内容及精确 HEAD/tag 身份，并在签名完成、取得输出目录独占锁后再次复验。同一输出目录的并发打包提交会串行执行；普通错误会尝试恢复原有集合，若恢复不完整则保留 `.sun-commit-backup-*` 证据，后续打包也会失败关闭等待人工处理。四个独立路径不是对未加锁读取者的一次文件系统原子切换；`SIGKILL`、内核崩溃或断电可能留下部分集合和恢复目录，不承诺崩溃原子性。只有命令成功返回且不存在恢复目录后，才能读取、校验或上传 `$release_dist`。

## 生成文件

```text
$release_dist/security-update-notify-VERSION.tar.gz
$release_dist/security-update-notify-VERSION.tar.gz.sha256
$release_dist/security-update-notify-VERSION.tar.gz.asc  # 签名构建
$release_dist/sun.sh.asc                                  # 签名构建，高保障首次安装
```

发布压缩包只包含安装、诊断、引导、迁移兼容所需的产品文件，以及 README 引用的用户和维护者文档；不包含构建工具、workflow 或私有运维资料。`sun.sh` 包含在签名压缩包中；签名构建还在压缩包之外生成 `sun.sh.asc`，不会把不确定签名时间写入可复现归档。镜像工作流从验签归档提取脚本和公钥，与 detached signature 一起发布到不可变版本目录；兼容稳定 URL 仍只提供 `sun.sh`。`install.sh` 与 `files/security-update-notify` 是 Go 打包器为旧 2.x 自升级客户端生成的最小启动器和版本标记，不包含旧安装或运行时逻辑，也不会落到已安装系统。

发布包内容：

```text
.env.example
CHANGELOG.md
LICENSE
README.md
README.en.md
VERSION
sun.sh
install.sh                              # 仅 2.x -> 3.0 的 Go 启动器
docs/development.en.md
docs/development.md
docs/go-port.md
docs/installation.en.md
docs/installation.md
docs/operations.en.md
docs/operations.md
docs/releasing.en.md
docs/releasing.md
docs/security.en.md
docs/security.md
files/needrestart-report-only.conf
files/release-signing.pub.asc
files/security-update-notify            # 仅旧客户端读取的版本标记
files/security-update-notify.logrotate
files/security-update-notify.service
files/security-update-notify-linux-amd64
files/security-update-notify-linux-arm64
files/security-update-notify-linux-386
files/security-update-notify-linux-ppc64le
files/security-update-notify-linux-s390x
```

## 先验证 Draft，再发布不可变 Release

发布操作必须严格按以下顺序进行。沿用前面已验证发布提交的变量和仍未推送的本地 annotated tag；从唯一的
同版本 CHANGELOG 段生成非空 `notes_file`，禁止手工填写占位路径：

```bash
set -euo pipefail
archive="security-update-notify-${tag#v}.tar.gz"
assets=("$archive" "$archive.sha256" "$archive.asc" "sun.sh.asc")
release_epoch="$(git show -s --format=%ct "$release_sha")"
notes_file="$(mktemp "/tmp/security-update-notify-${tag}-notes.XXXXXX")"
awk -v heading="## ${tag#v}" '
  $0 == heading { seen++; capture = (seen == 1); next }
  capture && /^## / { capture = 0 }
  capture { body[++count] = $0 }
  END {
    if (seen != 1) exit 1
    first = 1
    while (first <= count && body[first] == "") first++
    last = count
    while (last >= first && body[last] == "") last--
    if (last < first) exit 1
    for (line = first; line <= last; line++) print body[line]
  }
' CHANGELOG.md >"$notes_file"
[[ -s "$notes_file" ]]
```

正式资产必须直接构建到前面新建的 `$release_dist`，不能复用仓库内可能留有旧版本文件的 `dist/`。下面的
函数要求输入目录恰好包含四个普通文件，独立复验 checksum、归档白名单与签名，并在每次调用时创建全新的
GPG home，要求 `sun.sh.asc` 只有一个有效签名结果，且同时绑定固定主指纹和唯一 critical 版本 notation：

```bash
set -euo pipefail
release_pin='C678256ACBFC6491BF5076655F3AE24999921FFC'
release_notation='release-version@xxv.cc'
verify_release_set() {
  local set_dir="$1" actual_set expected_set verify_work bootstrap_status
  local gpg_home
  local -a gpg_cmd primary_fingerprints

  actual_set="$(find "$set_dir" -mindepth 1 -maxdepth 1 \
    -printf '%f\t%y\n' | LC_ALL=C sort)"
  expected_set="$(printf '%s\tf\n' "${assets[@]}" | LC_ALL=C sort)"
  [[ "$actual_set" == "$expected_set" ]]

  (cd "$set_dir" && sha256sum -c "$archive.sha256")
  go run ./cmd/security-update-notify verify \
    --tarball "$set_dir/$archive" \
    --sha256 "$set_dir/$archive.sha256" \
    --asc "$set_dir/$archive.asc" \
    --pubkey files/release-signing.pub.asc \
    --fingerprint "$release_pin"
  python3 -I build/release-archive-test.py \
    "$set_dir/$archive" "${tag#v}" "$release_epoch" .

  verify_work="$(mktemp -d "/tmp/security-update-notify-${tag}-verify.XXXXXX")"
  gpg_home="$verify_work/gnupg"
  install -m 0700 -d "$gpg_home"
  tar -xOf "$set_dir/$archive" \
    "security-update-notify-${tag#v}/sun.sh" >"$verify_work/sun.sh"
  cmp sun.sh "$verify_work/sun.sh"
  gpg_cmd=(gpg --no-options --homedir "$gpg_home" --batch)
  "${gpg_cmd[@]}" --import files/release-signing.pub.asc
  mapfile -t primary_fingerprints < <(
    "${gpg_cmd[@]}" --with-colons --fingerprint --list-keys |
      awk -F: '$1 == "pub" { want = 1; next }
                want && $1 == "fpr" { print $10; want = 0 }'
  )
  [[ "${#primary_fingerprints[@]}" -eq 1 \
     && "${primary_fingerprints[0]}" == "$release_pin" ]]
  bootstrap_status="$("${gpg_cmd[@]}" \
    --known-notation "$release_notation" --status-fd=1 --show-notation \
    --verify "$set_dir/sun.sh.asc" "$verify_work/sun.sh" \
    2>"$verify_work/bootstrap-gpg.log")"
  awk -v pin="$release_pin" -v notation="$release_notation" \
      -v version="${tag#v}" '
    $1 == "[GNUPG:]" && $2 == "GOODSIG" { outcome_count++; good_count++ }
    $1 == "[GNUPG:]" && $2 ~ /^(EXPSIG|EXPKEYSIG|REVKEYSIG|BADSIG|ERRSIG)$/ {
      outcome_count++
    }
    $1 == "[GNUPG:]" && $2 == "VALIDSIG" {
      valid_count++
      if ($3 == pin || $NF == pin) pinned_count++
    }
    $1 == "[GNUPG:]" && $2 == "NOTATION_NAME" {
      name_count++
      if (NF == 3 && $3 == notation) name_match++
    }
    $1 == "[GNUPG:]" && $2 == "NOTATION_FLAGS" {
      flags_count++
      if (NF == 4 && $3 == 1 && $4 == 1) flags_match++
    }
    $1 == "[GNUPG:]" && $2 == "NOTATION_DATA" {
      data_count++
      if (NF == 3 && $3 == version) data_match++
    }
    END {
      exit !(outcome_count == 1 && good_count == 1 &&
             valid_count == 1 && pinned_count == 1 &&
             name_count == 1 && name_match == 1 &&
             flags_count == 1 && flags_match == 1 &&
             data_count == 1 && data_match == 1)
    }
  ' <<<"$bootstrap_status"
}

[[ "$(git cat-file -t "$tag")" == tag ]]
[[ "$(git rev-parse "$tag^{commit}")" == "$release_sha" ]]
verify_release_set "$release_dist"
```

本地集合全部通过后才推送 tag，并立即从远端读取 direct 与 peeled ref，要求远端对象与本地 annotated tag
对象一致且只 peel 到 `release_sha`；不能把 `gh --verify-tag` 当作 annotated tag 身份证明：

```bash
set -euo pipefail
verify_remote_tag() {
  local remote_refs remote_tag_object remote_tag_commit
  remote_refs="$(git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}")"
  remote_tag_object=''
  remote_tag_commit=''
  while read -r object ref; do
    case "$ref" in
      "refs/tags/$tag") remote_tag_object="$object" ;;
      "refs/tags/$tag^{}") remote_tag_commit="$object" ;;
    esac
  done <<<"$remote_refs"
  [[ "$remote_tag_object" == "$(git rev-parse "$tag")" ]]
  [[ "$remote_tag_commit" == "$release_sha" ]]
}
git push origin "refs/tags/$tag"
verify_remote_tag
```

基于已经存在的远端 tag 创建仍可修改的 Draft Release，并上传明确列出的四项资产：

```bash
set -euo pipefail
gh release create "$tag" \
  "$release_dist/$archive" \
  "$release_dist/$archive.sha256" \
  "$release_dist/$archive.asc" \
  "$release_dist/sun.sh.asc" \
  --draft --verify-tag \
  --repo xxvcc/security-update-notify \
  --title "$tag" --notes-file "$notes_file"
```

省略 `--draft` 会过早公开 Release；省略 `--verify-tag` 会让 `gh` 在远端 tag 不存在时自动创建 lightweight tag。两者都不允许。

把 Draft 的全部资产下载到全新目录。先从 GitHub JSON 元数据证明 Release 仍是 Draft、tag 正确、资产名集合
精确且正文与提取的 CHANGELOG 段逐字节一致；再对回下载目录执行与本地完全相同的签名/归档验证，并逐项与
本地签名集合做字节比较：

```bash
set -euo pipefail
verify_dir="$(mktemp -d)"
gh release download "$tag" --repo xxvcc/security-update-notify --dir "$verify_dir"
release_json="$verify_dir/release.json.part"
gh release view "$tag" --repo xxvcc/security-update-notify \
  --json assets,body,isDraft,tagName >"$release_json"
python3 -I - "$notes_file" "$release_json" "$tag" "${assets[@]}" <<'PY'
import json
import sys
from pathlib import Path

notes_path, json_path, expected_tag, *expected_assets = sys.argv[1:]
metadata = json.loads(Path(json_path).read_text(encoding="utf-8"))
actual_assets = sorted(asset["name"] for asset in metadata["assets"])
if metadata["isDraft"] is not True:
    raise SystemExit("release is no longer a Draft")
if metadata["tagName"] != expected_tag:
    raise SystemExit("Draft tag does not match the verified tag")
if actual_assets != sorted(expected_assets):
    raise SystemExit(
        f"Draft asset set mismatch: {actual_assets!r} != {sorted(expected_assets)!r}"
    )
expected_body = Path(notes_path).read_text(encoding="utf-8")
if not expected_body or metadata["body"] != expected_body:
    raise SystemExit("Draft body differs from the exact CHANGELOG entry")
PY
rm -f -- "$release_json"
verify_release_set "$verify_dir"
for asset in "${assets[@]}"; do
  cmp "$release_dist/$asset" "$verify_dir/$asset"
done
```

不能把上传成功或本地校验结果当作远端校验。Draft 期间关联 tag 仍可变，因此发布前必须再次调用
`verify_remote_tag` 关闭整个 Draft 校验窗口。只有 Draft 中的上述检查全部通过后，才能发布为不可变 Latest Release，并立即要求 API 报告该 Release 已锁定：

```bash
set -euo pipefail
verify_remote_tag
gh release edit "$tag" --draft=false --latest --verify-tag \
  --repo xxvcc/security-update-notify
release_immutable="$(gh api "repos/xxvcc/security-update-notify/releases/tags/$tag" \
  --jq .immutable)"
latest_tag="$(gh api repos/xxvcc/security-update-notify/releases/latest --jq .tag_name)"
[[ "$release_immutable" == true && "$latest_tag" == "$tag" ]]
```

## 发布与镜像保护

正式 GitHub Release 的无部署权限 CI 完成后，`Mirror signed release` 才开始同步；该 CI 只是事件信号和纵深检查，不能自行授权发布。真正的部署门禁来自受保护默认分支的 workflow revision：自动路径按成功 CI 的固定 `head_sha` 检出源码，确认 tag 仍指向同一提交，并通过 GitHub compare API 证明发布提交和实际执行的 workflow revision 都属于当前受保护 `main` 的历史；手动修复还会在仓库内明确拒绝从 `refs/heads/main` 以外的 ref 触发。工作流的 `verify-release` runner 不持有 Environment：它先用默认分支固定的离线指纹和验证器重新校验精确资产集、归档、五架构 ELF 身份与静态链接；tag 的源码检出始终只作为不执行的数据，完成签名和归档校验后的五个运行时会在空环境、固定 PATH、有界超时和输出限制下以 `--version` 实际执行。只有该 runner 成功后，全新的 `verify-and-sync` runner 才取得仅允许 `main` 的 GitHub Environment 身份；它从头复验资产结构、规范 checksum、元数据、GPG、归档和引导器签名，但不执行任何发布载荷。

部署 SSH 身份由 forced-command `rrsync` 限制，不能在镜像主机执行任意 shell 命令；部署身份只存在于受 `main` 限制的 Environment。`verify-and-sync` 使用仓库级全局 concurrency 串行所有镜像写入。部署 runner 从已验签归档提取 `sun.sh` 和公钥，复验脚本签名与版本 notation，上传不可变版本目录，并从 `dl.ll.cd` 回读完整版本化集合；随后再次查询 GitHub Latest。仅当目标仍是 Latest 时，才以单文件 `rsync --delay-updates` 更新稳定 `sun.sh` 并完成公网回读，再最后更新和回读 `latest.json`。手动重跑旧版本只补齐其版本目录，不会覆盖稳定入口或 Latest。

`sun.sh` 与 `latest.json` 各自延迟替换，但两个文件不构成跨文件事务：若稳定脚本已经更新而后续步骤失败，公网可能暂时出现新 `sun.sh` 配旧 `latest.json`；更新发现仍停留在旧 manifest，维护者必须从 `main` 幂等重跑同一 tag。不要在前一个版本完成镜像和 canary 前发布下一个正式版本；GitHub concurrency 只保留一个 pending job，更晚的发布可能替换尚未开始的 pending job，此时必须手工补跑被替换的版本。仓库已经启用不可变 Release；每次镜像成功后以及每周一，独立 GitHub 托管 Ubuntu 22.04/24.04 真机 canary 会从两个公网源重新下载并实测验签、安装、doctor、dry-run、timer、卸载和 APT 配置恢复。

Release 必须先成为不可变状态。无部署权限的 release CI 验证公开资产后，默认分支上的镜像 workflow 才能使用受 Environment 限制的部署身份；tag 源码不执行，验签后的运行时只为实际版本探针调用。不要手工跳过 checksum、GPG、固定指纹、版本 notation、五架构实际版本、公网回读或 canary。

## 发布后核对

- GitHub Latest 指向目标不可变 Release，且显式资产集合恰好为四项。
- GitHub 与版本化镜像资产逐字节一致，checksum 和 GPG 验证通过。
- 稳定 `sun.sh`、版本化 `sun.sh` 和签名归档内脚本一致；关键 notation 绑定目标版本。
- Ubuntu 22.04/24.04 公网 canary 完成安装、doctor、dry-run、timer、卸载和 APT 基线恢复。
- 最后确认 `main`、远端提交、tag 和发布版本绑定一致。
