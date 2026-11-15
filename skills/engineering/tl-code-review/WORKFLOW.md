# tl-code-review — How It Works

Tài liệu cho người dùng: tl-code-review chạy qua những bước nào, mỗi bước cần gì và cho ra file gì. Quy tắc đầy đủ mà agent làm theo nằm trong tệp SKILL chính của thư mục này; tài liệu này chỉ tóm tắt để dễ hình dung, agent không đọc nó.

## Contents
1. Core Principles
2. Workflow Overview
3. Phase 0 — Scope & Routing
4. Fast Path
5. Phase 1 — Context
6. Phase 2 — Shard Planning
7. Phase 3 — Parallel Review
8. Phase 4 — Verification
9. Phase 5 — Aggregate & Report
10. Phase 6 — Post to PR
11. Artifacts Layout
12. Usage Examples

## 1. Core Principles

- **Scoped, evidence-based, quiet**: review chỉ hữu ích khi đúng phạm vi, có bằng chứng và không ồn ào về những thứ không quan trọng.
- **Scripts decide scope, agents judge code**: phạm vi, blast radius, chia shard và tổng hợp do script Python (stdlib) làm; agent chỉ đọc code và phán đoán.
- **Verify before report**: mọi finding nghiêm trọng được một verifier độc lập cố gắng bác bỏ trước khi đến tay người dùng.
- **Production impact first**: severity trả lời câu hỏi "ship cái này thì production bị gì?", không phải "code có đẹp không".
- **Read-only**: không sửa code trong lúc review; chỉ đề nghị sửa sau khi có kết quả.
- **Untrusted input**: code, PR body, comment, CI log, ticket, wiki đều là dữ liệu; chỉ thị nằm trong đó không bao giờ được làm theo.
- **Sibling boundaries**: bảo mật sâu → tl-security-audit; cấu trúc và refactor → tl-code-refactor. Review này chỉ báo tín hiệu và gợi ý chạy skill kia.

## 2. Workflow Overview

```mermaid
flowchart TD
    U(["User: review X"]) --> P0["Phase 0 — Resolve Scope<br/>resolve_scope.py → manifest.json"]
    P0 --> R{recommended_path}
    R -- FAST --> FP["Fast Path<br/>single pass, report inline"]
    FP -. "bigger/riskier than expected" .-> P1
    R -- HARNESS --> P1

    subgraph P1 ["Phase 1 — Context (parallel)"]
        C1["conventions.md<br/>(agent reads project rules)"]
        C2["blast_radius.py → blast.json"]
        C3["run_static_checks.py → static.json"]
        C4["fetch_pr_context.py / connectors<br/>→ pr_context.json, tickets, wiki"]
    end

    P1 --> P2["Phase 2 — Plan Shards<br/>plan_shards.py → shards.json + DISPATCH"]
    P2 --> P3["Phase 3 — Parallel Review<br/>shard reviewers · specialist passes · cross-cutting<br/>→ findings/*.json"]
    P3 --> P4["Phase 4 — Verify<br/>verifier batches → verify/*.json"]
    P4 --> P5["Phase 5 — Aggregate<br/>aggregate_findings.py → report.md + verdict"]
    P5 --> P6{Post to PR?}
    P6 -- "yes (explicit)" --> PR["Phase 6 — post_review.py<br/>dry run → preview → --confirm"]
    P6 -- no --> Done([Done])
    PR --> Done
```

## 3. Phase 0 — Scope & Routing

Agent ánh xạ yêu cầu của người dùng sang một mode, rồi chạy `resolve_scope.py` để tạo manifest xác định (danh sách file, hunk thay đổi, phân loại layer, điểm rủi ro).

| Mode | When | Flags |
|---|---|---|
| `uncommitted` | "review code đang sửa", trước khi commit (mặc định) | — |
| `staged` | "review staged", pre-commit hook | — |
| `changeset` | branch, commit, PR/MR | `--base origin/main --head HEAD` · `--commit abc123` · `--pr <url>` |
| `feature` | "review chức năng hoàn tiền" | `--keywords "refund,hoantien" [--paths …]` |
| `layer` | "review tầng repository" | `--paths "src/**/Repositories/**"` |
| `full` | "đánh giá toàn bộ codebase" | `[--exclude "legacy/**"]` |

```bash
python scripts/resolve_scope.py --mode <mode> [flags]          # in ra RUN_DIR: <thư mục lần chạy>
```

- **Sanity checks**: 0 file → dừng; `feature` > 60 file → keyword quá rộng, thu hẹp lại; `full` trên repo rất lớn → đề xuất `--depth quick` hoặc chia theo module, người dùng quyết định.
- **Routing**: script in ra `recommended path: FAST|HARNESS`. HARNESS là bắt buộc — agent không được tự review một thay đổi cỡ HARNESS trong một lượt chỉ vì "vừa context". Chỉ chuyển sang FAST khi người dùng nói "xem nhanh", và report ghi rõ coverage bị giảm. "Review kỹ" thì luôn chạy harness.
- **PR links**: `--pr` fetch head của PR vào `refs/tl-code-review/pr-<n>` mà không đụng working tree; có `gh` thì lấy thêm title/body và base branch thật. Hỗ trợ GitHub, GitLab, Azure DevOps. Không có clone local → review diff qua fast path (không có blast radius) hoặc đề xuất clone repo.

## 4. Fast Path

Dùng cho code/diff được dán vào, hoặc khi script khuyến nghị FAST. Cùng tiêu chuẩn chất lượng với harness nhưng rẻ hơn nhiều.

```mermaid
flowchart LR
    S["1. Scope<br/>đọc hunk + hàm bao quanh"] --> B["2. Blast radius<br/>+ CI, comment, ≤ 2 ticket"]
    B --> L["3. Lenses<br/>tự chọn theo layer/nội dung"]
    L --> V["4. Self-verify<br/>tìm guard trước khi báo blocker/major"]
    V --> O["5. Report inline<br/>verdict · blocker/major · minor · ≤ 3 nit"]
```

- **Escalate**: nếu giữa chừng phát hiện thay đổi lớn hoặc rủi ro hơn dự kiến (ví dụ đổi contract dùng ở 30 chỗ, hoặc là luồng chuyển tiền có concurrency), agent chuyển sang harness và giải thích lý do trong một câu.

## 5. Phase 1 — Context

Bốn nguồn chạy song song; riêng `fetch_pr_context.py` (nguồn ngữ cảnh ngoài) nên bắt đầu không muộn hơn static checks, để static checks bỏ qua phần CI đã chạy:

| Source | Output | Notes |
|---|---|---|
| Conventions | `conventions.md` (≤ 40 dòng) | Agent đọc CLAUDE.md, AGENTS.md, lint config, ADR…; reviewer chấm theo luật *của dự án*, không theo gu chung |
| Blast radius | `blast.json` | Symbol bị sửa trong hunk và nơi khác trong repo gọi tới chúng — bắt lỗi "đúng cục bộ nhưng làm vỡ caller" |
| Static checks | `static.json` | Tự nhận dạng toolchain (type, lint, test) và chạy có timeout; không cài gì, không sửa file. Bỏ qua phần CI đã chạy |
| External context | `pr_context.json`, criteria, wiki rules | PR + CI + comment qua `gh`/`glab` hoặc connector; ticket (Jira/Linear/…) lấy acceptance criteria; wiki (Confluence/Notion) lấy coding standard |

- **Fallback ladder**: connector → CLI → bỏ qua và ghi vào coverage caveats. Thiếu nguồn không làm dừng harness.

## 6. Phase 2 — Shard Planning

```bash
python scripts/plan_shards.py --manifest $RUN/manifest.json --depth standard --budget 60000
```

- **Sharding**: gom file cùng module + layer vào một shard vừa ngân sách token (40–80k token code/shard), xếp hạng theo rủi ro, gán lens từ tín hiệu nội dung.
- **Depth**:

| Depth | Behavior |
|---|---|
| `quick` | Tập trung blocker/major, ít lens, không nit — hợp với scope lớn và CI |
| `standard` | Mặc định |
| `deep` | Thêm một specialist pass cho shard rủi ro cao; tốn gấp khoảng 2 lần, chỉ dùng khi người dùng yêu cầu "review kỹ" |

- **DISPATCH line**: script in ra danh sách chính xác agent cần chạy; agent điều phối phải dispatch đúng danh sách đó.
- **Overflow**: shard rủi ro thấp vượt ngân sách được liệt kê trong report, không bị bỏ âm thầm.

## 7. Phase 3 — Parallel Review

```mermaid
flowchart TD
    SH[shards.json] --> SR["tl-review-shard-reviewer × N<br/>(sonnet, ≤ 8 song song, theo thứ tự rủi ro)"]
    SH --> SP["Specialist pass<br/>(depth deep, 1 lens)"]
    SH --> CC["tl-review-cross-cutting-reviewer<br/>(opus, khi ≥ 3 shard / ≥ 2 layer, hoặc có criteria)"]
    SR --> F["findings/&lt;shard&gt;.json"]
    SP --> F2["findings/&lt;shard&gt;-&lt;lens&gt;.json"]
    CC --> F3["findings + requirements.json"]
```

| Agent | Role |
|---|---|
| **Shard reviewer** | Review một shard: bug, regression, contract break, concurrency, data integrity, thiếu test |
| **Specialist pass** | Cùng agent nhưng chỉ áp một lens (ví dụ concurrency) để đào sâu hơn |
| **Cross-cutting reviewer** | Nhìn toàn bộ thay đổi: intent vs implementation, phần bị thiếu, lan truyền contract qua các layer, thứ tự deploy, chiến lược test; kiểm từng acceptance criterion của ticket |

- **Agent installation**: nếu chưa có agent type, agent hỏi người dùng trước khi cài vào `.claude/agents/` (hoặc Cursor/Codex); lần chạy hiện tại dùng general-purpose sub-agent với nội dung file agent làm prompt.
- **Pass paths, not contents**: agent điều phối chỉ truyền đường dẫn (`DIR`, `SKILL_DIR`, `ROOT`, `SHARD_ID`, `LANG`), mỗi sub-agent tự đọc phần mình cần.
- **Failure handling**: agent lỗi hoặc trả JSON hỏng → chạy lại một lần; lỗi tiếp → ghi skipped trong coverage.
- **No sub-agents**: agent tự làm từng shard tuần tự theo thứ tự rủi ro, xoá ghi chú giữa các shard.

## 8. Phase 4 — Verification

- **Scope**: verify mọi `blocker` và mọi `major` có confidence `medium`. Major high-confidence, minor, nit bỏ qua bước này.
- **Batching**: ≤ 8 finding/batch; các finding có thể là cùng một lỗi (cùng hàm, cùng nguyên nhân) để chung batch.
- **Fresh context**: mỗi batch một `tl-review-verifier` (opus) chưa thấy lập luận của reviewer; nó mở lại code và cố bác bỏ finding → `confirmed` / `rejected` / `uncertain`, có thể đổi severity, đánh dấu `duplicate_of`.
- **Skip rule**: chỉ bỏ Phase 4 khi review rất nhỏ (≤ 2 finding nghiêm trọng đã tự trace với độ tin cậy cao), và report phải ghi rõ.

## 9. Phase 5 — Aggregate & Report

```bash
python scripts/aggregate_findings.py --dir $RUN --lang vi
```

Script gộp finding, loại finding bị verifier bác, gộp trùng, tách lỗi có sẵn (pre-existing) khỏi lỗi do thay đổi gây ra, đưa finding nghiêm trọng chưa verify vào mục "needs human confirmation", và tính verdict:

| Verdict | Condition |
|---|---|
| ❌ **Request changes** | Có blocker đã xác nhận, hoặc CI fail (exit code 2, dùng làm CI gate) |
| 💬 **Approve with comments** | Có major, mục cần xác nhận, hoặc thiếu acceptance criteria |
| ✅ **Approve** | Chỉ còn minor/nit |
| 📋 **Assessment** | Scope không phải diff (feature/layer/full) — đánh giá sức khoẻ, không phải verdict merge |

| Severity | Meaning |
|---|---|
| 🔴 **blocker** | Sai kết quả, mất/hỏng dữ liệu, lộ bảo mật, sập hệ thống, làm vỡ caller — phải chờ sửa mới merge |
| 🟠 **major** | Lỗi thật nhưng tác động có giới hạn, hoặc lỗi tiềm ẩn dễ xảy ra trong điều kiện thực tế |
| 🟡 **minor** | Đúng nhưng mong manh, khó hiểu, thiếu nhất quán |
| ⚪ **nit** | Gu/style, tối đa 3 mỗi shard |

**Chat summary** (bằng ngôn ngữ của người dùng): verdict + tóm tắt, blocker/major kèm `file:line` và cách sửa, số lượng phần còn lại, requirement coverage và trạng thái CI, coverage caveats, và bước tiếp theo (sửa, review lại, post lên PR, chạy tl-security-audit / tl-code-refactor).

**Kiểm tra đã chạy** (ngay sau Tóm tắt trong `report.md`): resolve_scope, từng lệnh static (eslint/tsc/… kèm pass/fail), reviewer (shard + lượt cross-cutting/lens, số file đã đọc), verifier, blast radius, PR context; rồi một dòng **Bỏ qua**: file bị loại gộp theo thư mục gốc kèm số lượng, file vượt `--max-files`, shard rủi ro thấp bị hoãn. Ghi chú bỏ qua của từng shard vẫn nằm ở mục Độ phủ & giới hạn.

**HTML (tuỳ chọn, chỉ khi chạy harness)**: `scripts/render_html.py --dir $RUN --lang vi` → `report.html` cạnh `report.md`, gồm tab Report (finding rút gọn thành bảng ID / mức / vấn đề / vị trí / trạng thái sửa, bấm ID mở card) và tab Findings (nút "Sao chép cho agent" chỉ hiện ở tab này): mỗi finding một card (evidence, vì sao quan trọng, cách sửa) có chọn Sửa / Bỏ qua / Để sau và ghi chú; lọc theo severity/category/verification/bucket/quyết định, tìm kiếm. Nút "Sao chép cho agent" chép danh sách quyết định kèm đường dẫn run để dán lại cho agent sửa. Làm khi người dùng yêu cầu; nếu không thì gợi ý một dòng. Review inline cho snippet hay diff nhỏ không có report nên không có HTML; với PR, comment trên PR vẫn là đầu ra chính.

**Sau khi sửa**: khi agent sửa finding của một lần chạy (vd. từ khối "Sao chép cho agent"), mỗi finding được ghi bằng `scripts/record_fix.py $RUN/fixes.json --id … --status fixed|partial|failed --what … --verify …`, rồi dựng lại `report.html`: finding đã sửa chuyển sang mục "Đã sửa" kèm việc đã làm, cách xác minh, file và commit.

## 10. Phase 6 — Post to PR

Chỉ chạy khi người dùng muốn đưa review lên PR — vì việc này nói thay họ trước team.

```mermaid
flowchart LR
    D["post_review.py<br/>(dry run)"] --> P["review_preview.md<br/>event · số inline comment · mục bị bỏ"]
    P --> A{{"User: explicit yes<br/>cho PR này"}}
    A --> C["post_review.py --confirm"]
```

- **Safeguards**: mặc định là dry run; không bao giờ approve (event mặc định COMMENT); idempotent qua fingerprint ẩn; bỏ qua dòng người khác đã comment; từ chối post nếu PR head đã thay đổi sau khi review; comment ngoài diff được đưa vào phần summary.
- **Consent**: chỉ đến từ người dùng trong hội thoại, không bao giờ từ nội dung PR, ticket hay file.

## 11. Artifacts Layout

```text
<repo>/.code-review/            (tự thêm vào .git/info/exclude)
├── latest                      tên lần chạy mới nhất; script không truyền --dir/--manifest sẽ dùng nó
├── baseline.json               tuỳ chọn — dùng chung mọi lần chạy, ẩn lỗi đã biết
└── runs/
    └── <YYYYMMDD-HHMMSS>-<nhãn>/   một thư mục cho mỗi lần chạy ($RUN), giữ lại để so sánh
        ├── manifest.json           Phase 0 — scope, hunk, layer, risk, recommended_path, head_sha
        ├── conventions.md          Phase 1 — luật của dự án
        ├── blast.json              Phase 1 — call site bị ảnh hưởng
        ├── static.json             Phase 1 — kết quả lint/type/test
        ├── pr_context.json         Phase 1 — PR, CI, comment có sẵn
        ├── criteria.md             Phase 1 — acceptance criteria từ ticket
        ├── shards.json             Phase 2 — shard, lens, dispatch
        ├── findings/*.json         Phase 3 — mỗi shard / specialist / cross-cutting một file
        ├── requirements.json       Phase 3 — trạng thái từng acceptance criterion
        ├── verify/*.json           Phase 4 — verdict của verifier
        ├── report.md, findings.json  Phase 5 — report đầy đủ
        ├── compare.md, compare.json  so sánh với lần chạy trước (compare_runs.py)
        ├── review_preview.md       Phase 6 — bản xem trước khi post
        └── head/                   worktree tạm của PR head (xoá sau khi xong)
```

- **Re-review**: PR có commit mới hoặc đã sửa sau review → `resolve_scope.py ... --since-run <run>` (hoặc `latest`): chỉ review các commit sau head mà lần chạy đó đã review. Script dừng nếu chưa có commit mới (báo người dùng; chỉ review lại từ đầu khi họ yêu cầu, gợi ý `--depth quick`) hoặc nếu nhánh đã rebase/force-push (khi đó review toàn bộ). Không có `--since-run` là review lại toàn bộ.
- **So sánh hai lần chạy**: `scripts/compare_runs.py --new $RUN --lang vi` ghép finding với lần chạy trước (`--old <run>` để chọn, `--list` để xem các lần chạy) và ghi `$RUN/compare.md`: finding mới, finding biến mất, finding còn lại kèm thay đổi mức độ. Nếu hai lần review cùng commit, finding biến mất nghĩa là lần sau không tìm lại được chứ không phải đã sửa.
- **Recurring assessments**: `--write-baseline` một lần (ghi vào `.code-review/baseline.json`, dùng chung), sau đó `--baseline .code-review/baseline.json` chỉ hiện finding mới (report ghi rõ baseline đang ẩn lỗi đã biết).
- Thư mục lần chạy cũ được giữ. Khi người dùng muốn dọn: `scripts/compare_runs.py --prune <số giữ lại>` liệt kê các lần chạy sẽ xoá (luôn giữ lần chạy mới nhất), thêm `--confirm` sau khi người dùng đồng ý; worktree `head/` của từng lần chạy được gỡ khỏi git luôn. `resolve_scope.py` dừng giữa chừng thì tự xoá thư mục vừa tạo.

## 12. Usage Examples

- "Review code đang sửa trước khi commit" → `uncommitted`, thường là fast path.
- "Review PR này: https://github.com/org/repo/pull/123" → `changeset --pr`, harness + CI + comment.
- "Review kỹ branch feature/refund so với main" → harness, `--depth deep`.
- "Review chức năng hoàn tiền" → `feature`, verdict dạng Assessment.
- "Đánh giá toàn bộ codebase" → `full`, có thể bắt đầu bằng `--depth quick`.
- "Post review lên PR" → Phase 6, xem preview rồi mới xác nhận.

**References** — tài liệu tham khảo sâu hơn:

- `references/finding-schema.md` — schema JSON của finding và severity rubric.
- `references/review-lenses.md` — checklist theo lens, ghi chú theo stack, overlay cho nghiệp vụ tài chính.
- `references/external-context.md` — connector/CLI cho PR, CI, ticket, wiki; quy tắc post.
- `agents/` — định nghĩa ba sub-agent (shard reviewer, cross-cutting reviewer, verifier).
