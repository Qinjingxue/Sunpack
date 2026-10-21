# HTML UI 子系统计划（历史文档）

> ⚠️ **历史文档** —— 这是当年规划"HTML page 子系统"时写的，文中所有 `.html`/`<state>`
> 都已经在 build 30 切到 `.uix` SFC 格式。完整现状参考 [uix-guide.md](uix-guide.md)。
> 保留本文用于追溯设计动机。
>
> 原始目标：在 core-ui 中新增一套 HTML + Vue-like 语法的声明式 UI 子系统，与现有
> `.ui` markup 并存，不破坏任何既有代码。

---

## 1. 范围与非范围

### 目标
- **`.html` = 页面**（顶级 UI 单元，不是可复用组件）
- Vue 风格语法：`{{ }}` / `:attr` / `@event` / `v-if` / `v-for` / `v-model`
- CSS 子集：现代 Web 常用的 ~45 个属性，选择器 8 种
- 响应式运行时：`Property<T>` + `Binding` + 线程局部捕获
- 自研 Flex 布局引擎（不引入 Yoga）
- 热重载

### 非目标（v0 明确不做）
- 组件组合（`<MyCard />` 仅限于 C++ 注册的 widget，不支持 .html 之间 import）
- JavaScript 引擎
- 虚拟 DOM
- 外部 `.css` 文件
- `<style>` 非 scoped 的复杂场景（默认 scoped）
- CSS: grid / float / animation / filter / `!important`
- Flex: wrap / reverse / align-content / baseline / order
- v-for 的 keyed diff
- slots / 组件生命周期

---

## 2. 设计决定（锁定）

### HTML 解析
- **L3 严格模式**：所有标签必须闭合（`<br/>` 而不是 `<br>`）
- 文件后缀：`.html`
- 单根约束
- 短形式属性语法：`:x="e"` / `@x="f"` / `v-if` / `v-for` / `v-model`
- 文本插值 `{{ expr }}`，空白折叠 + trim 首尾
- 注释 `<!-- -->` 支持；CDATA 不支持；DOCTYPE / `<?xml?>` 识别后忽略
- 实体：5 基础 + 数字引用 + `&nbsp;`，不支持全 HTML 命名实体
- 解析器输出纯 AST（不耦合 Widget）
- 表达式即时 parse（attr 里的 AST 随模板 AST 一起产出）

### 表达式子集
- 字面量：数字、字符串（`'…'` 或 `"…"`）、布尔、null
- 运算符：`+ - * / %` / `< <= > >= == !=` / `&& || !` / `?:` / `.` 成员 / `[]` 下标
- 函数调用：仅调白名单
- 对象字面量 `{k: v}`、数组字面量 `[a, b]`（`:style`/`:class` 必需）
- **不支持**：赋值、`new`、`typeof`、箭头函数、模板字符串

### CSS
- **`<style>` 默认 scoped**，加 `global` 关键字才全局（编译期加 `data-c="hash"` 重写选择器）
- **主题用 CSS `var(--x)`**，`:root` 定义
- **`box-sizing: border-box`** 默认值
- **display 默认值由 widget 类型决定**（`<VBox>` 默认 column-flex）
- **不支持 `!important`**
- **v0 不支持外部 `.css`**
- 选择器：type / class / id / descendant / child / attr / pseudo-class / grouping
- 不支持：`+ ~` 兄弟、`:nth-*`、`::before/::after`、`:not`、`*`
- 属性清单详见 §5 CSS 子集
- `calc()` + `var()` 必须有

### 响应式运行时
- `Property<T>` 值类型，`Get()`/`Set()` + `SetSilent()` + `Bind(lambda)`
- `Binding` 持 lambda，RAII `CaptureScope` 捕获依赖
- 线程局部 `g_current`
- 同步通知（v0 不批处理）
- 循环检测：`evaluating_` 标志位

### 指令语义
- **`v-if`**：挂载/卸载（不是 visible 切换）
- **`v-for`**：v0 裸重建；`:key` 语法接受但忽略
- **`v-model`**：简单糖，编译成 `:value + @input/change`，支持 input/textarea/checkbox/select/slider

### 页面模型
- `.html` = 页面（顶级单元）
- 每个页面有 `PageState`：响应式变量池 + handler 表
- C API：`ui_page_load` / `ui_page_set_*` / `ui_page_set_handler` / `ui_page_reload`

### Flex 布局
- 单行（nowrap）
- `flex-direction`: row / column
- `justify-content`: start / end / center / space-between / space-around / space-evenly
- `align-items` / `align-self`: start / end / center / stretch
- `flex-grow` / `flex-shrink` / `flex-basis` / `flex` 简写
- `gap` / `row-gap` / `column-gap`
- v1 再加：wrap / reverse / align-content / order

---

## 3. 目录结构

```
src/ui/
├── reactive/          # M1
│   ├── property.h
│   ├── binding.h
│   └── binding.cpp
├── expression/        # M2
│   ├── value.h
│   ├── ast.h
│   ├── parser.h/cpp   # Pratt
│   └── evaluator.h/cpp
├── html/              # M3
│   ├── tokenizer.h/cpp
│   ├── html_parser.h/cpp
│   ├── entities.cpp
│   └── errors.h
├── css/               # M4
│   ├── css_tokenizer.h/cpp
│   ├── css_parser.h/cpp
│   ├── selector.h/cpp
│   ├── value.h/cpp
│   ├── cascade.h/cpp
│   └── applier.h/cpp
├── flex/              # M5
│   ├── flex.h
│   └── flex.cpp       # pure function
├── page/              # M6-M8
│   ├── widget_factory.h/cpp
│   ├── compiler.h/cpp
│   ├── render_plan.h
│   ├── page_state.h/cpp
│   └── page_api.cpp   # C API
test/src/
├── reactive_test.cpp
├── expression_test.cpp
├── html_parser_test.cpp
├── css_parser_test.cpp
├── flex_test.cpp
└── page_integration_test.cpp
demo/
├── html_demo.cpp
└── app.html
include/
└── ui_core.h          # 追加 ui_page_* 声明
```

---

## 4. 模块依赖图

```
          ┌──────────────────┐
          │  reactive (M1)    │
          └────────┬──────────┘
                   │
     ┌─────────────┼─────────────┐
     │             │             │
 expression    html parser    css parser
   (M2)         (M3)           (M4)
     │             │             │
     └─────────────┼─────────────┘
                   │
             widget factory (M6)
                   │
             compiler (M7)  ──── flex (M5, 独立)
                   │
         page runtime + C API (M8)
                   │
                 demo (M9)
```

独立可测的模块：**M1/M2/M3/M4/M5**。

---

## 5. CSS 属性清单（v0）

**盒模型**
- width / height / min-width / max-width / min-height / max-height
- padding / padding-top|right|bottom|left
- margin / margin-top|right|bottom|left
- border / border-width / border-color / border-style / border-radius（4 角）
- box-sizing（默认 border-box）

**背景**
- background-color
- background-image（纯色 / linear-gradient / url）
- background-size / background-position / background-repeat

**文字**
- color
- font-family / font-size / font-weight / font-style
- line-height / letter-spacing / text-align / text-decoration
- white-space / word-break / overflow-wrap

**布局**
- display（flex / block / inline / none）
- flex-direction / justify-content / align-items / align-self / flex-wrap
- flex-grow / flex-shrink / flex-basis / flex
- gap / row-gap / column-gap
- position（static / relative / absolute）/ top / right / bottom / left / z-index

**视觉**
- opacity / visibility / overflow / cursor
- box-shadow
- transform（translate / rotate / scale）
- transition（v0 解析不生效，P1 启用）

**值类型**
- 长度：px / % / em / rem / vw / vh / auto
- 颜色：#RGB / #RRGGBB / #RRGGBBAA / rgb() / rgba() / hsl() / hsla() / 命名色 / var()
- calc(): 算术 `+ - * /`
- var(): CSS 变量引用

---

## 6. HTML Tag → Widget 映射

| HTML | Widget |
|---|---|
| `<div>` | VBox/HBox（由 flex-direction 决定）|
| `<span>` | Label（inline）|
| `<p>` | Label（normal white-space）|
| `<h1>`–`<h6>` | Label + 预置字号 |
| `<button>` | Button |
| `<a>` | Label + cursor:pointer + click |
| `<img>` | ImageViewPlus |
| `<input type="text">` | TextInput |
| `<input type="checkbox">` | CheckBox |
| `<input type="radio">` | RadioButton |
| `<input type="range">` | Slider |
| `<input type="number">` | NumberBox |
| `<textarea>` | TextArea |
| `<select>` | ComboBox |
| `<ul>` / `<ol>` | VBox + 预置 padding |
| `<li>` | HBox 或 Label |
| `<hr/>` | Separator |
| 任意 CamelCase tag | C++ 注册的自定义 widget |

未知 tag → 报错 + edit-distance 建议。

---

## 7. 实施阶段

### M1 — 响应式核心（独立）
- [ ] property.h / binding.h / binding.cpp
- [ ] 单测：Get/Set、Bind lambda、依赖自动追踪、COW 隔离、循环检测、生命周期（P 先死/B 先死）
- [ ] CMake 集成（加入 UI_CORE_SOURCES）+ test/CMakeLists
- [ ] 编译验证（clang++）+ 单测全绿
- **完成标志**：`./reactive_test` 输出全 [PASS]

### M2 — 表达式引擎（独立）
- [ ] Value 变体（Number/String/Bool/Null/Object/Array）
- [ ] AST 节点类型
- [ ] Pratt parser（支持表达式子集所列全部运算符和字面量）
- [ ] Evaluator（在给定 scope 下求值，读 Property → 自动被上层 Binding 捕获依赖）
- [ ] 单测：字面量、算术、比较、逻辑、三元、成员、下标、调用、对象/数组、错误位置
- **完成标志**：能从字符串 `"user.age > 18 ? 'adult' : 'minor'"` parse + 求值

### M3 — HTML 解析器（独立）
- [ ] Tokenizer（状态机）
- [ ] AST 类型（HtmlNode、Attr、Expression 嵌入）
- [ ] 解析主循环（标签/文本/插值/注释）
- [ ] 实体解码
- [ ] 错误收集（多错误 + 行列号 + edit-distance 建议）
- [ ] 单测：静态 HTML、绑定/事件/指令、嵌套、错误场景
- **完成标志**：从给定 .html 字符串产出可 dump 的 AST

### M4 — CSS 子系统（独立）
- [ ] CSS tokenizer
- [ ] rule AST（selectors + declarations）
- [ ] selector 匹配器
- [ ] 值解析（长度/颜色/calc/var）
- [ ] cascade 解析器（specificity + 继承）
- [ ] scoped 选择器重写
- [ ] 单测：选择器匹配、特异度、calc 求值、var 解析
- **完成标志**：给定 CSS 文本 + widget tree，产出每个 widget 的 ComputedStyle

### M5 — Flex 布局（独立）
- [ ] flex.h 的 LayoutInput / LayoutResult 结构
- [ ] 算法（主轴空间分配 / 交叉轴对齐 / gap）
- [ ] 单测：100+ case 覆盖所有 justify/align/grow/shrink 组合
- **完成标志**：纯函数，给输入算输出，不依赖 widget

### M6 — Widget 工厂
- [ ] HTML tag → widget 类型分发
- [ ] 属性应用（common attrs + HTML 特有）
- [ ] 自定义 widget 注册接口
- **完成标志**：给定 HtmlNode + ComputedStyle 能构造 Widget

### M7 — 编译器
- [ ] AST + StyleRules → RenderPlan
- [ ] scoped rewrite 执行
- [ ] 指令 lowering（v-if / v-for / v-model）
- [ ] 静态属性与响应式属性分离
- **完成标志**：RenderPlan 能被 instantiate 多次，零额外解析

### M8 — 运行时 + C API
- [ ] PageState：Property 池 + handler 表
- [ ] Loader：parse → compile → instantiate
- [ ] 热重载：diff RenderPlan，保留顶层 Property 值
- [ ] C API：`ui_page_load` / `ui_page_set_*` / `ui_page_set_handler` / `ui_page_reload`
- **完成标志**：C API 能加载 .html 文件并正常交互

### M9 — Demo
- [ ] `demo/app.html`：覆盖数据绑定、v-if、v-for、flex 布局、样式、v-model
- [ ] `demo/html_demo.cpp`：开窗、加载 .html、连接 handler
- **完成标志**：demo 窗口跑起来，交互正常

---

## 8. 每模块完成标准

1. 编译通过（clang++ -std=c++17 / MSVC）
2. 单测 ≥ 90% 关键路径覆盖
3. 无 warning（-Wall -Wextra）
4. 不破坏现有 core-ui 构建（`.ui` markup 测试仍然通过）

---

## 9. 总量估算

| 模块 | 源码 | 测试 |
|---|--:|--:|
| M1 响应式 | 280 | 300 |
| M2 表达式 | 800 | 300 |
| M3 HTML 解析 | 900 | 300 |
| M4 CSS 子系统 | 1900 | 500 |
| M5 Flex | 700 | 400 |
| M6 Widget 工厂 | 500 | 100 |
| M7 编译器 | 800 | 200 |
| M8 运行时 + C API | 1200 | 200 |
| M9 Demo | 200 | — |
| **合计** | **~7300** | **~2300** |

文档 + CMake 约 500 行。总工作量约 **10,000 行**。

---

## 10. 风险

| 风险 | 应对 |
|---|---|
| Flex 边界 case 复杂度爆炸 | 单测驱动，100+ case 先写，算法围着测试转 |
| 响应式系统的循环/野指针 | 第一版用 vector 简单实现，性能不够再 intrusive |
| CSS calc/var 的依赖追踪 | var 读取时走 Property → 自然被 Binding 捕获 |
| 热重载保状态的 diff 不可靠 | v0 不保精细状态，只保顶层变量按名字映射 |
| 与现有 .ui 的构建冲突 | 严格新增目录，不动 src/ui/markup |

---

## 11. 当前状态

- 设计阶段：✅ 完成
- M1 响应式核心：🔄 进行中
- 其他模块：⏸ 待启动
