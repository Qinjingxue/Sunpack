# 快速开始

## 文件结构

```
my_app/
  main.cpp          — 入口：加载 .ui 文件 + 注册事件
  app.ui            — 界面布局（声明式）
  ui_core.h         — 头文件
  core-ui.dll       — 运行时库
```

## CMake 集成

发布包提供两种链接方式，按需选用。

### 方式 A：动态链接（DLL）

体积小，运行时需带 `core-ui.dll`。

```cmake
add_executable(my_app WIN32 main.cpp)
target_include_directories(my_app PRIVATE third_party/core-ui/include)
target_link_libraries(my_app PRIVATE
    third_party/core-ui/lib/dynamic/core-ui.lib)

# 把 DLL 拷到 exe 同目录（运行时加载需要）
add_custom_command(TARGET my_app POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/third_party/core-ui/lib/dynamic/core-ui.dll
        $<TARGET_FILE_DIR:my_app>)
```

### 方式 B：静态链接（单 EXE）

把 core-ui 整个编进 exe，运行时**零非系统 DLL**依赖。下游交付最干净的方式。

```cmake
include(third_party/core-ui/cmake/UiCoreHelpers.cmake)

add_executable(my_app WIN32 main.cpp)
target_compile_definitions(my_app PRIVATE UI_CORE_STATIC)  # 必须！
target_include_directories(my_app PRIVATE third_party/core-ui/include)
target_link_libraries(my_app PRIVATE
    third_party/core-ui/lib/static/core-ui.lib
    ${UI_CORE_STATIC_SYSTEM_LIBS})    # Win32 系统 lib，helper 已定义好

# 推荐用 /MT 静态 CRT —— release 自带的 core-ui.lib 就是 /MT 编的，下游
# 用 /MD 会触发 LNK4098 mismatch 警告
set_property(TARGET my_app PROPERTY MSVC_RUNTIME_LIBRARY
    "MultiThreaded$<$<CONFIG:Debug>:Debug>")
```

`UI_CORE_STATIC` 这个 define **必须**加，否则 `ui_core.h` 里 API 宏会展开成
`__declspec(dllimport)`，链接 static lib 直接报 unresolved external。

## .ui 文件方式（推荐）

**app.ui**
```xml
<ui version="1" width="640" height="480" resizable="true" title="My App">
  <VBox gap="0" expand="true">
    <TitleBar title="My App" />
    <VBox padding="24" gap="12" expand="true">
      <Label text="Hello, Core UI!" fontSize="20" bold="true" />
      <Button id="btn" text="Click Me" width="120" onClick="onBtnClick" />
      <Label id="status" text="Ready" />
    </VBox>
  </VBox>
</ui>
```

**main.cpp**
```cpp
#include <ui_core.h>
#include "../src/ui/markup/markup.h"
#include "../src/ui/controls.h"
#include "../src/ui/ui_context.h"
#include "../src/ui/ui_window.h"

static ui::UiMarkup g_layout;
static UiWindow g_win = UI_INVALID;

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    ui_init();

    // 1. 注册事件（必须在 LoadFile 之前）
    g_layout.SetHandler("onBtnClick", std::function<void()>([]() {
        g_layout.SetText("status", L"Button clicked!");
        ui_window_invalidate(g_win);
    }));

    // 2. 加载 .ui 文件
    if (!g_layout.LoadFile(L"app.ui")) {
        MessageBoxA(nullptr, g_layout.LastError().c_str(), "Error", MB_ICONERROR);
        return 1;
    }

    // 3. 创建窗口
    auto& wh = g_layout.Window();
    UiWindowConfig cfg = {0};
    cfg.title = L"My App";
    cfg.width = wh.width; cfg.height = wh.height;
    cfg.resizable = wh.resizable;
    g_win = ui_window_create(&cfg);

    auto& ctx = ui::GetContext();
    ui_window_set_root(g_win, ctx.handles.Insert(g_layout.Root()));
    ui_window_show(g_win);

    int ret = ui_run();
    ui_shutdown();
    return ret;
}
```

## C API 方式（简单场景 / 非 C++ 宿主）

```c
#include <ui_core.h>

void on_click(UiWidget w, void* ud) {
    ui_label_set_text(*(UiWidget*)ud, L"Clicked!");
}

int WINAPI wWinMain(HINSTANCE h, HINSTANCE, LPWSTR, int) {
    ui_init();
    UiWindowConfig cfg = {0};
    cfg.title = L"My App"; cfg.width = 640; cfg.height = 480; cfg.resizable = 1;
    UiWindow win = ui_window_create(&cfg);

    UiWidget root = ui_vbox();
    ui_widget_set_padding_uniform(root, 16);
    ui_widget_set_gap(root, 8);

    UiWidget label = ui_label(L"Hello!");
    ui_widget_add_child(root, label);

    UiWidget btn = ui_button(L"Click Me");
    ui_widget_set_width(btn, 120);
    ui_widget_on_click(btn, on_click, &label);
    ui_widget_add_child(root, btn);

    ui_window_set_root(win, root);
    ui_window_show(win);
    return ui_run();
}
```

## 内嵌资源（单 EXE 发布）

不想随 exe 拖一堆 `.uix` / `.ui` / `.lang` 外部文件？用 `ui_core_embed_text()`
CMake helper 把它们烤进 exe，得到完全自包含的二进制。

**1. 在你的 CMakeLists 里 include helper：**

```cmake
# 假设 release 包解压到 third_party/core-ui/
include(third_party/core-ui/cmake/UiCoreHelpers.cmake)

add_executable(my_app WIN32 main.cpp)
target_link_libraries(my_app PRIVATE core-ui)

# 把 app.uix 烤成 inline constexpr char[]，自动加进 my_app 的 sources
ui_core_embed_text(my_app
    FILE app.uix
    OUT  app_uix.embed.h
    VAR  k_app_uix)
```

**2. 在源码里直接 #include 用：**

```cpp
#include <ui_core.h>
#include "app_uix.embed.h"   // CMake 自动生成到 build dir

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    ui_init_with_theme(UI_THEME_LIGHT);
    UiPage page = ui_page_load_string(k_app_uix);
    UiWindow win = ui_page_open_window(page, nullptr);
    return ui_run();
}
```

源 `app.uix` 改了 ninja/make 自动重新生成 `.embed.h` 触发重新编译，不用手动 xxd。

**`.uix` 之外**：`.ui`（旧 markup）、`.lang`（i18n）、纯文本任何东西都可以这样
内嵌 —— 只要对应加载 API 接受 `const char*` 就行。`ui-demo.exe` 自己就是这样
做的：app.ui + 中英 lang 全内嵌，单文件运行（参见 `demo/app.cpp` + 顶层
`CMakeLists.txt` 里 `ui_core_embed_text(ui-demo ...)`）。

### 图片 / 外部 CSS（自 build 19）

`.uix` 模板里 `<img src="logo.png">` / `<link rel="stylesheet" href="theme.css">`
按"名字"引用资源。两种工作流：

**dev：注册一个目录**

```c
ui_init();
ui_asset_register_dir("assets");   // <img src="logo.png"> → assets/logo.png
UiPage p = ui_page_load_file(L"app.uix");
```

边改 PNG / CSS 边看，不用重编。

**ship：CMake 烤成字节，注册 blob**

```cmake
ui_core_embed_text  (my_app FILE assets/theme.css OUT theme_css.embed.h VAR k_theme_css)
ui_core_embed_binary(my_app FILE assets/logo.png  OUT logo_png.embed.h  VAR k_logo_png)
```

`ui_core_embed_text` 给文本（CSS / .uix / lang），`ui_core_embed_binary`
给二进制（PNG / JPG / 任意 blob，无 0x00 终结符）。

```cpp
#include "logo_png.embed.h"
#include "theme_css.embed.h"

ui_init();
ui_asset_register_blob("logo.png",  k_logo_png,  k_logo_png_size);
ui_asset_register_blob("theme.css", k_theme_css, k_theme_css_size);
UiPage p = ui_page_load_string(k_app_uix);   // .uix 完全不变
```

**`.uix` 里 `src` / `href` 始终是同一个名字**，dev / ship 切换不用改一行。
完整 API：见 [c-api.md 资源解析器](c-api.md#资源解析器自-140-build-19)。
