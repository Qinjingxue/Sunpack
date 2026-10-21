import { makeStyles, tokens, MessageBar, MessageBarBody } from "@fluentui/react-components";
import { useTranslation } from "react-i18next";
import { CodeBlock } from "../components/CodeBlock";

const useStyles = makeStyles({
  page: {
    maxWidth: "880px",
  },
  title: {
    fontSize: "32px",
    fontWeight: 700,
    color: tokens.colorNeutralForeground1,
    marginBottom: "8px",
  },
  subtitle: {
    color: tokens.colorNeutralForeground2,
    marginBottom: "32px",
    lineHeight: "24px",
  },
  section: {
    marginBottom: "32px",
  },
  sectionTitle: {
    fontSize: "20px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground1,
    marginBottom: "12px",
  },
  paragraph: {
    color: tokens.colorNeutralForeground2,
    lineHeight: "24px",
    marginBottom: "16px",
  },
  list: {
    color: tokens.colorNeutralForeground2,
    lineHeight: "28px",
    paddingInlineStart: "24px",
    marginBottom: "16px",
  },
});

const buildCode = `# Clone the repository
git clone https://github.com/ghboke/core-ui.git
cd core-ui

# Build with the bundled PowerShell script
powershell -NoProfile -ExecutionPolicy Bypass \`
  -File scripts/build-clang-cl.ps1 -Target core-ui

# Output: build output directory contains core-ui.dll + core-ui.lib`;

const minimalExample = `#include "ui_core.h"

void on_click(UiWidget w, void* data) {
    UiWindow win = (UiWindow)(uintptr_t)data;
    ui_toast(win, L"Button clicked!", 2000);
}

int main() {
    ui_init();  // Initialize with dark theme

    UiWindowConfig cfg = {
        .title = L"My First App",
        .width = 640,
        .height = 480,
    };
    UiWindow win = ui_window_create(&cfg);

    // Build UI tree
    UiWidget root = ui_vbox();
    ui_widget_set_padding_uniform(root, 24);
    ui_widget_set_gap(root, 16);

    UiWidget title = ui_label(L"Welcome to Core UI");
    ui_label_set_font_size(title, 28);
    ui_label_set_bold(title, true);
    ui_widget_add_child(root, title);

    UiWidget btn = ui_button(L"Say Hello");
    ui_widget_on_click(btn, on_click, (void*)(uintptr_t)win);
    ui_widget_add_child(root, btn);

    ui_window_set_root(win, root);
    ui_window_show(win);
    return ui_run();
}`;

const markupWay = `<!-- app.uix -->
<window title="Welcome" width="500" height="320" centered="true"/>

<script>
export default {
  data() { return { greeting: "Welcome to Core UI", dark: false }; },
  methods: {
    onHello() { this.greeting = "Hi there!"; },
  },
}
</script>

<style>
  .shell { padding: 24px; gap: 16px; background: var(--bg); }
  .h1    { font-size: 28px; color: var(--fg); font-weight: 700; }
  .row   { flex-direction: row; gap: 8px; align-items: center; }
</style>

<template>
<div class="shell">
  <label class="h1">{{ greeting }}</label>

  <button @click="onHello">Say Hello</button>

  <div class="row">
    <toggle v-model="dark"/>
    <label>Dark mode</label>
  </div>
</div>
</template>`;

const cmakeIntegration = `# CMakeLists.txt
add_executable(myapp WIN32 main.cpp)
target_include_directories(myapp PRIVATE third_party/core-ui/include)
target_link_libraries(myapp PRIVATE
    third_party/core-ui/lib/dynamic/core-ui.lib)

add_custom_command(TARGET myapp POST_BUILD
    COMMAND \${CMAKE_COMMAND} -E copy_if_different
        \${CMAKE_SOURCE_DIR}/third_party/core-ui/lib/dynamic/core-ui.dll
        $<TARGET_FILE_DIR:myapp>)`;

export function GettingStarted() {
  const styles = useStyles();
  const { t } = useTranslation();

  return (
    <div className={styles.page}>
      <h1 className={styles.title}>{t("gs.title")}</h1>
      <p className={styles.subtitle}>{t("gs.subtitle")}</p>

      <MessageBar intent="info" style={{ marginBottom: "24px" }}>
        <MessageBarBody>{t("gs.requirements")}</MessageBarBody>
      </MessageBar>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("gs.buildTitle")}</h2>
        <CodeBlock code={buildCode} language="Shell" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("gs.cmakeTitle")}</h2>
        <p className={styles.paragraph}>{t("gs.cmakeDesc")}</p>
        <CodeBlock code={cmakeIntegration} language="CMake" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("gs.minimalTitle")}</h2>
        <p className={styles.paragraph}>{t("gs.minimalDesc")}</p>
        <CodeBlock code={minimalExample} language="C" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("gs.markupTitle")}</h2>
        <p className={styles.paragraph}>{t("gs.markupDesc")}</p>
        <CodeBlock code={markupWay} language=".uix" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("gs.distTitle")}</h2>
        <ul className={styles.list}>
          <li><strong>{t("gs.distDynamic")}</strong> {t("gs.distDynamicDesc")}</li>
          <li><strong>{t("gs.distStatic")}</strong> {t("gs.distStaticDesc")}</li>
        </ul>
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("gs.depsTitle")}</h2>
        <p className={styles.paragraph}>{t("gs.depsDesc")}</p>
        <ul className={styles.list}>
          <li>Direct2D, Direct3D 11, DXGI, DirectWrite</li>
          <li>DWM, UxTheme, WindowsCodecs</li>
          <li>GDI+ (for image streaming mode)</li>
        </ul>
      </div>
    </div>
  );
}
