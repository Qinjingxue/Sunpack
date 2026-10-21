import { makeStyles, tokens } from "@fluentui/react-components";
import { useTranslation } from "react-i18next";
import { CodeBlock } from "../components/CodeBlock";

const useStyles = makeStyles({
  page: { maxWidth: "880px" },
  title: { fontSize: "32px", fontWeight: 700, color: tokens.colorNeutralForeground1, marginBottom: "8px" },
  subtitle: { color: tokens.colorNeutralForeground2, marginBottom: "32px", lineHeight: "24px" },
  section: { marginBottom: "32px" },
  sectionTitle: { fontSize: "20px", fontWeight: 600, color: tokens.colorNeutralForeground1, marginBottom: "12px" },
  paragraph: { color: tokens.colorNeutralForeground2, lineHeight: "24px", marginBottom: "16px" },
});

const skeleton = `<window title="Hello" width="500" height="320" centered="true"/>

<script>
export default {
  data() { return { count: 0, name: "Ada" }; },
  computed: {
    doubled() { return this.count * 2; },
  },
  methods: {
    inc() { this.count++; },
  },
}
</script>

<style>
  .shell { padding: 24px; gap: 12px; background: var(--bg); }
  .h1    { font-size: 22px; color: var(--fg); font-weight: 700; }
</style>

<template>
<div class="shell">
  <label class="h1">Hi, {{ name }}</label>
  <label>count = {{ count }}, doubled = {{ doubled }}</label>
  <button @click="inc">+1</button>
</div>
</template>`;

const reactivity = `<script>
export default {
  data() {
    return {
      items: [
        { id: 1, text: "alpha", done: false },
        { id: 2, text: "beta",  done: true  },
      ],
      filter: "all",
    };
  },
  computed: {
    visible() {
      if (this.filter === "active") return this.items.filter(x => !x.done);
      if (this.filter === "done")   return this.items.filter(x =>  x.done);
      return this.items;
    },
    pending() { return this.items.filter(x => !x.done).length; },
  },
  methods: {
    toggle(it) {
      this.items = this.items.map(x =>
        x.id === it.id ? { ...x, done: !x.done } : x);
    },
  },
}
</script>`;

const directives = `<template>
<div class="shell">
  <!-- 文本插值 -->
  <label>Hello, {{ name }} ({{ count }} items)</label>

  <!-- 属性绑定 :attr -->
  <button :class="canSave ? '' : 'subtle'" @click="save">Save</button>

  <!-- 事件 @event="method" 或表达式 -->
  <input @change="onName($event)" placeholder="name"/>

  <!-- v-if 条件挂载 / 卸载；v-show 只切换可见性 -->
  <label v-if="page === 'home'">Home page</label>
  <label v-if="page === 'about'">About page</label>
  <label v-show="page !== 'home' && page !== 'about'">Unknown</label>

  <!-- v-for 列表渲染（推荐带 :key） -->
  <div v-for="(it, i) in visible" :key="it.id" class="row">
    <input type="checkbox" :checked="it.done" @change="toggle(it)"/>
    <label>{{ i }}: {{ it.text }}</label>
  </div>

  <!-- v-model 双向绑定 -->
  <input v-model="name"/>
  <toggle v-model="darkMode"/>
</div>
</template>`;

const styleBlock = `<style>
  /* 库自动注入 ~30 个语义 CSS 变量，主题切换时全部重 cascade。 */
  .shell    { padding: 16px; gap: 8px; background: var(--bg); }
  .sidebar  { background: var(--sidebar-bg); }
  .card     { background: var(--card-bg); border-radius: 6px; padding: 16px; }
  .h1       { font-size: 24px; color: var(--fg); font-weight: 700; }
  .lbl      { font-size: 13px; color: var(--fg-2); }
  .btn      { background: var(--accent); color: var(--fg-on-accent);
              padding: 6px 14px; border-radius: 4px; }
  .btn:hover{ opacity: 0.9; }

  /* 后代选择器 / 多类 / 伪类 / :root vars 都支持 */
  .nav.on > .nav-bar { background: var(--accent); }
  :root              { --my-brand: #ff5588; }
</style>`;

const i18n = `<script>
export default {
  data() { return { name: "Ada" }; },
}
</script>

<template>
<div>
  <!-- $t(key) 查表，依赖 $locale 反应式 -->
  <label>{{ $t('greeting') }} {{ name }}</label>
  <button @click="$locale = 'zh'">中文</button>
  <button @click="$locale = 'en'">English</button>
</div>
</template>`;

const lifecycle = `// C side — register a per-id lifecycle hook (Vue ref+watch parity)
void on_btn_mount(UiPage page, UiWidget w, void* ud) {
    // 'w' is the freshly-mounted widget instance — wire callbacks here.
    ui_widget_on_click(w, on_click, ud);
}

ui_page_on_widget_mount(page, "btn_x", on_btn_mount, NULL);
// Fires every time v-if / v-for re-mounts a widget with id="btn_x".
// Use ui_page_on_widget_unmount for cleanup.`;

const reactiveMenu = `<script>
export default {
  data() {
    return {
      commands: [
        { id: 'copy',  label: 'Copy',  enabled: true  },
        { id: 'paste', label: 'Paste', enabled: false },
      ],
      isAdmin: true,
    };
  },
  methods: {
    run(cmd) { /* ... */ },
    del()    { /* ... */ },
  },
}
</script>

<template>
<div id="tree-item">tree</div>

<menu trigger="#tree-item" event="rclick">
  <menuitem v-for="cmd in commands" :key="cmd.id"
            :disabled="!cmd.enabled" @click="run(cmd)">
    <label>{{ cmd.label }}</label>
  </menuitem>
  <separator/>
  <menuitem v-if="isAdmin" @click="del">
    <label>Delete</label>
  </menuitem>
</menu>
</template>`;

const cIntegration = `// Load + run a .uix file (single-file component)
UiPage page = ui_page_load_file(L"demo/app.uix");
if (!page) {
    fprintf(stderr, "%s\\n", ui_page_last_error(page));
    return 1;
}

// Optional: load translations
ui_page_load_language_file(page, "zh", L"lang/zh.lang");
ui_page_load_language_file(page, "en", L"lang/en.lang");
ui_page_set_locale(page, "zh");

// Open the window declared by <window .../>
UiWindow win = ui_page_open_window(page, NULL);

// Push initial state from C
ui_page_set_string(page, "name", "Ada");
ui_page_set_int(page, "count", 0);

ui_run();
ui_page_destroy(page);`;

export function Markup() {
  const styles = useStyles();
  const { t } = useTranslation();

  return (
    <div className={styles.page}>
      <h1 className={styles.title}>{t("markup.title")}</h1>
      <p className={styles.subtitle}>{t("markup.subtitle")}</p>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("markup.skeletonTitle")}</h2>
        <p className={styles.paragraph}>{t("markup.skeletonDesc")}</p>
        <CodeBlock code={skeleton} language=".uix" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("markup.scriptTitle")}</h2>
        <p className={styles.paragraph}>{t("markup.scriptDesc")}</p>
        <CodeBlock code={reactivity} language=".uix" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("markup.directivesTitle")}</h2>
        <p className={styles.paragraph}>{t("markup.directivesDesc")}</p>
        <CodeBlock code={directives} language=".uix" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("markup.styleTitle")}</h2>
        <p className={styles.paragraph}>{t("markup.styleDesc")}</p>
        <CodeBlock code={styleBlock} language=".uix" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("markup.i18nTitle")}</h2>
        <p className={styles.paragraph}>{t("markup.i18nDesc")}</p>
        <CodeBlock code={i18n} language=".uix" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("markup.lifecycleTitle")}</h2>
        <p className={styles.paragraph}>{t("markup.lifecycleDesc")}</p>
        <CodeBlock code={lifecycle} language="C" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("markup.reactiveMenuTitle")}</h2>
        <p className={styles.paragraph}>{t("markup.reactiveMenuDesc")}</p>
        <CodeBlock code={reactiveMenu} language=".uix" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("markup.cIntegrationTitle")}</h2>
        <p className={styles.paragraph}>{t("markup.cIntegrationDesc")}</p>
        <CodeBlock code={cIntegration} language="C" />
      </div>
    </div>
  );
}
