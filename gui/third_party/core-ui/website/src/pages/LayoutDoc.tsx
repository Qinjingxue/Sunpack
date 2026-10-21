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

const vboxExample = `<!-- .uix flex column (default flex-direction is column) -->
<style>
  .col { padding: 16px; gap: 12px; }
</style>
<div class="col">
  <label>Top</label>
  <label>Middle</label>
  <label>Bottom</label>
</div>

<!-- C API equivalent -->
// UiWidget col = ui_vbox();
// ui_widget_set_padding_uniform(col, 16);
// ui_widget_set_gap(col, 12);
// ui_widget_add_child(col, ui_label(L"Top"));`;

const flexExample = `<!-- flex: 1 makes a widget fill remaining space -->
<style>
  .body  { flex: 1; }
  .head  { height: 48px; }
  .foot  { height: 32px; }
</style>
<div>
  <label class="head">Header</label>
  <div class="body">
    <label>Content</label>
  </div>
  <label class="foot">Footer</label>
</div>

<!-- C API: ui_widget_set_expand(content, 1) -->`;

const gridExample = `<!-- core-ui doesn't ship a true CSS Grid; emulate with stacked flex rows. -->
<style>
  .grid-row { flex-direction: row; gap: 8px; }
  .cell     { flex: 1; padding: 8px; background: var(--card-bg); }
  .span2    { flex: 2; }
</style>
<div style="gap: 8px">
  <div class="grid-row">
    <div class="cell"><label>1</label></div>
    <div class="cell"><label>2</label></div>
    <div class="cell"><label>3</label></div>
  </div>
  <div class="grid-row">
    <div class="cell span2"><label>4 (2 cols)</label></div>
    <div class="cell"><label>5</label></div>
  </div>
</div>`;

const scrollExample = `// ScrollView with auto-scrollbar
UiWidget scroll = ui_scroll_view();
UiWidget content = ui_vbox();
ui_widget_set_gap(content, 8);
for (int i = 0; i < 100; i++) {
    ui_widget_add_child(content, ui_label(L"Item"));
}
ui_scroll_set_content(scroll, content);
ui_widget_set_expand(scroll, 1);`;

export function LayoutDoc() {
  const styles = useStyles();
  const { t } = useTranslation();

  return (
    <div className={styles.page}>
      <h1 className={styles.title}>{t("layout.title")}</h1>
      <p className={styles.subtitle}>{t("layout.subtitle")}</p>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("layout.vboxHboxTitle")}</h2>
        <p className={styles.paragraph}>{t("layout.flexDesc")}</p>
        <CodeBlock code={vboxExample} language=".uix" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("layout.flexTitle")}</h2>
        <p className={styles.paragraph}>{t("layout.flexExpandDesc")}</p>
        <CodeBlock code={flexExample} language=".uix" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("layout.gridTitle")}</h2>
        <p className={styles.paragraph}>{t("layout.gridDesc")}</p>
        <CodeBlock code={gridExample} language=".uix" />
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("layout.scrollTitle")}</h2>
        <p className={styles.paragraph}>{t("layout.scrollDesc")}</p>
        <CodeBlock code={scrollExample} language="C" />
      </div>
    </div>
  );
}
