// Build a .docx from the JSON spec written by build_docs.py (docx-js).
// Usage: node build_docx.js <spec.json>
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell,
  WidthType, ShadingType, BorderStyle, AlignmentType, HeadingLevel, LevelFormat,
  PageBreak, Footer, PageNumber, PositionalTab, PositionalTabAlignment,
  PositionalTabRelativeTo, PositionalTabLeader, TableLayoutType,
} = require("docx");

const spec = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));

const NAVY = "0B1F3A";
const ACCENT = "0E7490";
const FONT = "Calibri";
const MONO = "Consolas";
const PAGE_W = 11906; // A4 width (DXA)
const MARGIN = 1020; // 1.8 cm
const CONTENT_W = PAGE_W - 2 * MARGIN; // 9866 DXA
const MAX_IMG_PX = Math.floor((CONTENT_W / 1440) * 96); // ~657 px

// ---- inline markup: **bold**, `code`, *italic* ----------------------------
function runs(text, base = {}) {
  const out = [];
  const re = /(\*\*.+?\*\*|`.+?`|(?<![\w*])\*(?!\s).+?(?<!\s)\*(?![\w*]))/g;
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(new TextRun({ ...base, text: text.slice(last, m.index) }));
    const tok = m[0];
    if (tok.startsWith("**")) out.push(new TextRun({ ...base, text: tok.slice(2, -2), bold: true }));
    else if (tok.startsWith("`"))
      out.push(new TextRun({ ...base, text: tok.slice(1, -1), font: MONO, size: 18,
        shading: { type: ShadingType.CLEAR, color: "auto", fill: "F1F5F9" } }));
    else out.push(new TextRun({ ...base, text: tok.slice(1, -1), italics: true }));
    last = m.index + tok.length;
  }
  if (last < text.length) out.push(new TextRun({ ...base, text: text.slice(last) }));
  return out;
}

const thin = { style: BorderStyle.SINGLE, size: 4, color: "E2E8F0" };
const none = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };

function table(b) {
  const n = b.head.length;
  const fr = b.widths || Array(n).fill(1 / n);
  const widths = fr.map((f) => Math.floor(f * CONTENT_W));
  widths[n - 1] += CONTENT_W - widths.reduce((a, c) => a + c, 0); // exact sum
  const cell = (text, i, header, zebra) =>
    new TableCell({
      width: { size: widths[i], type: WidthType.DXA },
      shading: header
        ? { type: ShadingType.CLEAR, color: "auto", fill: NAVY }
        : zebra ? { type: ShadingType.CLEAR, color: "auto", fill: "F8FAFC" } : undefined,
      margins: { top: 60, bottom: 60, left: 100, right: 100 },
      borders: { top: thin, bottom: thin, left: none, right: none },
      children: [new Paragraph({
        spacing: { before: 0, after: 0 },
        children: runs(String(text), header ? { bold: true, color: "FFFFFF", size: 19 } : { size: 19 }),
      })],
    });
  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: widths,
    layout: TableLayoutType.FIXED,
    rows: [
      new TableRow({ tableHeader: true, children: b.head.map((h, i) => cell(h, i, true)) }),
      ...b.rows.map((r, ri) =>
        new TableRow({ cantSplit: true, children: r.map((c, i) => cell(c, i, false, ri % 2 === 1)) })),
    ],
  });
}

function image(b) {
  const [w, h] = b.px;
  const targetW = Math.round(MAX_IMG_PX * (b.width || 1));
  const scale = targetW / w;
  let width = targetW;
  let height = Math.round(h * scale);
  const MAX_H = 860; // keep tall screenshots within one page
  if (height > MAX_H) { width = Math.round(width * (MAX_H / height)); height = MAX_H; }
  return [
    new Paragraph({
      alignment: AlignmentType.CENTER, keepNext: true, spacing: { before: 120, after: 60 },
      children: [new ImageRun({ type: "png", data: fs.readFileSync(b.path),
        transformation: { width, height },
        altText: { title: b.caption, description: b.caption, name: b.caption } })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER, spacing: { after: 200 },
      children: runs(b.caption, { italics: true, size: 17, color: "475569" }),
    }),
  ];
}

let listInstance = 0;
function blocks(list) {
  const out = [];
  for (const b of list) {
    switch (b.t) {
      case "h1": out.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: runs(b.text) })); break;
      case "h2": out.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: runs(b.text) })); break;
      case "h3": out.push(new Paragraph({ heading: HeadingLevel.HEADING_3, children: runs(b.text) })); break;
      case "p":
        out.push(new Paragraph({ alignment: AlignmentType.JUSTIFIED, spacing: { after: 120 }, children: runs(b.text) }));
        break;
      case "ul": case "ol": {
        listInstance += 1;
        for (const item of b.items)
          out.push(new Paragraph({
            numbering: { reference: b.t === "ul" ? "bullets" : "numbers", level: 0, instance: listInstance },
            spacing: { after: 60 }, children: runs(item),
          }));
        out.push(new Paragraph({ spacing: { after: 60 }, children: [] }));
        break;
      }
      case "code": {
        // One dark cell holding one paragraph per line: renders as a single solid block
        // (per-paragraph shading leaves thin white gaps between lines in Word).
        const lines = b.text.split("\n");
        out.push(new Table({
          width: { size: CONTENT_W, type: WidthType.DXA },
          columnWidths: [CONTENT_W],
          rows: [new TableRow({ cantSplit: true, children: [new TableCell({
            width: { size: CONTENT_W, type: WidthType.DXA },
            shading: { type: ShadingType.CLEAR, color: "auto", fill: "0F172A" },
            margins: { top: 120, bottom: 120, left: 180, right: 180 },
            borders: { top: none, bottom: none, left: none, right: none },
            children: lines.map((line) => new Paragraph({
              spacing: { before: 0, after: 0, line: 252 },
              children: [new TextRun({ text: line.length ? line : " ", font: MONO, size: 18, color: "E2E8F0" })],
            })),
          })] })],
        }), new Paragraph({ spacing: { after: 120 }, children: [] }));
        break;
      }
      case "note":
        out.push(new Paragraph({
          spacing: { before: 80, after: 160 },
          border: { left: { style: BorderStyle.SINGLE, size: 24, color: b.kind === "warn" ? "D97706" : ACCENT, space: 8 } },
          shading: { type: ShadingType.CLEAR, color: "auto", fill: b.kind === "warn" ? "FFFBEB" : "ECFEFF" },
          children: runs(b.text),
        }));
        break;
      case "table": out.push(table(b), new Paragraph({ spacing: { after: 120 }, children: [] })); break;
      case "img": out.push(...image(b)); break;
      case "pagebreak": out.push(new Paragraph({ children: [new PageBreak()] })); break;
      case "toc":
        out.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun("Sommaire")] }));
        for (const h of b.items)
          out.push(new Paragraph({
            spacing: { after: 60 },
            border: { bottom: { style: BorderStyle.DOTTED, size: 4, color: "CBD5E1", space: 2 } },
            children: runs(h),
          }));
        break;
      default: throw new Error("unknown block " + b.t);
    }
  }
  return out;
}

function cover() {
  const band = new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: [CONTENT_W],
    rows: [new TableRow({ children: [new TableCell({
      width: { size: CONTENT_W, type: WidthType.DXA },
      shading: { type: ShadingType.CLEAR, color: "auto", fill: NAVY },
      margins: { top: 900, bottom: 900, left: 500, right: 500 },
      borders: { top: none, bottom: none, left: none, right: none },
      children: [
        new Paragraph({ spacing: { after: 160 }, children: [new TextRun({ text: spec.kind.toUpperCase(), color: "67E8F9", bold: true, size: 20, characterSpacing: 40 })] }),
        new Paragraph({ spacing: { after: 120 }, children: [
          new TextRun({ text: "Phish", bold: true, size: 72, color: "FFFFFF" }),
          new TextRun({ text: "Guard", bold: true, size: 72, color: "22D3EE" }),
          new TextRun({ text: " AI", bold: true, size: 72, color: "FFFFFF" })] }),
        new Paragraph({ spacing: { after: 360 }, children: [new TextRun({ text: spec.subtitle, size: 30, color: "CBD5E1" })] }),
        new Paragraph({ children: [new TextRun({ text: spec.context, size: 21, color: "94A3B8" })] }),
      ],
    })] })],
  });
  const fw = [Math.round(CONTENT_W * 0.42), CONTENT_W - Math.round(CONTENT_W * 0.42)];
  const fields = new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: fw,
    rows: spec.fields.map(([a, v]) => new TableRow({ children: [
      new TableCell({ width: { size: fw[0], type: WidthType.DXA }, borders: { top: none, bottom: none, left: none, right: none },
        children: [new Paragraph({ spacing: { after: 100 }, children: [new TextRun({ text: a, color: "64748B", size: 22 })] })] }),
      new TableCell({ width: { size: fw[1], type: WidthType.DXA }, borders: { top: none, bottom: none, left: none, right: none },
        children: [new Paragraph({ spacing: { after: 100 }, children: [new TextRun({ text: v, bold: true, size: 22 })] })] }),
    ] })),
  });
  return [band, new Paragraph({ spacing: { before: 3600 }, children: [] }), fields,
    new Paragraph({ children: [new PageBreak()] })];
}

const heading = (size, color, before, after) => ({
  run: { font: FONT, size, bold: true, color },
  paragraph: { spacing: { before, after }, keepNext: true, keepLines: true },
});

const doc = new Document({
  creator: "PhishGuard AI",
  title: `PhishGuard AI — ${spec.kind}`,
  styles: {
    default: {
      document: { run: { font: FONT, size: 21, color: "1E293B" }, paragraph: { spacing: { line: 276 } } },
      title: heading(56, NAVY, 0, 200),
      heading1: { ...heading(34, NAVY, 400, 160), paragraph: { spacing: { before: 400, after: 160 }, keepNext: true, keepLines: true,
        border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: ACCENT, space: 4 } } } },
      heading2: heading(27, ACCENT, 280, 100),
      heading3: heading(23, NAVY, 200, 80),
    },
  },
  numbering: { config: [
    { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 540, hanging: 270 } } } }] },
    { reference: "numbers", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 540, hanging: 300 } } } }] },
  ] },
  sections: [{
    properties: { page: { size: { width: PAGE_W, height: 16838 }, margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN } } },
    footers: { default: new Footer({ children: [new Paragraph({ children: [
      new TextRun({ text: `PhishGuard AI — ${spec.kind}`, size: 16, color: "64748B" }),
      new TextRun({ children: [new PositionalTab({ alignment: PositionalTabAlignment.RIGHT,
        relativeTo: PositionalTabRelativeTo.MARGIN, leader: PositionalTabLeader.NONE })], size: 16 }),
      new TextRun({ children: [PageNumber.CURRENT, " / ", PageNumber.TOTAL_PAGES], size: 16, color: "64748B" }),
    ] })] }) },
    children: [...cover(), ...blocks(spec.blocks)],
  }],
});

Packer.toBuffer(doc).then((buf) => fs.writeFileSync(spec.out, buf));
