"""Document skills: Word, PowerPoint and Excel files written into the run's own output folder.

The libraries (python-docx, python-pptx, openpyxl) come with the optional ``office`` extra. They are imported
only when a skill runs, so a missing one is reported as a clear tool error, never as a failed import.
"""
from __future__ import annotations

from typing import Any

from . import FileInfo, Skill, SkillContext, SkillError, SkillResult, write_output_file

MAX_FILE_BYTES = 5_000_000
MAX_TEXT = 5_000
MAX_BLOCKS = 200
MAX_LIST_ITEMS = 100
MAX_TABLE_ROWS = 100
MAX_TABLE_COLS = 12
MAX_SLIDES = 50
MAX_BULLETS = 20
MAX_SHEETS = 10
MAX_SHEET_ROWS = 1_000
MAX_SHEET_COLS = 50


def _library(module: str, package: str) -> Any:
    import importlib

    try:
        return importlib.import_module(module)
    except ImportError as exc:
        raise SkillError(f"This skill needs the {package} library, which is not installed. "
                         f"Install it with: pip install 'second-shift-runtime[office]'.") from exc


def _str(value: Any, where: str, *, maximum: int = MAX_TEXT, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SkillError(f"{where} must be text.")
    if not allow_empty and not value.strip():
        raise SkillError(f"{where} must not be empty.")
    if len(value) > maximum:
        raise SkillError(f"{where} is too long ({len(value)} characters; the limit is {maximum}).")
    return value


def _list(value: Any, where: str, maximum: int) -> list[Any]:
    if not isinstance(value, list):
        raise SkillError(f"{where} must be a list.")
    if len(value) > maximum:
        raise SkillError(f"{where} has {len(value)} items; the limit is {maximum}.")
    return value


def _result(info: FileInfo, what: str) -> SkillResult:
    return SkillResult(f"Created {what}: {info.name} ({info.size} bytes, sha256 {info.sha256}).", [info])


def _xml_safe(text: str) -> str:
    """Control characters are not allowed in Office XML; drop them (tab and new lines stay)."""
    return "".join(ch for ch in text if ch in "\t\n\r" or ord(ch) >= 32)


class CreateWordDocument(Skill):
    name = "create_word_document"
    description = ("Create a Word (.docx) document from structured content: a title and a list of blocks. "
                   "Each block is a heading, a paragraph, a bullet list or a table.")
    input_schema = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "blocks": {"type": "array", "maxItems": MAX_BLOCKS, "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["heading", "paragraph", "bullets", "table"]},
                    "text": {"type": "string", "description": "For heading and paragraph."},
                    "level": {"type": "integer", "minimum": 1, "maximum": 3, "description": "For heading."},
                    "items": {"type": "array", "items": {"type": "string"}, "description": "For bullets."},
                    "header": {"type": "array", "items": {"type": "string"}, "description": "For table: column names."},
                    "rows": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}, "description": "For table."},
                },
                "required": ["type"],
            }},
        },
        "required": ["title", "blocks"],
        "additionalProperties": False,
    }
    default_risk = "low"  # it only writes into the run's own folder

    def describe(self, args: dict[str, Any]) -> str:
        blocks = args.get("blocks")
        count = len(blocks) if isinstance(blocks, list) else 0
        return f"Create a Word document titled {str(args.get('title', ''))[:100]!r} with {count} blocks in the run's output folder."

    def run(self, args: dict[str, Any], context: SkillContext) -> SkillResult:
        title = _str(args.get("title"), "title", maximum=200)
        blocks = _list(args.get("blocks"), "blocks", MAX_BLOCKS)
        checked = [self._check(b, i) for i, b in enumerate(blocks)]
        docx = _library("docx", "python-docx")

        def write(path: Any) -> None:
            doc = docx.Document()
            doc.add_heading(_xml_safe(title), level=0)
            for kind, data in checked:
                if kind == "heading":
                    doc.add_heading(_xml_safe(data["text"]), level=data["level"])
                elif kind == "paragraph":
                    doc.add_paragraph(_xml_safe(data["text"]))
                elif kind == "bullets":
                    for item in data["items"]:
                        doc.add_paragraph(_xml_safe(item), style="List Bullet")
                else:
                    table = doc.add_table(rows=0, cols=len(data["header"]))
                    table.style = "Table Grid"
                    for row in [data["header"], *data["rows"]]:
                        cells = table.add_row().cells
                        for cell, value in zip(cells, row, strict=True):
                            cell.text = _xml_safe(value)
            doc.save(str(path))

        return _result(write_output_file(context.output_dir, title, "docx", write, MAX_FILE_BYTES), "the Word document")

    @staticmethod
    def _check(block: Any, index: int) -> tuple[str, dict[str, Any]]:
        where = f"blocks[{index}]"
        if not isinstance(block, dict):
            raise SkillError(f"{where} must be an object.")
        kind = block.get("type")
        if kind == "heading":
            level = block.get("level", 1)
            if isinstance(level, bool) or not isinstance(level, int) or not 1 <= level <= 3:
                raise SkillError(f"{where}.level must be 1, 2 or 3.")
            return kind, {"text": _str(block.get("text"), f"{where}.text", maximum=300), "level": level}
        if kind == "paragraph":
            return kind, {"text": _str(block.get("text"), f"{where}.text")}
        if kind == "bullets":
            items = _list(block.get("items"), f"{where}.items", MAX_LIST_ITEMS)
            return kind, {"items": [_str(x, f"{where}.items[{j}]", maximum=1000) for j, x in enumerate(items)]}
        if kind == "table":
            header = _list(block.get("header"), f"{where}.header", MAX_TABLE_COLS)
            if not header:
                raise SkillError(f"{where}.header must name at least one column.")
            rows = _list(block.get("rows"), f"{where}.rows", MAX_TABLE_ROWS)
            clean_rows = []
            for r, row in enumerate(rows):
                row = _list(row, f"{where}.rows[{r}]", MAX_TABLE_COLS)
                if len(row) != len(header):
                    raise SkillError(f"{where}.rows[{r}] has {len(row)} cells but the table has {len(header)} columns.")
                clean_rows.append([_str(c, f"{where}.rows[{r}] cell", maximum=500, allow_empty=True) for c in row])
            return kind, {"header": [_str(h, f"{where}.header", maximum=200, allow_empty=True) for h in header], "rows": clean_rows}
        raise SkillError(f"{where}.type must be heading, paragraph, bullets or table.")


class CreatePresentation(Skill):
    name = "create_presentation"
    description = "Create a PowerPoint (.pptx) presentation: a title and slides, each with a title, bullet points and optional speaker notes."
    input_schema = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "slides": {"type": "array", "maxItems": MAX_SLIDES, "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "bullets": {"type": "array", "items": {"type": "string"}, "maxItems": MAX_BULLETS},
                    "notes": {"type": "string"},
                },
                "required": ["title"],
            }},
        },
        "required": ["title", "slides"],
        "additionalProperties": False,
    }
    default_risk = "low"

    def describe(self, args: dict[str, Any]) -> str:
        slides = args.get("slides")
        count = len(slides) if isinstance(slides, list) else 0
        return f"Create a presentation titled {str(args.get('title', ''))[:100]!r} with {count} slides in the run's output folder."

    def run(self, args: dict[str, Any], context: SkillContext) -> SkillResult:
        title = _str(args.get("title"), "title", maximum=200)
        slides = []
        for i, slide in enumerate(_list(args.get("slides"), "slides", MAX_SLIDES)):
            where = f"slides[{i}]"
            if not isinstance(slide, dict):
                raise SkillError(f"{where} must be an object.")
            bullets = _list(slide.get("bullets", []), f"{where}.bullets", MAX_BULLETS)
            slides.append({
                "title": _str(slide.get("title"), f"{where}.title", maximum=300),
                "bullets": [_str(b, f"{where}.bullets[{j}]", maximum=1000) for j, b in enumerate(bullets)],
                "notes": _str(slide.get("notes", ""), f"{where}.notes", allow_empty=True),
            })
        pptx = _library("pptx", "python-pptx")

        def write(path: Any) -> None:
            deck = pptx.Presentation()
            cover = deck.slides.add_slide(deck.slide_layouts[0])
            cover.shapes.title.text = _xml_safe(title)
            for item in slides:
                slide = deck.slides.add_slide(deck.slide_layouts[1])
                slide.shapes.title.text = _xml_safe(item["title"])
                frame = slide.placeholders[1].text_frame
                for n, bullet in enumerate(item["bullets"]):
                    paragraph = frame.paragraphs[0] if n == 0 else frame.add_paragraph()
                    paragraph.text = _xml_safe(bullet)
                if item["notes"]:
                    slide.notes_slide.notes_text_frame.text = _xml_safe(item["notes"])
            deck.save(str(path))

        return _result(write_output_file(context.output_dir, title, "pptx", write, MAX_FILE_BYTES), "the presentation")


class CreateSpreadsheet(Skill):
    name = "create_spreadsheet"
    description = "Create an Excel (.xlsx) spreadsheet from sheets of rows. Cells hold text, numbers, true/false or nothing. Text is never treated as a formula."
    input_schema = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "sheets": {"type": "array", "maxItems": MAX_SHEETS, "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "rows": {"type": "array", "maxItems": MAX_SHEET_ROWS, "items": {
                        "type": "array", "maxItems": MAX_SHEET_COLS,
                        "items": {"type": ["string", "number", "boolean", "null"]}}},
                },
                "required": ["name", "rows"],
            }},
        },
        "required": ["title", "sheets"],
        "additionalProperties": False,
    }
    default_risk = "low"

    def describe(self, args: dict[str, Any]) -> str:
        sheets = args.get("sheets")
        count = len(sheets) if isinstance(sheets, list) else 0
        return f"Create a spreadsheet titled {str(args.get('title', ''))[:100]!r} with {count} sheets in the run's output folder."

    def run(self, args: dict[str, Any], context: SkillContext) -> SkillResult:
        title = _str(args.get("title"), "title", maximum=200)
        sheets = []
        for i, sheet in enumerate(_list(args.get("sheets"), "sheets", MAX_SHEETS)):
            where = f"sheets[{i}]"
            if not isinstance(sheet, dict):
                raise SkillError(f"{where} must be an object.")
            name = "".join(ch for ch in _str(sheet.get("name"), f"{where}.name", maximum=100) if ch not in "[]:*?/\\")[:31].strip("'")
            if not name:
                raise SkillError(f"{where}.name has no usable characters.")
            rows = []
            for r, row in enumerate(_list(sheet.get("rows"), f"{where}.rows", MAX_SHEET_ROWS)):
                row = _list(row, f"{where}.rows[{r}]", MAX_SHEET_COLS)
                for cell in row:
                    if cell is not None and not isinstance(cell, (str, int, float, bool)):
                        raise SkillError(f"{where}.rows[{r}] holds a value that is not text, a number, true/false or empty.")
                    if isinstance(cell, str) and len(cell) > 2000:
                        raise SkillError(f"{where}.rows[{r}] holds text longer than 2000 characters.")
                rows.append(row)
            sheets.append((name, rows))
        if not sheets:
            raise SkillError("sheets must hold at least one sheet.")
        openpyxl = _library("openpyxl", "openpyxl")

        def write(path: Any) -> None:
            book = openpyxl.Workbook()
            book.remove(book.active)
            used: set[str] = set()
            for name, rows in sheets:
                unique, n = name, 1
                while unique.lower() in used:
                    n += 1
                    unique = f"{name[:28]}-{n}"
                used.add(unique.lower())
                sheet = book.create_sheet(unique)
                for r, row in enumerate(rows, 1):
                    for c, value in enumerate(row, 1):
                        cell = sheet.cell(row=r, column=c)
                        if isinstance(value, str):
                            cell.value = _xml_safe(value)
                            cell.data_type = "s"  # text, even when it starts with "=": never a formula
                        else:
                            cell.value = value
            book.save(str(path))

        return _result(write_output_file(context.output_dir, title, "xlsx", write, MAX_FILE_BYTES), "the spreadsheet")
