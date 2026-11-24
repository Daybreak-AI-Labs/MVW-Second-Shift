import hashlib
import importlib

import pytest

from second_shift_runtime.skills import SkillContext, SkillError
from second_shift_runtime.skills.documents import CreatePresentation, CreateSpreadsheet, CreateWordDocument


def ctx(tmp_path):
    return SkillContext(output_dir=tmp_path / "out")


def check_result(result, tmp_path, extension):
    assert len(result.files) == 1
    info = result.files[0]
    assert info.path.parent == (tmp_path / "out").resolve() and info.name.endswith("." + extension)
    assert info.size == info.path.stat().st_size and info.sha256 == hashlib.sha256(info.path.read_bytes()).hexdigest()
    assert info.name in result.text and str(info.size) in result.text and info.sha256 in result.text
    return info


def test_word_document_can_be_opened_again_with_the_content_asked_for(tmp_path):
    import docx

    args = {"title": "Quarterly Review", "blocks": [
        {"type": "heading", "text": "Summary", "level": 1},
        {"type": "paragraph", "text": "Sales rose."},
        {"type": "bullets", "items": ["one", "two"]},
        {"type": "table", "header": ["Region", "Sales"], "rows": [["North", "10"], ["South", "20"]]},
        {"type": "heading", "text": "Detail", "level": 2},
    ]}
    info = check_result(CreateWordDocument().run(args, ctx(tmp_path)), tmp_path, "docx")
    document = docx.Document(str(info.path))
    texts = [p.text for p in document.paragraphs]
    assert texts[0] == "Quarterly Review" and "Summary" in texts and "Sales rose." in texts and "Detail" in texts
    assert [p.text for p in document.paragraphs if p.style.name == "List Bullet"] == ["one", "two"]
    table = document.tables[0]
    assert [[c.text for c in row.cells] for row in table.rows] == [["Region", "Sales"], ["North", "10"], ["South", "20"]]
    assert [p.text for p in document.paragraphs if p.style.name.startswith("Heading")] == ["Summary", "Detail"]


def test_presentation_can_be_opened_again_with_slides_bullets_and_notes(tmp_path):
    import pptx

    args = {"title": "Launch", "slides": [
        {"title": "Why", "bullets": ["fast", "cheap"], "notes": "say it slowly"},
        {"title": "Next"},
    ]}
    info = check_result(CreatePresentation().run(args, ctx(tmp_path)), tmp_path, "pptx")
    deck = pptx.Presentation(str(info.path))
    slides = list(deck.slides)
    assert len(slides) == 3 and slides[0].shapes.title.text == "Launch"
    assert slides[1].shapes.title.text == "Why"
    assert [p.text for p in slides[1].placeholders[1].text_frame.paragraphs] == ["fast", "cheap"]
    assert slides[1].notes_slide.notes_text_frame.text == "say it slowly"
    assert slides[2].shapes.title.text == "Next" and not slides[2].has_notes_slide


def test_spreadsheet_can_be_opened_again_and_text_is_never_a_formula(tmp_path):
    import openpyxl

    args = {"title": "Budget", "sheets": [
        {"name": "Q1: Plan?", "rows": [["Item", "Cost", "Paid"], ["Rent", 1200.5, True], ["=SUM(B2:B2)", None, "-1+1"]]},
        {"name": "Q1 Plan", "rows": []},
    ]}
    info = check_result(CreateSpreadsheet().run(args, ctx(tmp_path)), tmp_path, "xlsx")
    book = openpyxl.load_workbook(str(info.path))
    assert book.sheetnames == ["Q1 Plan", "Q1 Plan-2"]
    sheet = book["Q1 Plan"]
    assert [[c.value for c in row] for row in sheet.iter_rows()][:2] == [["Item", "Cost", "Paid"], ["Rent", 1200.5, True]]
    assert sheet["A3"].value == "=SUM(B2:B2)" and sheet["A3"].data_type == "s" and sheet["C3"].value == "-1+1"
    assert openpyxl.load_workbook(str(info.path), data_only=False)["Q1 Plan"]["A3"].data_type == "s"


def test_files_stay_inside_the_output_folder_with_safe_generated_names(tmp_path):
    for title in ["../../etc/passwd", "a/b\\c", "C:\\x", "  ", "..", "x" * 200, "\u202eevil"]:
        result = CreateWordDocument().run({"title": title.strip() or "t", "blocks": []}, ctx(tmp_path))
        info = result.files[0]
        assert info.path.parent == (tmp_path / "out").resolve()
        assert "/" not in info.name and "\\" not in info.name and ".." not in info.name and len(info.name) <= 60
    assert not (tmp_path / "etc").exists()
    names = {p.name for p in (tmp_path / "out").iterdir()}
    again = CreateWordDocument().run({"title": "../../etc/passwd", "blocks": []}, ctx(tmp_path)).files[0].name
    assert again not in names  # two files with the same title never overwrite each other


@pytest.mark.parametrize("skill,args,fragment", [
    (CreateWordDocument, {"title": "t", "blocks": [{"type": "paragraph", "text": "x"}] * 201}, "limit is 200"),
    (CreateWordDocument, {"title": "t", "blocks": [{"type": "paragraph", "text": "x" * 5001}]}, "too long"),
    (CreateWordDocument, {"title": "t", "blocks": [{"type": "script"}]}, "must be heading, paragraph, bullets or table"),
    (CreateWordDocument, {"title": "t", "blocks": [{"type": "heading", "text": "x", "level": 9}]}, "level must be 1, 2 or 3"),
    (CreateWordDocument, {"title": "t", "blocks": [{"type": "bullets", "items": ["x"] * 101}]}, "limit is 100"),
    (CreateWordDocument, {"title": "t", "blocks": [{"type": "table", "header": ["a"], "rows": [["1", "2"]]}]}, "has 2 cells but the table has 1"),
    (CreateWordDocument, {"title": "t", "blocks": [{"type": "table", "header": ["a"] * 13, "rows": []}]}, "limit is 12"),
    (CreateWordDocument, {"title": "", "blocks": []}, "must not be empty"),
    (CreateWordDocument, {"title": "t", "blocks": "no"}, "must be a list"),
    (CreateWordDocument, {"title": 5, "blocks": []}, "must be text"),
    (CreatePresentation, {"title": "t", "slides": [{"title": "s"}] * 51}, "limit is 50"),
    (CreatePresentation, {"title": "t", "slides": [{"title": "s", "bullets": ["b"] * 21}]}, "limit is 20"),
    (CreatePresentation, {"title": "t", "slides": ["x"]}, "must be an object"),
    (CreateSpreadsheet, {"title": "t", "sheets": []}, "at least one sheet"),
    (CreateSpreadsheet, {"title": "t", "sheets": [{"name": "s", "rows": [[1]] * 1001}]}, "limit is 1000"),
    (CreateSpreadsheet, {"title": "t", "sheets": [{"name": "s", "rows": [[1] * 51]}]}, "limit is 50"),
    (CreateSpreadsheet, {"title": "t", "sheets": [{"name": "s", "rows": [[{"a": 1}]]}]}, "not text, a number"),
    (CreateSpreadsheet, {"title": "t", "sheets": [{"name": "[]", "rows": []}]}, "no usable characters"),
    (CreateSpreadsheet, {"title": "t", "sheets": [{"name": "s", "rows": []}] * 11}, "limit is 10"),
])
def test_input_sizes_and_shapes_are_bounded(tmp_path, skill, args, fragment):
    with pytest.raises(SkillError, match=fragment):
        skill().run(args, ctx(tmp_path))
    assert not (tmp_path / "out").exists() or list((tmp_path / "out").iterdir()) == []


def test_an_oversized_file_is_removed(tmp_path, monkeypatch):
    from second_shift_runtime.skills import documents

    monkeypatch.setattr(documents, "MAX_FILE_BYTES", 100)
    with pytest.raises(SkillError, match="over the 100 byte limit"):
        CreateWordDocument().run({"title": "t", "blocks": []}, ctx(tmp_path))
    assert list((tmp_path / "out").iterdir()) == []


@pytest.mark.parametrize("skill,args,library,package", [
    (CreateWordDocument, {"title": "t", "blocks": []}, "docx", "python-docx"),
    (CreatePresentation, {"title": "t", "slides": []}, "pptx", "python-pptx"),
    (CreateSpreadsheet, {"title": "t", "sheets": [{"name": "s", "rows": []}]}, "openpyxl", "openpyxl"),
])
def test_a_missing_library_is_reported_clearly(tmp_path, monkeypatch, skill, args, library, package):
    real = importlib.import_module

    def fake(name, *a, **k):
        if name == library:
            raise ImportError("no module")
        return real(name, *a, **k)

    monkeypatch.setattr(importlib, "import_module", fake)
    with pytest.raises(SkillError, match=f"needs the {package} library.*second-shift-runtime\\[office\\]"):
        skill().run(args, ctx(tmp_path))


def test_the_package_imports_without_the_office_libraries():
    import subprocess
    import sys

    code = ("import sys\nfor m in ('docx','pptx','openpyxl'):\n    sys.modules[m] = None\n"
            "import second_shift_runtime.skills.documents, second_shift_runtime.loop\n"
            "from second_shift_runtime.skills import registry\nprint(sorted(registry()))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
    assert "create_word_document" in out


def test_document_skills_are_rated_low_because_they_only_write_into_the_run_folder():
    for skill in (CreateWordDocument, CreatePresentation, CreateSpreadsheet):
        assert skill.default_risk == "low"
