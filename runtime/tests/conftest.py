import pytest

from second_shift_runtime.definition import parse_definition

from fakes import definition_dict


@pytest.fixture
def definition():
    return parse_definition(definition_dict())
