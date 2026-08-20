from wj import render


def test_seven_layers_ordered_top_to_bottom():
    numbers = [n for n, _name, _color, _protos in render.OSI_LAYERS]
    assert numbers == [7, 6, 5, 4, 3, 2, 1]


def test_layer_lookup_tables_cover_every_layer():
    assert render.LAYER_NAME[4] == "Transport"
    assert set(render.LAYER_COLOR) == {1, 2, 3, 4, 5, 6, 7}


def test_layer_tags_renders_one_chip_per_layer():
    tags = render.layer_tags(7, 4)
    assert "L7" in tags and "L4" in tags
    assert tags.count("[/") == 2
