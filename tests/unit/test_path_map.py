import ntpath

import pytest

from sunpack.core.support.path_keys import absolute_path_key
from sunpack.core.support.path_map import PathMap


@pytest.mark.parametrize("root", ["C:\\", "\\\\server\\share\\"])
def test_path_map_moves_subtrees_in_order_and_releases_their_index(root):
    # Output-level tests never query a drive/UNC root or reuse a pruned subtree.
    # Cover those boundaries and ordered relocation without filesystem IO.
    paths = PathMap()
    branch = ntpath.join(root, "output")
    child = ntpath.join(branch, "deep", "child")
    sibling = ntpath.join(root, "output-other")
    outside = "Z:\\unrelated"
    for path, value in ((child, "child"), (outside, "outside"),
                        (branch, "branch"), (sibling, "sibling"), (root, "root")):
        paths[path] = value
    paths[child.upper()] = "updated"
    assert paths.has_under(root)
    assert [value for _, value in paths.ancestors(child)] == ["root", "branch", "updated"]
    assert paths.pop_under(branch) == [(absolute_path_key(child), "updated"),
                                       (absolute_path_key(branch), "branch")]
    assert not paths.has_under(branch)
    assert paths[sibling] == "sibling"
    assert paths.pop_under(branch) == []
    paths[child] = "reused"
    del paths[child]
    assert not paths.has_under(branch)
    assert paths.pop_under(root) == [(absolute_path_key(sibling), "sibling"),
                                     (absolute_path_key(root), "root")]
    assert list(paths.items()) == [(absolute_path_key(outside), "outside")]
    assert paths.pop_under("Z:\\") == [(absolute_path_key(outside), "outside")]
    assert not paths and not paths.has_under(root)
