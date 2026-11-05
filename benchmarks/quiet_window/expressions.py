"""Bounded, monotone symbolic policies for OFFLINE closed-loop discovery.

Only interval is observable. Grammar construction proves nonnegativity and
monotonicity; no trace labels or completion truth can enter the expression.
"""
from __future__ import annotations

import ast
import itertools
import math
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from sunpack_native import fast_hash128


UNARY = ("log", "sqrt", "sat", "power")
BOUNDS = {"A": (0.001, 100.0), "P": (0.001, 100.0), "r": (0.0, 1.0), "p": (0.25, 1.5)}


def tree_tuple(value):
    return value if isinstance(value, str) else tuple(tree_tuple(item) for item in value)


def operators(tree):
    if isinstance(tree, str):
        return []
    return [tree[0], *(op for child in tree[1:] for op in operators(child))]


def render_tree(tree, x, parameters):
    if tree == "x":
        return x
    op, *children = tree
    terms = [render_tree(child, x, parameters) for child in children]
    a = terms[0]
    if op == "log":
        return f"math.log1p({a})"
    if op == "sqrt":
        return f"math.sqrt({a})"
    if op == "sat":
        return f"({a} / (1.0 + {a}))"
    if op == "power":
        return f"({a} ** {parameters['p']!r})"
    if op == "add":
        r = parameters["r"]
        return f"({r!r} * {a} + {1.0-r!r} * {terms[1]})"
    if op == "mul":
        return f"({a} * {terms[1]})"
    raise ValueError(f"unknown expression operator: {op}")


def rounded(value):
    return float(f"{value:.3g}")


@dataclass(frozen=True)
class Expression:
    tree: object
    parameters: tuple[tuple[str, float], ...] = ()

    @classmethod
    def make(cls, tree, **parameters):
        tree = tree_tuple(tree)
        if tree in ("baseline", "zero"):
            return cls(tree)
        ops = operators(tree)
        used = {"A", "P"} | ({"r"} if "add" in ops else set()) | ({"p"} if "power" in ops else set())
        values = {name: rounded(parameters.get(name, {"A": 1., "P": 1. if tree == "x" else 2., "r": .5, "p": .5}[name])) for name in used}
        if tree == "x":
            values = {"A": rounded(values["A"] / values["P"])}
        for name, value in values.items():
            low, high = BOUNDS[name]
            if not math.isfinite(value) or not low <= value <= high:
                raise ValueError(f"constant outside registered bounds: {name}={value}")
        return cls(tree, tuple(sorted(values.items())))

    @classmethod
    def from_record(cls, record):
        expression = cls.make(record["tree"], **record["parameters"])
        if expression.tree not in ("baseline", "zero", "x") and expression.tree not in grammar():
            raise ValueError("expression outside the registered grammar")
        return expression

    @property
    def source(self):
        if self.tree == "baseline":
            return "(interval + 0.75 * math.log1p(interval / 2.0))"
        if self.tree == "zero":
            return "0.0"
        parameters = dict(self.parameters)
        x = "interval" if self.tree == "x" else f"(interval / {parameters['P']!r})"
        return f"({parameters['A']!r} * {render_tree(self.tree, x, parameters)})"

    @property
    def identity(self):
        return fast_hash128(self.source.encode("utf-8"))

    @property
    def complexity(self):
        # Saturation expands to two primitive operations; weighted addition
        # expands to three. All constants have at most three significant digits.
        return sum({"sat": 2, "add": 3}.get(op, 1) for op in operators(self.tree)) + len(self.parameters)

    def record(self):
        return {"id": self.identity, "tree": self.tree, "parameters": dict(self.parameters),
                "expression": self.source, "complexity": self.complexity}

    def function(self):
        namespace = {"math": math}
        exec(compile(f"def mapping(interval):\n    return {self.source}\n", "<quiet-expression>", "exec"), namespace)
        return namespace["mapping"]

    def export_policy(self, source: Path, destination: Path):
        text = source.read_text(encoding="utf-8")
        module = ast.parse(text)
        policy = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == "AdaptiveQuietPolicy")
        target = next(node for node in policy.body if isinstance(node, ast.FunctionDef) and node.name == "target_seconds")
        lines = text.splitlines(keepends=True)
        lines[target.lineno - 1:target.end_lineno] = [
            "    def target_seconds(self, interval: float) -> float:\n",
            f"        return {self.source}\n",
        ]
        destination.write_text("".join(lines), encoding="utf-8")


@lru_cache(maxsize=4)
def grammar(max_operations=3):
    """Canonical commutative trees, at most one mix and one free exponent."""
    levels = {0: ["x"]}
    for count in range(1, max_operations + 1):
        found = set()
        for op, child in itertools.product(UNARY, levels[count - 1]):
            found.add((op, child))
        for left_count in range(count - 1):
            right_count = count - 1 - left_count
            for left, right in itertools.product(levels[left_count], levels[right_count]):
                if repr(left) > repr(right):
                    continue
                found.add(("mul", left, right))
                if left != right:
                    found.add(("add", left, right))
        levels[count] = sorted((tree for tree in found if operators(tree).count("add") <= 1
                                and operators(tree).count("power") <= 1), key=repr)
    return tuple(tree for count in levels for tree in levels[count])


def radical_inverse(index, base):
    result, weight = 0.0, 1.0 / base
    while index:
        index, digit = divmod(index, base)
        result += digit * weight
        weight /= base
    return result


def initial_candidates(count):
    trees = grammar()
    # Round-robin root operators and complexity gives every operator a chance;
    # representation search is bounded sampling, not a global optimality claim.
    groups = {}
    for tree in trees:
        key = (len(operators(tree)), tree if isinstance(tree, str) else tree[0])
        groups.setdefault(key, []).append(tree)
    ordered = []
    for depth in range(max(map(len, groups.values()))):
        ordered.extend(group[depth] for group in groups.values() if depth < len(group))
    candidates = [Expression.make("baseline"), Expression.make("zero"),
                  Expression.make(("log", "x"), A=2.75, P=2)]
    seen = {item.identity for item in candidates}
    # Reserve enough constants per structure to avoid a single unlucky scale
    # eliminating it before local black-box refinement.
    selected = ordered[:max(1, (count - 3) // 3)]
    index = 0
    while len(candidates) < count:
        tree = selected[index % len(selected)]
        cycle = index // len(selected)
        index += 1
        parameters = {"P": (2.0, .05, .25)[cycle % 3], "r": .5, "p": .5}
        if cycle < 3:
            unit = Expression.make(tree, A=1, **parameters).function()
            reference = .02 if cycle < 2 else .1
            parameters["A"] = min(100., max(.001, 1.375 * reference / unit(reference)))
        else:
            parameters.update(A=10 ** (-3 + 5 * radical_inverse(index, 2)),
                              P=10 ** (-3 + 5 * radical_inverse(index, 3)),
                              r=radical_inverse(index, 5), p=.25 + 1.25 * radical_inverse(index, 7))
        try:
            candidate = Expression.make(tree, **parameters)
        except ValueError:
            continue
        if candidate.identity not in seen:
            seen.add(candidate.identity)
            candidates.append(candidate)
    # Same-form parameter-search control, independently refined by the same
    # black-box neighbour generator used for all other expressions.
    current_tree = ("add", "x", ("log", "x"))
    for P, r in itertools.product((.05, .25, 2., 16.), (.1, .5, .9)):
        unit = Expression.make(current_tree, A=1, P=P, r=r).function()
        candidate = Expression.make(current_tree, A=min(100., 1.375 * .02 / unit(.02)), P=P, r=r)
        if candidate.identity not in seen:
            seen.add(candidate.identity)
            candidates.append(candidate)
    return candidates


def neighbours(expression, round_index=0):
    if expression.tree in ("baseline", "zero"):
        return []
    values = dict(expression.parameters)
    candidates = []
    for name, value in values.items():
        if name in ("A", "P"):
            alternatives = (value * factor for factor in ((.5, .8, 1.25, 2.) if round_index == 0 else (.8, .95, 1.05, 1.25)))
        else:
            step = .2 if round_index == 0 else .05
            alternatives = (value - step, value + step)
        for alternative in alternatives:
            low, high = BOUNDS[name]
            candidates.append(Expression.make(expression.tree, **{**values, name: min(high, max(low, alternative))}))
    if "P" in values:
        # Coordinate moves alone cannot traverse narrow viable A/P valleys.
        # Joint scale moves preserve the near-zero response of linear/log/sat
        # policies while exploring different compression of long intervals.
        for factor, gain in itertools.product((.25, .5, 2.), (1., 1.1)):
            changes = {**values, "A": values["A"] * factor * gain, "P": values["P"] * factor}
            if all(BOUNDS[name][0] <= value <= BOUNDS[name][1] for name, value in changes.items()):
                candidates.append(Expression.make(expression.tree, **changes))
    return candidates
